use anyhow::{bail, Result};
use std::path::Path;

use super::protocol::{Protocol, SecretsKind, CHAP_SECRETS, IPSEC_SECRETS};
use crate::fsx;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub login: String,
    pub password: String,
}

/// Разобранная строка `chap-secrets`. Комментарии и нераспознанные строки
/// сохраняются дословно, чтобы перезапись файла не теряла чужие записи.
#[derive(Debug, Clone)]
enum ChapLine {
    Entry {
        login: String,
        service: String,
        password: String,
        addresses: String,
    },
    Verbatim(String),
}

#[derive(Debug, Clone, Default)]
pub struct ChapSecrets {
    lines: Vec<ChapLine>,
}

fn quote(value: &str) -> String {
    if value.is_empty() || value.contains(char::is_whitespace) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed[1..trimmed.len() - 1].replace("\\\"", "\"")
    } else {
        trimmed.to_string()
    }
}

/// Разбивает строку на поля с учётом кавычек — пароль может содержать пробелы.
fn split_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut started = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started || !current.is_empty() {
                    fields.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started || !current.is_empty() {
        fields.push(current);
    }
    fields
}

impl ChapSecrets {
    pub fn load(path: &Path) -> Result<Self> {
        let Some(text) = fsx::read_opt(path)? else {
            return Ok(Self::default());
        };
        let mut lines = Vec::new();
        for raw in text.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                lines.push(ChapLine::Verbatim(raw.to_string()));
                continue;
            }
            let fields = split_fields(raw);
            if fields.len() < 3 {
                lines.push(ChapLine::Verbatim(raw.to_string()));
                continue;
            }
            lines.push(ChapLine::Entry {
                login: fields[0].clone(),
                service: fields[1].clone(),
                password: fields[2].clone(),
                addresses: fields.get(3).cloned().unwrap_or_else(|| "*".into()),
            });
        }
        Ok(Self { lines })
    }

    pub fn render(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            match line {
                ChapLine::Verbatim(raw) => text.push_str(raw),
                ChapLine::Entry { login, service, password, addresses } => {
                    text.push_str(&format!(
                        "{} {} {} {}",
                        quote(login),
                        quote(service),
                        quote(password),
                        addresses
                    ));
                }
            }
            text.push('\n');
        }
        text
    }

    /// Записи только указанной службы: PPTP, L2TP и SSTP делят один файл,
    /// и без фильтра по колонке службы менеджер показывал бы чужих клиентов.
    pub fn clients(&self, service: &str) -> Vec<Client> {
        self.lines
            .iter()
            .filter_map(|line| match line {
                ChapLine::Entry { login, service: owner, password, .. } if owner == service => {
                    Some(Client { login: unquote(login), password: unquote(password) })
                }
                _ => None,
            })
            .collect()
    }


    pub fn upsert(&mut self, service: &str, login: &str, password: &str) {
        for line in self.lines.iter_mut() {
            if let ChapLine::Entry { login: existing, service: owner, password: secret, .. } = line {
                if owner == service && unquote(existing) == login {
                    *secret = password.to_string();
                    return;
                }
            }
        }
        self.lines.push(ChapLine::Entry {
            login: login.to_string(),
            service: service.to_string(),
            password: password.to_string(),
            addresses: "*".into(),
        });
    }

    pub fn remove(&mut self, service: &str, login: &str) -> bool {
        let before = self.lines.len();
        self.lines.retain(|line| match line {
            ChapLine::Entry { login: existing, service: owner, .. } => {
                !(owner == service && unquote(existing) == login)
            }
            _ => true,
        });
        self.lines.len() != before
    }
}

/// Содержимое `/etc/ipsec.secrets`, разложенное по смыслу записей.
#[derive(Debug, Clone, Default)]
pub struct IpsecSecrets {
    pub rsa_key: Option<String>,
    pub psk: Option<String>,
    pub eap: Vec<Client>,
}

impl IpsecSecrets {
    pub fn load(path: &Path) -> Result<Self> {
        let Some(text) = fsx::read_opt(path)? else {
            return Ok(Self::default());
        };
        let mut parsed = Self::default();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((left, right)) = line.split_once(':') else { continue };
            let left = left.trim();
            let right = right.trim();

            if let Some(rest) = right.strip_prefix("RSA") {
                parsed.rsa_key = Some(unquote(rest));
            } else if let Some(rest) = right.strip_prefix("PSK") {
                if left.split_whitespace().all(|token| token == "%any") {
                    parsed.psk = Some(unquote(rest));
                }
            } else if let Some(rest) = right.strip_prefix("EAP") {
                if !left.is_empty() && !left.contains(char::is_whitespace) {
                    parsed.eap.push(Client {
                        login: unquote(left),
                        password: unquote(rest),
                    });
                }
            }
        }
        Ok(parsed)
    }

    pub fn render(&self) -> String {
        let mut text = String::new();
        if let Some(key) = &self.rsa_key {
            text.push_str(&format!(": RSA \"{key}\"\n"));
        }
        if let Some(psk) = &self.psk {
            text.push_str(&format!("%any %any : PSK \"{psk}\"\n"));
        }
        for client in &self.eap {
            text.push_str(&format!("{} : EAP \"{}\"\n", client.login, client.password));
        }
        text
    }

    pub fn upsert_eap(&mut self, login: &str, password: &str) {
        if let Some(existing) = self.eap.iter_mut().find(|client| client.login == login) {
            existing.password = password.to_string();
        } else {
            self.eap.push(Client {
                login: login.to_string(),
                password: password.to_string(),
            });
        }
    }

    pub fn remove_eap(&mut self, login: &str) -> bool {
        let before = self.eap.len();
        self.eap.retain(|client| client.login != login);
        self.eap.len() != before
    }
}

/// Единый доступ к учётным записям поверх двух разных форматов хранения.
pub struct Store;

impl Store {
    pub fn list(protocol: Protocol) -> Result<Vec<Client>> {
        match protocol.secrets_kind() {
            Some(SecretsKind::Chap { service }) => {
                Ok(ChapSecrets::load(Path::new(CHAP_SECRETS))?.clients(service))
            }
            Some(SecretsKind::Eap) => Ok(IpsecSecrets::load(Path::new(IPSEC_SECRETS))?.eap),
            None => Ok(Vec::new()),
        }
    }

    pub fn exists(protocol: Protocol, login: &str) -> Result<bool> {
        Ok(Self::list(protocol)?
            .iter()
            .any(|client| client.login == login))
    }

    pub fn upsert(protocol: Protocol, login: &str, password: &str) -> Result<()> {
        match protocol.secrets_kind() {
            Some(SecretsKind::Chap { service }) => {
                let path = Path::new(CHAP_SECRETS);
                let mut secrets = ChapSecrets::load(path)?;
                secrets.upsert(service, login, password);
                fsx::write_atomic(path, &secrets.render(), 0o600)
            }
            Some(SecretsKind::Eap) => {
                let path = Path::new(IPSEC_SECRETS);
                let mut secrets = IpsecSecrets::load(path)?;
                secrets.upsert_eap(login, password);
                fsx::write_atomic(path, &secrets.render(), 0o600)
            }
            None => bail!("{} не поддерживает управление клиентами", protocol.display()),
        }
    }

    pub fn remove(protocol: Protocol, login: &str) -> Result<()> {
        let removed = match protocol.secrets_kind() {
            Some(SecretsKind::Chap { service }) => {
                let path = Path::new(CHAP_SECRETS);
                let mut secrets = ChapSecrets::load(path)?;
                let removed = secrets.remove(service, login);
                if removed {
                    fsx::write_atomic(path, &secrets.render(), 0o600)?;
                }
                removed
            }
            Some(SecretsKind::Eap) => {
                let path = Path::new(IPSEC_SECRETS);
                let mut secrets = IpsecSecrets::load(path)?;
                let removed = secrets.remove_eap(login);
                if removed {
                    fsx::write_atomic(path, &secrets.render(), 0o600)?;
                }
                removed
            }
            None => bail!("{} не поддерживает управление клиентами", protocol.display()),
        };
        if !removed {
            bail!("клиент \"{login}\" не найден");
        }
        Ok(())
    }
}

pub fn validate_login(login: &str) -> Result<()> {
    if login.len() < 3 || login.len() > 32 {
        bail!("логин должен содержать от 3 до 32 символов");
    }
    if !login
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        bail!("допустимы только латинские буквы, цифры, дефис и подчёркивание");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "# Secrets for authentication using CHAP\n",
        "# client\tserver\tsecret\n",
        "vpnuser pptpd Ab12Cd34 *\n",
        "admin pptpd Zz99Yy88 *\n",
        "\"l2tpuser\" * Qw34Er56 *\n",
        "\"sstpuser\" sstp \"Mn78Bv90\" *\n",
    );

    fn sample() -> ChapSecrets {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chap-secrets");
        std::fs::write(&path, SAMPLE).unwrap();
        ChapSecrets::load(&path).unwrap()
    }

    #[test]
    fn clients_are_scoped_to_their_service() {
        let secrets = sample();
        let pptp: Vec<String> = secrets.clients("pptpd").into_iter().map(|c| c.login).collect();
        assert_eq!(pptp, vec!["vpnuser", "admin"]);
        assert_eq!(secrets.clients("sstp").len(), 1);
        assert_eq!(secrets.clients("*")[0].login, "l2tpuser");
    }

    #[test]
    fn removal_keeps_comments_and_other_services() {
        let mut secrets = sample();
        assert!(secrets.remove("pptpd", "admin"));
        let rendered = secrets.render();
        assert!(rendered.contains("# Secrets for authentication"));
        assert!(rendered.contains("l2tpuser"));
        assert!(rendered.contains("sstpuser"));
        assert!(!rendered.contains("admin"));
    }

    #[test]
    fn removal_does_not_touch_same_login_of_another_service() {
        let mut secrets = sample();
        secrets.upsert("sstp", "admin", "Secret01");
        assert!(secrets.remove("pptpd", "admin"));
        assert_eq!(secrets.clients("sstp").len(), 2);
    }

    #[test]
    fn upsert_replaces_password_in_place() {
        let mut secrets = sample();
        secrets.upsert("pptpd", "vpnuser", "NewPass1");
        let clients = secrets.clients("pptpd");
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].password, "NewPass1");
    }

    #[test]
    fn quoted_password_with_spaces_survives_round_trip() {
        let mut secrets = ChapSecrets::default();
        secrets.upsert("sstp", "user", "pass with space");
        let rendered = secrets.render();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chap-secrets");
        std::fs::write(&path, rendered).unwrap();
        let reloaded = ChapSecrets::load(&path).unwrap();
        assert_eq!(reloaded.clients("sstp")[0].password, "pass with space");
    }

    #[test]
    fn ipsec_secrets_keep_psk_and_rsa_when_users_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipsec.secrets");
        std::fs::write(
            &path,
            ": RSA \"server-key.pem\"\n%any  %any  : PSK \"SharedKey1\"\nikeuser : EAP \"Ik45Ev67\"\nike2 : EAP \"Pp11Qq22\"\n",
        )
        .unwrap();

        let mut secrets = IpsecSecrets::load(&path).unwrap();
        assert_eq!(secrets.psk.as_deref(), Some("SharedKey1"));
        assert_eq!(secrets.eap.len(), 2);

        secrets.remove_eap("ikeuser");
        secrets.upsert_eap("ike2", "Rotated1");
        let rendered = secrets.render();
        assert!(rendered.contains("PSK \"SharedKey1\""));
        assert!(rendered.contains("RSA \"server-key.pem\""));
        assert!(rendered.contains("ike2 : EAP \"Rotated1\""));
        assert!(!rendered.contains("ikeuser"));
    }

    #[test]
    fn prefix_logins_are_not_confused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ipsec.secrets");
        std::fs::write(&path, "vpn : EAP \"First111\"\nvpn2 : EAP \"Second22\"\n").unwrap();
        let mut secrets = IpsecSecrets::load(&path).unwrap();
        secrets.remove_eap("vpn");
        assert_eq!(secrets.eap.len(), 1);
        assert_eq!(secrets.eap[0].login, "vpn2");
        assert_eq!(secrets.eap[0].password, "Second22");
    }

    #[test]
    fn login_validation() {
        assert!(validate_login("ok-user_1").is_ok());
        assert!(validate_login("ab").is_err());
        assert!(validate_login("пользователь").is_err());
        assert!(validate_login("user name").is_err());
    }
}
