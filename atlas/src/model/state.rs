use anyhow::{Context, Result};
use rand::Rng;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use super::protocol::{Protocol, STATE_DIR};
use crate::fsx;

const PASSWORD_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PASSWORD_LEN: usize = 16;
const PSK_LEN: usize = 24;

/// 16 символов из 56-символьного алфавита — около 93 бит, что снимает
/// осмысленность онлайн-перебора MS-CHAPv2 без rate-limit.
pub fn random_secret(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| PASSWORD_ALPHABET[rng.gen_range(0..PASSWORD_ALPHABET.len())] as char)
        .collect()
}

pub fn random_password() -> String {
    random_secret(PASSWORD_LEN)
}

pub fn random_psk() -> String {
    random_secret(PSK_LEN)
}

fn parse_keyvalue(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn render_keyvalue(entries: &BTreeMap<String, String>) -> String {
    entries
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect()
}

/// Сетевые параметры, зафиксированные при первой установке.
#[derive(Debug, Clone)]
pub struct Network {
    pub wan_interface: String,
    pub public_ip: Option<Ipv4Addr>,
}

impl Network {
    fn path() -> PathBuf {
        Path::new(STATE_DIR).join("network.conf")
    }

    pub fn load() -> Result<Option<Self>> {
        let Some(text) = fsx::read_opt(&Self::path())? else {
            return Ok(None);
        };
        let entries = parse_keyvalue(&text);
        let Some(wan_interface) = entries.get("WAN_IFACE").cloned() else {
            return Ok(None);
        };
        Ok(Some(Self {
            wan_interface,
            public_ip: entries.get("PUBLIC_IP").and_then(|value| value.parse().ok()),
        }))
    }

    pub fn save(&self) -> Result<()> {
        let mut entries = BTreeMap::new();
        entries.insert("WAN_IFACE".into(), self.wan_interface.clone());
        if let Some(ip) = self.public_ip {
            entries.insert("PUBLIC_IP".into(), ip.to_string());
        }
        fsx::write_atomic(&Self::path(), &render_keyvalue(&entries), 0o644)
    }
}

/// Маркер установленного протокола. Существование файла — единственный признак,
/// по которому меню считает протокол установленным, поэтому он снимается
/// при замене и удалении.
#[derive(Debug, Clone, Serialize)]
pub struct Marker {
    pub protocol: Protocol,
    pub user: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    pub installed: String,
}

impl Marker {
    pub fn load(protocol: Protocol) -> Result<Option<Self>> {
        let Some(text) = fsx::read_opt(&protocol.marker())? else {
            return Ok(None);
        };
        let entries = parse_keyvalue(&text);
        Ok(Some(Self {
            protocol,
            user: entries.get("VPN_USER").cloned().unwrap_or_default(),
            password: entries.get("VPN_PASS").cloned().unwrap_or_default(),
            psk: entries
                .get("VPN_PSK")
                .filter(|value| !value.is_empty())
                .cloned(),
            installed: entries.get("INSTALLED").cloned().unwrap_or_default(),
        }))
    }

    pub fn save(&self) -> Result<()> {
        let mut entries = BTreeMap::new();
        entries.insert("PROTOCOL".into(), self.protocol.id().to_string());
        entries.insert("VPN_USER".into(), self.user.clone());
        entries.insert("VPN_PASS".into(), self.password.clone());
        if let Some(psk) = &self.psk {
            entries.insert("VPN_PSK".into(), psk.clone());
        }
        entries.insert("INSTALLED".into(), self.installed.clone());
        fsx::write_atomic(&self.protocol.marker(), &render_keyvalue(&entries), 0o600)
    }

    pub fn remove(protocol: Protocol) -> Result<()> {
        fsx::remove_if_exists(&protocol.marker())
    }
}

/// Реестр пакетов, фактически взятых из архивов прошлых выпусков. Ведётся
/// отдельно от списка пакетов протокола, потому что apt подменяет ещё и
/// транзитивные зависимости вроде bcrelay.
#[derive(Debug, Clone, Default)]
pub struct LegacyRecord {
    pub entries: BTreeMap<String, String>,
}

impl LegacyRecord {
    fn path() -> PathBuf {
        Path::new(STATE_DIR).join("legacy.conf")
    }

    pub fn load() -> Result<Self> {
        let Some(text) = fsx::read_opt(&Self::path())? else {
            return Ok(Self::default());
        };
        Ok(Self { entries: parse_keyvalue(&text) })
    }

    pub fn record(packages: &[(String, String)]) -> Result<()> {
        let mut record = Self::load()?;
        for (package, suite) in packages {
            record.entries.insert(package.clone(), suite.clone());
        }
        fsx::write_atomic(&Self::path(), &render_keyvalue(&record.entries), 0o644)
    }



    pub fn clear() -> Result<()> {
        fsx::remove_if_exists(&Self::path())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn installed_protocols() -> Vec<Protocol> {
    Protocol::ALL
        .into_iter()
        .filter(|protocol| protocol.is_installed())
        .collect()
}

pub fn today() -> String {
    crate::sys::cmd::Cmd::new("date")
        .arg("+%Y-%m-%d")
        .stdout()
        .unwrap_or_else(|_| "неизвестно".into())
}

pub fn ensure_state_dir() -> Result<()> {
    std::fs::create_dir_all(STATE_DIR)
        .with_context(|| format!("создание {STATE_DIR}"))?;
    fsx::set_mode(Path::new(STATE_DIR), 0o700)
}

/// Путь к CA-сертификату для клиентов IKEv2.
pub fn ca_certificate() -> Option<PathBuf> {
    [
        "/etc/atlastunnel/ca-cert.pem",
        "/etc/ipsec.d/cacerts/ca-cert.pem",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_have_expected_shape() {
        let password = random_password();
        assert_eq!(password.len(), PASSWORD_LEN);
        assert!(password.chars().all(|ch| ch.is_ascii_alphanumeric()));
        assert!(!password.contains('l') && !password.contains('O'));
        assert_ne!(random_password(), random_password());
        assert_eq!(random_psk().len(), PSK_LEN);
    }

    #[test]
    fn keyvalue_round_trip_ignores_comments() {
        let parsed = parse_keyvalue("# note\nA=1\n\n B = 2 \n");
        assert_eq!(parsed.get("A").map(String::as_str), Some("1"));
        assert_eq!(parsed.get("B").map(String::as_str), Some("2"));
        assert_eq!(render_keyvalue(&parsed), "A=1\nB=2\n");
    }
}
