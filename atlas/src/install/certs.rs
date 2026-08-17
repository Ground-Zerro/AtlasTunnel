use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::path::Path;

use super::tx::{Progress, Transaction};
use crate::fsx;
use crate::sys::cmd::Cmd;

const CA_KEY: &str = "/etc/ipsec.d/private/ca-key.pem";
const CA_CERT: &str = "/etc/ipsec.d/cacerts/ca-cert.pem";
const SERVER_KEY: &str = "/etc/ipsec.d/private/server-key.pem";
const SERVER_CERT: &str = "/etc/ipsec.d/certs/server-cert.pem";
const CA_EXPORT: &str = "/etc/atlastunnel/ca-cert.pem";
const SSTP_DIR: &str = "/etc/sstp-server";
const RENEWAL_HOOK: &str = "/etc/letsencrypt/renewal-hooks/deploy/atlastunnel.sh";

/// Чем подписан сертификат SSTP. Самоподписанный работает везде, но требует
/// ручного импорта на клиенте; сертификат Let's Encrypt Windows принимает сам.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Certificate {
    SelfSigned,
    LetsEncrypt { domain: String, email: Option<String> },
}

impl Certificate {
    pub fn domain(&self) -> Option<&str> {
        match self {
            Certificate::SelfSigned => None,
            Certificate::LetsEncrypt { domain, .. } => Some(domain),
        }
    }
}

/// Пути, которые получает демон. Для Let's Encrypt это симлинки в live/,
/// поэтому после продления достаточно перезапустить службу — путь не меняется.
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub cert: String,
    pub key: String,
}

fn pki(args: &[&str]) -> Cmd {
    Cmd::new("ipsec").arg("pki").args(args)
}

/// Каждый шаг проверяется отдельно: в bash-версии падение любой команды в
/// конвейере оставляло пустой файл сертификата, а установка продолжалась.
fn produce(path: &str, command: Cmd, mode: u32) -> Result<()> {
    let output = command.capture()?;
    if !output.ok() {
        bail!("генерация {path}: {}", output.failure_reason());
    }
    if output.stdout.trim().is_empty() {
        bail!("генерация {path}: команда вернула пустой результат");
    }
    let target = Path::new(path);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    fsx::write_atomic(target, &output.stdout, mode)?;
    Ok(())
}

pub fn issue_ipsec(
    tx: &mut Transaction,
    progress: &mut dyn Progress,
    public_ip: Ipv4Addr,
) -> Result<()> {
    std::fs::create_dir_all("/etc/ipsec.d/private")?;
    std::fs::create_dir_all("/etc/ipsec.d/cacerts")?;
    std::fs::create_dir_all("/etc/ipsec.d/certs")?;
    fsx::set_mode(Path::new("/etc/ipsec.d/private"), 0o700)?;

    for path in [CA_KEY, CA_CERT, SERVER_KEY, SERVER_CERT, CA_EXPORT] {
        tx.guard(Path::new(path))?;
    }

    progress.info("Генерация корневого ключа");
    produce(
        CA_KEY,
        pki(&["--gen", "--type", "rsa", "--size", "4096", "--outform", "pem"]),
        0o600,
    )?;

    progress.info("Выпуск корневого сертификата");
    produce(
        CA_CERT,
        pki(&[
            "--self", "--ca", "--lifetime", "3650", "--in", CA_KEY, "--type", "rsa", "--dn",
            "CN=AtlasTunnel Root CA", "--outform", "pem",
        ]),
        0o644,
    )?;

    progress.info("Генерация серверного ключа");
    produce(
        SERVER_KEY,
        pki(&["--gen", "--type", "rsa", "--size", "4096", "--outform", "pem"]),
        0o600,
    )?;

    progress.info(&format!("Выпуск серверного сертификата на {public_ip}"));
    let public = pki(&["--pub", "--in", SERVER_KEY, "--type", "rsa"]).capture()?;
    if !public.ok() || public.stdout_bytes.is_empty() {
        bail!("извлечение публичного ключа сервера: {}", public.failure_reason());
    }
    let address = public_ip.to_string();
    produce(
        SERVER_CERT,
        pki(&[
            "--issue",
            "--lifetime",
            "1825",
            "--cacert",
            CA_CERT,
            "--cakey",
            CA_KEY,
            "--dn",
            &format!("CN={address}"),
            "--san",
            &address,
            "--flag",
            "serverAuth",
            "--flag",
            "ikeIntermediate",
            "--outform",
            "pem",
        ])
        .stdin(public.stdout_bytes),
        0o644,
    )?;

    let ca = std::fs::read_to_string(CA_CERT).context("чтение корневого сертификата")?;
    fsx::write_atomic(Path::new(CA_EXPORT), &ca, 0o644)?;
    progress.ok(&format!("CA-сертификат для клиентов: {CA_EXPORT}"));
    Ok(())
}

/// Самоподписанный сертификат для SSTP. Клиенты Windows не доверяют ему
/// автоматически, поэтому его тоже нужно раздавать вручную.
pub fn issue_sstp(tx: &mut Transaction, public_ip: Ipv4Addr) -> Result<CertPaths> {
    std::fs::create_dir_all(SSTP_DIR)?;
    let key = "/etc/sstp-server/key.pem";
    let cert = "/etc/sstp-server/cert.pem";
    tx.guard(Path::new(key))?;
    tx.guard(Path::new(cert))?;

    let output = Cmd::new("openssl")
        .args([
            "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:2048", "-keyout", key,
            "-out", cert, "-subj",
        ])
        .arg(format!("/CN={public_ip}"))
        .capture()?;
    if !output.ok() {
        bail!("генерация сертификата SSTP: {}", output.failure_reason());
    }
    fsx::set_mode(Path::new(key), 0o600)?;
    fsx::set_mode(Path::new(cert), 0o644)?;
    Ok(CertPaths { cert: cert.into(), key: key.into() })
}

/// certbot заканчивает вывод общей отсылкой в форум, поэтому берём строки,
/// которые действительно объясняют отказ.
fn certbot_reason(output: &crate::sys::cmd::Output) -> String {
    let meaningful: Vec<&str> = output
        .stderr
        .lines()
        .chain(output.stdout.lines())
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("Ask for help")
                && !line.starts_with("See the logfile")
                && !line.contains("Saving debug log")
                && !line.starts_with("-")
        })
        .collect();

    let tail: Vec<&str> = meaningful
        .iter()
        .rev()
        .take(4)
        .rev()
        .copied()
        .collect();

    if tail.is_empty() {
        format!(
            "{}\n  подробности: /var/log/letsencrypt/letsencrypt.log",
            output.failure_reason()
        )
    } else {
        format!(
            "{}\n  подробности: /var/log/letsencrypt/letsencrypt.log",
            tail.join("\n  ")
        )
    }
}

/// Проверяет, что домен указывает на этот сервер: certbot в режиме standalone
/// иначе упадёт с невнятной ошибкой уже после установки пакетов.
fn domain_points_here(domain: &str, public_ip: Ipv4Addr) -> Result<()> {
    let output = Cmd::new("getent").args(["ahostsv4", domain]).timeout(30).capture()?;
    if !output.ok() || output.trimmed().is_empty() {
        bail!("домен {domain} не разрешается в IPv4-адрес");
    }
    let resolved: Vec<String> = output
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect();
    if !resolved.iter().any(|address| address == &public_ip.to_string()) {
        bail!(
            "домен {domain} указывает на {}, а сервер имеет адрес {public_ip} — \
             исправьте A-запись и повторите",
            resolved.join(", ")
        );
    }
    Ok(())
}

/// Выпуск доверенного сертификата. Продление выполняет штатный таймер certbot,
/// а deploy-хук перезапускает демон, чтобы он подхватил новый файл.
pub fn issue_letsencrypt(
    tx: &mut Transaction,
    progress: &mut dyn Progress,
    domain: &str,
    email: Option<&str>,
    public_ip: Ipv4Addr,
) -> Result<CertPaths> {
    domain_points_here(domain, public_ip)?;
    progress.info(&format!("домен {domain} указывает на этот сервер"));

    if let Some(process) = crate::sys::net::port_listener(crate::sys::net::Port::tcp(80)) {
        bail!(
            "порт TCP/80 занят процессом «{process}» — certbot не сможет подтвердить домен; \
             освободите порт или используйте самоподписанный сертификат"
        );
    }

    crate::sys::pkg::install(&["certbot"])?;

    let mut command = Cmd::new("certbot")
        .args([
            "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--keep-until-expiring",
            "-d",
        ])
        .arg(domain);
    command = match email {
        Some(address) => command.args(["--email", address]),
        None => command.arg("--register-unsafely-without-email"),
    };

    let output = command.capture()?;
    if !output.ok() {
        bail!(
            "выпуск сертификата Let's Encrypt для {domain}:\n  {}",
            certbot_reason(&output)
        );
    }

    let live = format!("/etc/letsencrypt/live/{domain}");
    let paths = CertPaths {
        cert: format!("{live}/fullchain.pem"),
        key: format!("{live}/privkey.pem"),
    };
    if !Path::new(&paths.cert).exists() {
        bail!("certbot отработал, но {} не появился", paths.cert);
    }
    progress.ok(&format!("сертификат Let's Encrypt выпущен для {domain}"));

    std::fs::create_dir_all("/etc/letsencrypt/renewal-hooks/deploy")?;
    tx.write(
        Path::new(RENEWAL_HOOK),
        "#!/bin/sh\n\
         # Создано AtlasTunnel: подхватить продлённый сертификат.\n\
         systemctl is-active --quiet sstp-server && systemctl restart sstp-server\n\
         exit 0\n",
        0o755,
    )?;

    // Продление выполняет таймер из пакета certbot; без него сертификат
    // протухнет через 90 дней и SSTP перестанет принимать клиентов.
    if crate::sys::systemd::unit_exists("certbot.timer") {
        let _ = crate::sys::systemd::enable("certbot.timer");
        let _ = crate::sys::systemd::start("certbot.timer");
        progress.ok("автопродление включено (certbot.timer)");
    } else {
        progress.warn("таймер certbot не найден — проверьте автопродление вручную");
    }

    Ok(paths)
}
