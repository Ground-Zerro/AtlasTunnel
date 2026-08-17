use anyhow::{bail, Context, Result};
use std::path::Path;

use super::tx::{Progress, Transaction};
use crate::sys::{cmd::Cmd, pkg, systemd};

pub const VENV: &str = "/opt/atlastunnel/sstp";
pub const UNIT_PATH: &str = "/etc/systemd/system/sstp-server.service";

const PACKAGE: &str = "sstp-server";
const BUILD_DEPS: [&str; 2] = ["gcc", "python3-dev"];

/// Версия 0.6.0 падает с SEGV в C-расширении `codec` при первом же подключении
/// клиента — проверено на стенде, воспроизводится даже на 127.0.0.1. Рабочая
/// версия 0.7.2 требует Python 3.12, поэтому интерпретатор ниже не годится.
const MIN_PYTHON: (u32, u32) = (3, 12);
const MIN_PACKAGE: (u32, u32) = (0, 7);
const DEADSNAKES_LIST: &str = "/etc/apt/sources.list.d/atlastunnel-deadsnakes.list";
const DEADSNAKES_KEY: &str = "/usr/share/keyrings/atlastunnel-deadsnakes.gpg";
const DEADSNAKES_FINGERPRINT: &str = "F23C5A6CF475977595C89F51BA6932366A755776";

/// Пакет `sstp-client` нужен только ради `sstp-pppd-plugin.so`, через который
/// sstpd получает от pppd ключи MPPE для crypto binding. Плагин из 1.0.17
/// (Ubuntu 22.04) несовместим с sstp-server 0.7.2: клиент обрывает сессию
/// сразу после CALL_CONNECTED. Версия 1.0.19 (24.04) работает — проверено
/// подключением. Без плагина туннель поднимается, но без crypto binding.
const PLUGIN_PACKAGE: &str = "sstp-client";
const PLUGIN_MIN_VERSION: &str = "1.0.19";

fn venv_bin(name: &str) -> String {
    format!("{VENV}/bin/{name}")
}

pub fn daemon_path() -> String {
    venv_bin("sstpd")
}

pub fn is_installed() -> bool {
    Path::new(&daemon_path()).exists()
}

/// Демон SSTP не пакетирован ни в одном выпуске Ubuntu — он публикуется на PyPI
/// (sorz/sstp-server). Прежние версии AtlasTunnel звали `apt-get install
/// sstp-server`, чего не могло сработать: в репозиториях есть только клиент.
/// Ставим в отдельный venv, чтобы не трогать системный Python (на 24.04 его
/// pip вообще отвергает установку по PEP 668).
fn version_of(interpreter: &str) -> Option<(u32, u32)> {
    let text = Cmd::new(interpreter).arg("--version").capture().ok()?;
    if !text.ok() {
        return None;
    }
    let raw = format!("{} {}", text.stdout.trim(), text.stderr.trim());
    let digits = raw.split_whitespace().find(|token| token.starts_with(char::is_numeric))?;
    let mut parts = digits.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

/// Подбирает интерпретатор не ниже 3.12. Если системный старше, ставит
/// python3.12 из deadsnakes: в репозиториях Ubuntu 22.04 его нет, а без него
/// пришлось бы брать заведомо падающую 0.6.0.
fn python_interpreter(progress: &mut dyn Progress) -> Result<String> {
    for candidate in ["python3.13", "python3.12", "python3"] {
        if let Some((major, minor)) = version_of(candidate) {
            if (major, minor) >= MIN_PYTHON {
                progress.info(&format!("интерпретатор: {candidate} {major}.{minor}"));
                return Ok(candidate.to_string());
            }
        }
    }

    progress.warn(&format!(
        "системный Python ниже {}.{} — рабочая версия {PACKAGE} на нём не запускается",
        MIN_PYTHON.0, MIN_PYTHON.1
    ));
    progress.warn("подключается архив deadsnakes для установки python3.12");

    add_deadsnakes(progress)?;
    pkg::update()?;
    pkg::install(&["python3.12", "python3.12-venv"])?;

    match version_of("python3.12") {
        Some((major, minor)) if (major, minor) >= MIN_PYTHON => {
            progress.ok(&format!("установлен python3.12 {major}.{minor}"));
            Ok("python3.12".into())
        }
        _ => bail!("python3.12 не установился — SSTP на этом выпуске недоступен"),
    }
}

/// Ставит плагин только если доступная версия заведомо совместима.
fn setup_plugin(progress: &mut dyn Progress) {
    let candidate = Cmd::new("apt-cache")
        .env("LC_ALL", "C")
        .args(["policy", PLUGIN_PACKAGE])
        .capture()
        .ok()
        .and_then(|output| {
            output.stdout.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("Candidate:")
                    .map(|value| value.trim().to_string())
            })
        })
        .filter(|value| value != "(none)");

    let Some(candidate) = candidate else {
        progress.warn("sstp-client недоступен — SSTP будет работать без crypto binding");
        return;
    };

    let compatible = Cmd::new("dpkg")
        .args(["--compare-versions", &candidate, "ge", PLUGIN_MIN_VERSION])
        .succeeded();

    if !compatible {
        progress.warn(&format!(
            "{PLUGIN_PACKAGE} {candidate} несовместим с sstp-server (нужен {PLUGIN_MIN_VERSION}+)"
        ));
        // sstpd находит плагин сам, флага для отключения у него нет, поэтому
        // несовместимую версию приходится снимать — иначе туннель не поднимется.
        if pkg::is_installed(PLUGIN_PACKAGE) {
            let removed = Cmd::new("apt-get")
                .env("DEBIAN_FRONTEND", "noninteractive")
                .args(["purge", "-y", PLUGIN_PACKAGE])
                .capture()
                .map(|output| output.ok())
                .unwrap_or(false);
            if removed {
                progress.warn(&format!("{PLUGIN_PACKAGE} удалён: с ним клиент обрывает сессию"));
            } else {
                progress.warn(&format!(
                    "не удалось снять {PLUGIN_PACKAGE} — SSTP может не заработать"
                ));
            }
        }
        progress.warn("SSTP работает без crypto binding на этом выпуске Ubuntu");
        return;
    }

    if pkg::install(&[PLUGIN_PACKAGE]).is_ok() {
        progress.info(&format!("{PLUGIN_PACKAGE} {candidate}: crypto binding включён"));
    }
}

/// Репозиторий подключается записью файлов, а не `add-apt-repository`: тот
/// требует software-properties-common, который тянет packagekit с dbus, и в
/// придачу умеет зависать на получении ключа без какого-либо предела времени.
fn add_deadsnakes(progress: &mut dyn Progress) -> Result<()> {
    let codename = crate::sys::net::codename()
        .context("не удалось определить кодовое имя выпуска Ubuntu")?;

    if !Path::new(DEADSNAKES_KEY).exists() {
        let key = Cmd::new("curl")
            .args(["-fsS", "--max-time", "30"])
            .arg(format!(
                "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{DEADSNAKES_FINGERPRINT}"
            ))
            .timeout(60)
            .capture()?;
        if !key.ok() || key.stdout_bytes.is_empty() {
            bail!("не удалось получить ключ подписи deadsnakes: {}", key.failure_reason());
        }

        let armored = Cmd::new("gpg")
            .args(["--dearmor", "--output", DEADSNAKES_KEY])
            .stdin(key.stdout_bytes)
            .timeout(60)
            .capture()?;
        if !armored.ok() || !Path::new(DEADSNAKES_KEY).exists() {
            bail!("не удалось сохранить ключ подписи: {}", armored.failure_reason());
        }
        progress.info("ключ подписи deadsnakes сохранён");
    }

    crate::fsx::write_atomic(
        Path::new(DEADSNAKES_LIST),
        &format!(
            "# Создано AtlasTunnel: python3.12 для SSTP.\n\
             deb [signed-by={DEADSNAKES_KEY}] \
             https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu {codename} main\n"
        ),
        0o644,
    )?;

    pkg::update()?;
    Ok(())
}

fn create_venv(progress: &mut dyn Progress, interpreter: &str) -> Result<()> {
    if interpreter == "python3" {
        pkg::install(&["python3-venv"])?;
    }

    if Path::new(VENV).exists() {
        std::fs::remove_dir_all(VENV)
            .with_context(|| format!("очистка {VENV} перед переустановкой"))?;
    }
    std::fs::create_dir_all(Path::new(VENV).parent().unwrap())?;

    Cmd::new(interpreter)
        .arg("-m")
        .arg("venv")
        .arg(VENV)
        .run()
        .context("создание виртуального окружения")?;
    progress.info(&format!("создано окружение {VENV}"));
    Ok(())
}

/// pip сам выбирает версию по requires_python: на Python 3.12 это 0.7.2 с
/// готовым manylinux-колесом, на 3.10 — 0.6.0, у которой колеса нет и C-расширение
/// собирается из исходников. Поэтому сначала пробуем только бинарное колесо и
/// лишь при неудаче ставим компилятор — на свежих системах он не понадобится.
fn install_package(progress: &mut dyn Progress) -> Result<String> {
    let pip = venv_bin("pip");

    let wheel_only = Cmd::new(&pip)
        .args(["install", "--no-cache-dir", "--only-binary=:all:", PACKAGE])
        .capture()?;

    if !wheel_only.ok() {
        progress.info("готового пакета нет — сборка из исходников");
        pkg::install(&BUILD_DEPS)?;
        let from_source = Cmd::new(&pip)
            .args(["install", "--no-cache-dir", PACKAGE])
            .capture()?;
        if !from_source.ok() {
            bail!("установка {PACKAGE} из PyPI: {}", from_source.failure_reason());
        }
    }

    if !is_installed() {
        bail!("{PACKAGE} установлен, но исполняемый файл {} не появился", daemon_path());
    }

    let version = Cmd::new(&pip)
        .args(["show", PACKAGE])
        .capture()?
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("Version:").map(|value| value.trim().to_string()))
        .unwrap_or_else(|| "неизвестно".into());

    // Отдельная проверка: pip молча откатывается на старую версию, когда
    // интерпретатор не подходит, а 0.6.x падает при первом подключении.
    let mut parts = version.split('.');
    let numeric = (
        parts.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0),
        parts.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0),
    );
    if numeric < MIN_PACKAGE {
        bail!(
            "установлена {PACKAGE} {version}, а нужна не ниже {}.{}: \
             ранние версии падают при подключении клиента",
            MIN_PACKAGE.0,
            MIN_PACKAGE.1
        );
    }
    Ok(version)
}

/// Юнит задаёт параметры флагами, а не конфиг-файлом: формат INI-конфига
/// различается между 0.6 и 0.7, а набор флагов у обеих версий одинаковый.
fn unit(local_ip: &str, subnet: &str, range: &str, certs: &super::certs::CertPaths) -> String {
    format!(
        "[Unit]\n\
         Description=SSTP VPN server (AtlasTunnel)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={daemon} \\\n\
         \x20   --listen 0.0.0.0 --listen-port 443 \\\n\
         \x20   --pem-cert {cert} \\\n\
         \x20   --pem-key {key} \\\n\
         \x20   --pppd /usr/sbin/pppd \\\n\
         \x20   --pppd-config /etc/ppp/sstp-options \\\n\
         \x20   --local {local_ip} \\\n\
         \x20   --remote {subnet} \\\n\
         \x20   --range {range}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        daemon = daemon_path(),
        cert = certs.cert,
        key = certs.key,
    )
}

pub fn provision(
    tx: &mut Transaction,
    progress: &mut dyn Progress,
    local_ip: &str,
    subnet: &str,
    range: &str,
    certs: &super::certs::CertPaths,
) -> Result<()> {
    let interpreter = python_interpreter(progress)?;
    setup_plugin(progress);
    create_venv(progress, &interpreter)?;

    let version = match install_package(progress) {
        Ok(version) => version,
        Err(error) => {
            let _ = std::fs::remove_dir_all(VENV);
            return Err(error);
        }
    };
    progress.info(&format!("{PACKAGE} {version} установлен из PyPI"));

    tx.write(Path::new(UNIT_PATH), &unit(local_ip, subnet, range, certs), 0o644)?;
    systemd::daemon_reload()?;
    Ok(())
}

pub fn remove(progress: &mut dyn Progress) -> Result<()> {
    if Path::new(VENV).exists() {
        std::fs::remove_dir_all(VENV)
            .with_context(|| format!("удаление {VENV}"))?;
        progress.info(&format!("удалено окружение {VENV}"));
    }
    crate::fsx::remove_if_exists(Path::new(UNIT_PATH))?;
    let _ = systemd::daemon_reload();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_drives_the_daemon_by_flags_not_config_file() {
        let certs = super::super::certs::CertPaths {
            cert: "/etc/sstp-server/cert.pem".into(),
            key: "/etc/sstp-server/key.pem".into(),
        };
        let text = unit("10.50.60.1", "10.50.60.0/24", "10.50.60.10-100", &certs);
        assert!(text.contains("--pem-cert /etc/sstp-server/cert.pem"));
        assert!(text.contains("--listen-port 443"));
        assert!(text.contains("--pppd-config /etc/ppp/sstp-options"));
        assert!(text.contains("--local 10.50.60.1"));
        assert!(text.contains("--remote 10.50.60.0/24"));
        assert!(text.contains("--range 10.50.60.10-100"));
        // Конфиг-файл не передаётся: у 0.6 и 0.7 разный формат ключей.
        assert!(!text.contains("--conf-file") && !text.contains(" -f "));
        assert!(text.contains(&daemon_path()));
    }

    fn parse_version(version: &str) -> (u32, u32) {
        let mut parts = version.split('.');
        (
            parts.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            parts.next().and_then(|v| v.parse().ok()).unwrap_or(0),
        )
    }

    #[test]
    fn crashing_versions_are_rejected() {
        // 0.6.0 падает с SEGV в codec при первом подключении клиента.
        assert!(parse_version("0.6.0") < MIN_PACKAGE);
        assert!(parse_version("0.5.1") < MIN_PACKAGE);
        assert!(parse_version("0.7.2") >= MIN_PACKAGE);
    }

    #[test]
    fn python_below_312_is_not_accepted() {
        assert!((3u32, 10u32) < MIN_PYTHON);
        assert!((3u32, 12u32) >= MIN_PYTHON);
        assert!((3u32, 13u32) >= MIN_PYTHON);
    }

    #[test]
    fn unit_restarts_on_failure() {
        let certs = super::super::certs::CertPaths {
            cert: "/etc/letsencrypt/live/vpn.example.com/fullchain.pem".into(),
            key: "/etc/letsencrypt/live/vpn.example.com/privkey.pem".into(),
        };
        let text = unit("10.50.60.1", "10.50.60.0/24", "10.50.60.10-100", &certs);
        assert!(text.contains("/etc/letsencrypt/live/vpn.example.com/fullchain.pem"));
        assert!(text.contains("Restart=on-failure"));
        assert!(text.contains("WantedBy=multi-user.target"));
    }
}
