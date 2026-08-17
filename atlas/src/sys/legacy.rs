use anyhow::{bail, Context, Result};
use std::path::Path;

use super::cmd::Cmd;
use super::pkg;

const SOURCES: &str = "/etc/apt/sources.list.d/atlastunnel-legacy.list";
const PREFERENCES: &str = "/etc/apt/preferences.d/atlastunnel-legacy";
const KEYRING: &str = "/usr/share/keyrings/ubuntu-archive-keyring.gpg";

/// Приоритет 991 выше штатных 500 — только для явно названных пакетов.
const PIN_TARGET: u16 = 991;
/// Всё остальное из архива — 100: ставится лишь тогда, когда в текущем выпуске
/// аналога нет вовсе. Без этого apt тянул бы из старого выпуска и системные
/// библиотеки вроде libkrb5 и netbase.
const PIN_FALLBACK: u16 = 100;

pub fn architecture() -> String {
    Cmd::new("dpkg")
        .arg("--print-architecture")
        .stdout()
        .unwrap_or_else(|_| "amd64".into())
}

/// Официальные зеркала Ubuntu: основные архитектуры и порты обслуживаются разными хостами.
fn mirror(architecture: &str) -> &'static str {
    match architecture {
        "amd64" | "i386" => "http://archive.ubuntu.com/ubuntu",
        _ => "http://ports.ubuntu.com/ubuntu-ports",
    }
}

fn sources_body(suites: &[&str], architecture: &str) -> String {
    let mirror = mirror(architecture);
    let mut body = String::from(
        "# Создано AtlasTunnel: пакеты, удалённые из текущего выпуска Ubuntu.\n\
         # Подпись проверяется штатным ключом Ubuntu, приоритет закрепления понижен.\n",
    );
    for suite in suites {
        for pocket in [
            (*suite).to_string(),
            format!("{suite}-updates"),
            format!("{suite}-security"),
        ] {
            body.push_str(&format!(
                "deb [arch={architecture} signed-by={KEYRING}] {mirror} {pocket} main universe\n"
            ));
        }
    }
    body
}

fn preferences_body(suites: &[&str], targets: &[&str]) -> String {
    let mut body = String::new();
    if !targets.is_empty() {
        for suite in suites {
            body.push_str(&format!(
                "Package: {}\nPin: release n={suite}\nPin-Priority: {PIN_TARGET}\n\n",
                targets.join(" ")
            ));
        }
    }
    for suite in suites {
        for pocket in [
            (*suite).to_string(),
            format!("{suite}-updates"),
            format!("{suite}-security"),
        ] {
            body.push_str(&format!(
                "Package: *\nPin: release n={pocket}\nPin-Priority: {PIN_FALLBACK}\n\n"
            ));
        }
    }
    body
}

/// Подключает архивы прошлых выпусков и закрепляет за ними только названные
/// пакеты. Ключ проверки подписи — штатный keyring Ubuntu, поэтому пакеты
/// остаются криптографически проверяемыми, в отличие от загрузки .deb по ссылке.
pub fn enable(suites: &[&str], targets: &[&str]) -> Result<()> {
    if !Path::new(KEYRING).exists() {
        bail!("не найден keyring {KEYRING} — проверка подписи архива невозможна");
    }
    let architecture = architecture();
    crate::fsx::write_atomic(Path::new(SOURCES), &sources_body(suites, &architecture), 0o644)?;
    crate::fsx::write_atomic(
        Path::new(PREFERENCES),
        &preferences_body(suites, targets),
        0o644,
    )?;
    pkg::update().context("обновление индексов после подключения старых выпусков")
}


pub fn sources_path() -> &'static Path {
    Path::new(SOURCES)
}

pub fn preferences_path() -> &'static Path {
    Path::new(PREFERENCES)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced {
    pub package: String,
    pub suite: String,
}

/// Разбирает вывод `apt-get install -s`: строки вида
/// `Inst pptpd (1.4.0-12build2 Ubuntu:22.04/jammy [amd64])`.
fn parse_simulation(output: &str, suites: &[&str]) -> Vec<Sourced> {
    let mut sourced = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("Inst ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(package) = parts.next() else { continue };
        let Some(origin) = parts.find(|token| token.contains('/')) else {
            continue;
        };
        let suite = origin
            .trim_start_matches('(')
            .split('/')
            .nth(1)
            .unwrap_or_default()
            .trim_end_matches([']', ')']);
        if let Some(matched) = suites.iter().find(|candidate| {
            suite == **candidate
                || suite == format!("{candidate}-updates")
                || suite == format!("{candidate}-security")
        }) {
            sourced.push(Sourced {
                package: package.to_string(),
                suite: if suite.is_empty() {
                    (*matched).to_string()
                } else {
                    suite.to_string()
                },
            });
        }
    }
    sourced
}

/// Показывает, какие пакеты придут из архивов, до фактической установки.
pub fn preview(packages: &[&str], suites: &[&str]) -> Result<Vec<Sourced>> {
    let output = Cmd::new("apt-get")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("LC_ALL", "C")
        .args(["install", "-s", "--no-install-recommends"])
        .args(packages)
        .capture()?;
    if !output.ok() {
        bail!(
            "проверка установки [{}]: {}",
            packages.join(", "),
            output.failure_reason()
        );
    }
    Ok(parse_simulation(&output.stdout, suites))
}

/// Ставит пакеты обычным `apt-get install` — без `-t`, чтобы зависимости
/// разрешались из текущего выпуска, а из архива приходило только то,
/// чего в нём нет. Возвращает фактически подменённые пакеты.
pub fn install(packages: &[&str], suites: &[&str]) -> Result<Vec<Sourced>> {
    let sourced = preview(packages, suites)?;

    let output = Cmd::new("apt-get")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("LC_ALL", "C")
        .args(["install", "-y", "--no-install-recommends"])
        .args(packages)
        .capture()?;
    if !output.ok() {
        bail!(
            "установка из архива [{}]: {}",
            packages.join(", "),
            output.failure_reason()
        );
    }
    for package in packages {
        if !pkg::is_installed(package) {
            bail!("пакет «{package}» не установился, несмотря на успешный apt");
        }
    }

    let names: Vec<&str> = sourced.iter().map(|item| item.package.as_str()).collect();
    hold(&names);
    Ok(sourced)
}

/// Фиксирует версию: без этого очередной `apt upgrade` подменит пакет версией
/// из текущего выпуска или удалит его вовсе.
pub fn hold(packages: &[&str]) {
    for package in packages {
        let _ = Cmd::new("apt-mark").arg("hold").arg(package).capture();
    }
}

pub fn unhold(packages: &[&str]) {
    for package in packages {
        let _ = Cmd::new("apt-mark").arg("unhold").arg(package).capture();
    }
}

pub fn held_packages() -> Vec<String> {
    Cmd::new("apt-mark")
        .arg("showhold")
        .capture()
        .map(|output| {
            output
                .stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn warning_lines(protocol_name: &str, packages: &[&str], suites: &[&str]) -> Vec<String> {
    vec![
        format!(
            "{protocol_name}: пакеты {} удалены из этого выпуска Ubuntu",
            packages.join(", ")
        ),
        format!(
            "Они будут взяты из официального архива {} с проверкой подписи.",
            suites.join(", ")
        ),
        "Обновления безопасности текущего выпуска на них не распространяются.".into(),
        "Из архива придут только недостающие пакеты, зависимости — из текущего выпуска.".into(),
        "Версии будут закреплены через apt-mark hold.".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMULATION: &str = "\
Inst adduser (3.137ubuntu1 Ubuntu:24.04/noble [all])
Inst libdbus-1-3 (1.14.10-4ubuntu4.1 Ubuntu:24.04/noble-updates [amd64])
Inst bcrelay (1.4.0-12build2 Ubuntu:22.04/jammy [amd64])
Inst ppp (2.4.9-1+1.1ubuntu4 Ubuntu:24.04/noble [amd64])
Inst pptpd (1.4.0-12build2 Ubuntu:22.04/jammy [amd64])
Conf pptpd (1.4.0-12build2 Ubuntu:22.04/jammy [amd64])
";

    #[test]
    fn only_legacy_sourced_packages_are_detected() {
        let sourced = parse_simulation(SIMULATION, &["jammy"]);
        let names: Vec<&str> = sourced.iter().map(|item| item.package.as_str()).collect();
        assert_eq!(names, vec!["bcrelay", "pptpd"]);
        assert!(sourced.iter().all(|item| item.suite == "jammy"));
    }

    #[test]
    fn current_release_packages_are_left_alone() {
        let sourced = parse_simulation(SIMULATION, &["jammy"]);
        let names: Vec<&str> = sourced.iter().map(|item| item.package.as_str()).collect();
        for current in ["adduser", "libdbus-1-3", "ppp"] {
            assert!(!names.contains(&current), "{current} не из архива");
        }
    }

    #[test]
    fn security_pocket_counts_as_the_same_suite() {
        let line = "Inst pptpd (1.4.0-12build2 Ubuntu:22.04/jammy-security [amd64])\n";
        let sourced = parse_simulation(line, &["jammy"]);
        assert_eq!(sourced.len(), 1);
        assert_eq!(sourced[0].suite, "jammy-security");
    }

    #[test]
    fn named_packages_outrank_the_current_release() {
        let body = preferences_body(&["jammy"], &["pptpd"]);
        assert!(body.contains("Package: pptpd\nPin: release n=jammy\nPin-Priority: 991"));
        assert!(body.contains("Package: *\nPin: release n=jammy\nPin-Priority: 100"));
        assert!(PIN_TARGET > 500 && PIN_FALLBACK < 500);
    }

    #[test]
    fn sources_are_signed_and_architecture_scoped() {
        let body = sources_body(&["jammy"], "arm64");
        assert_eq!(body.lines().filter(|line| line.starts_with("deb ")).count(), 3);
        assert!(body.contains(&format!("signed-by={KEYRING}")));
        assert!(body.contains("ports.ubuntu.com"));
        assert!(body.contains("arch=arm64"));
    }

    #[test]
    fn ports_mirror_is_used_for_non_intel_architectures() {
        assert!(mirror("amd64").contains("archive.ubuntu.com"));
        assert!(mirror("arm64").contains("ports.ubuntu.com"));
        assert!(mirror("riscv64").contains("ports.ubuntu.com"));
    }

    #[test]
    fn warning_names_packages_and_suites() {
        let lines = warning_lines("PPTP", &["pptpd"], &["jammy"]);
        assert!(lines[0].contains("pptpd"));
        assert!(lines.iter().any(|line| line.contains("jammy")));
        assert!(lines
            .iter()
            .any(|line| line.contains("безопасности") && line.contains("не распространяются")));
        assert!(lines.iter().any(|line| line.contains("проверкой подписи")));
    }
}
