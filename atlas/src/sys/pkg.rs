use anyhow::{bail, Result};

use super::cmd::Cmd;

fn apt(args: &[&str]) -> Cmd {
    Cmd::new("apt-get")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("LC_ALL", "C")
        .args(args)
}

pub fn update() -> Result<()> {
    let output = apt(&["update", "-qq"]).capture()?;
    if !output.ok() {
        bail!("apt-get update: {}", output.failure_reason());
    }
    Ok(())
}

/// Есть ли пакет в подключённых репозиториях. Прежняя версия для новых
/// выпусков Ubuntu тянула .deb по вшитым ссылкам на конкретные сборки amd64;
/// вместо этого протокол честно объявляется недоступным на этом выпуске.
pub fn has_candidate(package: &str) -> bool {
    Cmd::new("apt-cache")
        .env("LC_ALL", "C")
        .arg("policy")
        .arg(package)
        .capture()
        .map(|output| {
            output.ok()
                && output
                    .stdout
                    .lines()
                    .any(|line| {
                        let line = line.trim();
                        line.starts_with("Candidate:") && !line.ends_with("(none)")
                    })
        })
        .unwrap_or(false)
}

pub fn install(packages: &[&str]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    for package in packages {
        if !is_installed(package) && !has_candidate(package) {
            bail!(
                "пакет «{package}» отсутствует в репозиториях этого выпуска Ubuntu"
            );
        }
    }
    let missing: Vec<&str> = packages
        .iter()
        .copied()
        .filter(|name| !is_installed(name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let mut args = vec!["install", "-y", "--no-install-recommends"];
    args.extend_from_slice(&missing);
    let output = apt(&args).capture()?;
    if !output.ok() {
        bail!(
            "установка пакетов [{}]: {}",
            missing.join(", "),
            output.failure_reason()
        );
    }

    let still_missing: Vec<&str> = missing
        .into_iter()
        .filter(|name| !is_installed(name))
        .collect();
    if !still_missing.is_empty() {
        bail!(
            "пакеты не установились несмотря на успешный apt: {}",
            still_missing.join(", ")
        );
    }
    Ok(())
}

pub fn is_installed(package: &str) -> bool {
    Cmd::new("dpkg-query")
        .arg("-W")
        .arg("-f=${db:Status-Status}")
        .arg(package)
        .capture()
        .map(|output| output.ok() && output.trimmed() == "installed")
        .unwrap_or(false)
}

pub fn preseed(question: &str, kind: &str, value: &str) -> Result<()> {
    let line = format!("{question} {kind} {value}\n");
    Cmd::new("debconf-set-selections")
        .stdin(line.into_bytes())
        .run()?;
    Ok(())
}

