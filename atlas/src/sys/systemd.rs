use anyhow::{bail, Result};

use super::cmd::Cmd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Active,
    Inactive,
    Failed,
    Missing,
}

impl UnitState {
    pub fn label(&self) -> &'static str {
        match self {
            UnitState::Active => "ЗАПУЩЕН",
            UnitState::Inactive => "ОСТАНОВЛЕН",
            UnitState::Failed => "СБОЙ",
            UnitState::Missing => "НЕ УСТАНОВЛЕН",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, UnitState::Active)
    }
}

pub fn available() -> bool {
    std::path::Path::new("/run/systemd/system").is_dir()
}

pub fn require() -> Result<()> {
    if !available() {
        bail!("systemd не обнаружен — управление службами невозможно в этом окружении");
    }
    Ok(())
}

pub fn state(unit: &str) -> UnitState {
    let output = match Cmd::new("systemctl").arg("is-active").arg(unit).capture() {
        Ok(output) => output,
        Err(_) => return UnitState::Missing,
    };
    match output.trimmed() {
        "active" | "activating" => UnitState::Active,
        "failed" => UnitState::Failed,
        "inactive" | "deactivating" => UnitState::Inactive,
        _ => {
            if unit_exists(unit) {
                UnitState::Inactive
            } else {
                UnitState::Missing
            }
        }
    }
}

pub fn unit_exists(unit: &str) -> bool {
    Cmd::new("systemctl")
        .arg("list-unit-files")
        .arg("--no-legend")
        .arg(unit)
        .capture()
        .map(|output| !output.trimmed().is_empty())
        .unwrap_or(false)
}

pub fn start(unit: &str) -> Result<()> {
    Cmd::new("systemctl").arg("start").arg(unit).run()?;
    Ok(())
}

pub fn stop(unit: &str) -> Result<()> {
    Cmd::new("systemctl").arg("stop").arg(unit).run()?;
    Ok(())
}

pub fn restart(unit: &str) -> Result<()> {
    Cmd::new("systemctl").arg("restart").arg(unit).run()?;
    Ok(())
}

pub fn enable(unit: &str) -> Result<()> {
    Cmd::new("systemctl").arg("enable").arg(unit).run()?;
    Ok(())
}

pub fn disable(unit: &str) {
    let _ = Cmd::new("systemctl").arg("disable").arg(unit).capture();
}

pub fn reload_or_restart(unit: &str) {
    let _ = Cmd::new("systemctl").arg("reload").arg(unit).capture();
}

pub fn daemon_reload() -> Result<()> {
    Cmd::new("systemctl").arg("daemon-reload").run()?;
    Ok(())
}

/// Последние строки журнала юнита — показываются, когда служба не поднялась.
pub fn recent_log(unit: &str, lines: usize) -> Vec<String> {
    Cmd::new("journalctl")
        .arg("-u")
        .arg(unit)
        .arg("-n")
        .arg(lines.to_string())
        .arg("--no-pager")
        .arg("--output=cat")
        .capture()
        .map(|output| {
            output
                .stdout
                .lines()
                .map(str::to_string)
                .filter(|line| !line.trim().is_empty())
                .collect()
        })
        .unwrap_or_default()
}
