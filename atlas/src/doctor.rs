use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::model::protocol::{Ownership, Protocol};
use crate::model::secrets::Store;
use crate::model::state::{self, LegacyRecord, Marker};
use crate::sys::{legacy, net, systemd};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Ok,
    Warning,
    Error,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Ok => "ок",
            Severity::Warning => "внимание",
            Severity::Error => "ошибка",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub subject: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Finding {
    fn new(severity: Severity, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity,
            subject: subject.into(),
            detail: detail.into(),
            remedy: None,
        }
    }

    fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

/// Сверяет заявленное состояние (маркеры в /etc/atlastunnel) с фактическим:
/// службами, конфигами, учётными записями и владением файлами. Именно это
/// расхождение раньше оставалось невидимым — маркер утверждал, что протокол
/// установлен, хотя его конфиг был затёрт соседом.
pub fn run() -> Vec<Finding> {
    let mut findings = Vec::new();
    let installed = state::installed_protocols();

    if installed.is_empty() {
        findings.push(Finding::new(
            Severity::Warning,
            "состояние",
            "ни один протокол не установлен",
        ));
        return findings;
    }

    check_exclusive_ownership(&installed, &mut findings);
    check_public_ip(&mut findings);
    check_legacy_packages(&installed, &mut findings);
    check_sstp_plugin(&installed, &mut findings);

    for protocol in &installed {
        check_units(*protocol, &mut findings);
        check_files(*protocol, &mut findings);
        check_clients(*protocol, &mut findings);
        check_ports(*protocol, &mut findings);
    }

    if findings.is_empty() {
        findings.push(Finding::new(
            Severity::Ok,
            "состояние",
            format!("все протоколы согласованы: {}", installed.len()),
        ));
    }
    findings
}

/// Несколько установленных протоколов не могут монопольно владеть одним файлом.
fn check_exclusive_ownership(installed: &[Protocol], findings: &mut Vec<Finding>) {
    let mut owners: BTreeMap<&str, Vec<Protocol>> = BTreeMap::new();
    for protocol in installed {
        for file in protocol.owned_files() {
            if file.ownership == Ownership::Exclusive {
                owners.entry(file.path).or_default().push(*protocol);
            }
        }
    }
    for (path, claimants) in owners {
        if claimants.len() > 1 {
            let names: Vec<&str> = claimants.iter().map(|p| p.display()).collect();
            findings.push(
                Finding::new(
                    Severity::Error,
                    path,
                    format!(
                        "на файл претендуют несколько протоколов: {} — работоспособен только последний установленный",
                        names.join(", ")
                    ),
                )
                .with_remedy(format!(
                    "оставьте один протокол: atlas uninstall {}",
                    claimants[0].id()
                )),
            );
        }
    }
}

fn check_units(protocol: Protocol, findings: &mut Vec<Finding>) {
    for unit in protocol.units() {
        let state = systemd::state(unit);
        match state {
            systemd::UnitState::Active => {}
            systemd::UnitState::Missing => findings.push(
                Finding::new(
                    Severity::Error,
                    protocol.display(),
                    format!("служба {unit} не установлена, хотя протокол числится установленным"),
                )
                .with_remedy(format!("переустановите: atlas install --protocols {}", protocol.id())),
            ),
            systemd::UnitState::Failed => findings.push(
                Finding::new(
                    Severity::Error,
                    protocol.display(),
                    format!("служба {unit} в состоянии сбоя"),
                )
                .with_remedy(format!("журнал: journalctl -u {unit} -n 50")),
            ),
            systemd::UnitState::Inactive => findings.push(
                Finding::new(
                    Severity::Warning,
                    protocol.display(),
                    format!("служба {unit} остановлена"),
                )
                .with_remedy(format!("atlas start {}", protocol.id())),
            ),
        }
    }
}

fn check_files(protocol: Protocol, findings: &mut Vec<Finding>) {
    for file in protocol.owned_files() {
        if !Path::new(file.path).exists() {
            findings.push(
                Finding::new(
                    Severity::Error,
                    protocol.display(),
                    format!("отсутствует файл конфигурации {}", file.path),
                )
                .with_remedy(format!("atlas install --protocols {}", protocol.id())),
            );
        }
    }
}

fn check_clients(protocol: Protocol, findings: &mut Vec<Finding>) {
    if protocol.secrets_kind().is_none() {
        return;
    }
    match Store::list(protocol) {
        Ok(clients) if clients.is_empty() => findings.push(
            Finding::new(
                Severity::Warning,
                protocol.display(),
                "нет ни одной учётной записи — подключиться невозможно",
            )
            .with_remedy(format!("atlas client add {} <логин>", protocol.id())),
        ),
        Ok(_) => {}
        Err(error) => findings.push(Finding::new(
            Severity::Error,
            protocol.display(),
            format!("не удалось прочитать учётные записи: {error:#}"),
        )),
    }

    if let Some(marker) = Marker::load(protocol).ok().flatten() {
        if !marker.user.is_empty() {
            if let Ok(false) = Store::exists(protocol, &marker.user) {
                findings.push(
                    Finding::new(
                        Severity::Warning,
                        protocol.display(),
                        format!(
                            "учётная запись «{}» из маркера отсутствует в файле паролей",
                            marker.user
                        ),
                    )
                    .with_remedy(format!("atlas client add {} {}", protocol.id(), marker.user)),
                );
            }
        }
    }
}

fn check_ports(protocol: Protocol, findings: &mut Vec<Finding>) {
    for port in protocol.ports() {
        if net::port_listener(*port).is_none() && systemd::state(protocol.units()[0]).is_active() {
            findings.push(Finding::new(
                Severity::Warning,
                protocol.display(),
                format!("служба запущена, но порт {port} никто не слушает"),
            ));
        }
    }
}

/// Архивные пакеты — штатный, но заслуживающий внимания режим: они не получают
/// обновлений безопасности текущего выпуска.
fn check_legacy_packages(_installed: &[Protocol], findings: &mut Vec<Finding>) {
    let Ok(record) = LegacyRecord::load() else {
        return;
    };
    if record.is_empty() {
        return;
    }
    let listed: Vec<String> = record
        .entries
        .iter()
        .map(|(package, suite)| format!("{package} ({suite})"))
        .collect();
    findings.push(
        Finding::new(
            Severity::Warning,
            "пакеты из архива",
            format!(
                "используются пакеты прошлых выпусков Ubuntu: {} — обновления безопасности текущего выпуска на них не распространяются",
                listed.join(", ")
            ),
        )
        .with_remedy(
            "версии закреплены через apt-mark hold; источник: /etc/apt/sources.list.d/atlastunnel-legacy.list",
        ),
    );

    let held = legacy::held_packages();
    let unpinned: Vec<&String> = record
        .entries
        .keys()
        .filter(|package| !held.iter().any(|name| name == *package))
        .collect();
    if !unpinned.is_empty() {
        findings.push(
            Finding::new(
                Severity::Error,
                "пакеты из архива",
                format!(
                    "закрепление снято с {} — очередное обновление подменит или удалит пакет",
                    unpinned
                        .iter()
                        .map(|package| package.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .with_remedy(format!(
                "apt-mark hold {}",
                unpinned
                    .iter()
                    .map(|package| package.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            )),
        );
    }
}

/// Плагин pppd подхватывается sstpd автоматически, поэтому несовместимая
/// версия ломает SSTP молча — клиент обрывает сессию сразу после подключения.
fn check_sstp_plugin(installed: &[Protocol], findings: &mut Vec<Finding>) {
    if !installed.contains(&Protocol::Sstp) {
        return;
    }
    let present = glob_plugin();
    if !present {
        return;
    }
    let compatible = crate::sys::cmd::Cmd::new("dpkg-query")
        .args(["-W", "-f=${Version}", "sstp-client"])
        .capture()
        .ok()
        .filter(|output| output.ok())
        .map(|output| {
            crate::sys::cmd::Cmd::new("dpkg")
                .args(["--compare-versions", output.trimmed(), "ge", "1.0.19"])
                .succeeded()
        })
        .unwrap_or(true);
    if !compatible {
        findings.push(
            Finding::new(
                Severity::Error,
                "SSTP",
                "установлен несовместимый sstp-pppd-plugin.so — клиенты обрывают сессию сразу после подключения",
            )
            .with_remedy("apt-get purge -y sstp-client && systemctl restart sstp-server"),
        );
    }
}

fn glob_plugin() -> bool {
    std::fs::read_dir("/usr/lib/pppd")
        .map(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry.path().join("sstp-pppd-plugin.so").exists()
            })
        })
        .unwrap_or(false)
}

fn check_public_ip(findings: &mut Vec<Finding>) {
    let needs_certificate = state::installed_protocols()
        .into_iter()
        .any(|protocol| protocol.needs_ca_certificate());
    if !needs_certificate {
        return;
    }
    if state::ca_certificate().is_none() {
        findings.push(
            Finding::new(
                Severity::Error,
                "IKEv2",
                "CA-сертификат для клиентов не найден",
            )
            .with_remedy("переустановите протокол IKEv2"),
        );
    }
}

pub fn worst(findings: &[Finding]) -> Severity {
    findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Ok)
}
