pub mod certs;
pub mod firewall;
pub mod protocols;
pub mod sstp;
pub mod sysctl;
pub mod tx;

use anyhow::{bail, Result};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use crate::model::protocol::Protocol;
use crate::model::protocol::Availability;
use crate::model::state::{self, LegacyRecord, Marker, Network};
use crate::sys::{legacy, net, pkg, systemd};
use tx::{Progress, Transaction};

/// Что именно будет сделано. План строится до любых изменений, поэтому
/// конфликты и занятые порты обнаруживаются раньше первой записи на диск.
#[derive(Debug, Clone)]
pub struct Plan {
    pub certificate: certs::Certificate,
    pub selected: Vec<Protocol>,
    pub replaced: Vec<Protocol>,
    pub first_run: bool,
    pub warnings: Vec<String>,
    /// Протоколы, чьи пакеты придётся брать из архивов прошлых выпусков.
    pub legacy: Vec<LegacyNeed>,
}

#[derive(Debug, Clone)]
pub struct LegacyNeed {
    pub protocol: Protocol,
    pub packages: Vec<&'static str>,
    pub suites: &'static [&'static str],
}

impl Plan {
    pub fn steps(&self) -> usize {
        self.selected.len()
            + if self.first_run { 3 } else { 1 }
            + usize::from(!self.legacy.is_empty())
            + 1
    }

    pub fn needs_legacy(&self) -> bool {
        !self.legacy.is_empty()
    }

    fn legacy_for(&self, protocol: Protocol) -> Option<&LegacyNeed> {
        self.legacy.iter().find(|need| need.protocol == protocol)
    }
}

pub fn plan(selected: &[Protocol], certificate: certs::Certificate) -> Result<Plan> {
    if selected.is_empty() {
        bail!("не выбран ни один протокол");
    }

    let unique: BTreeSet<Protocol> = selected.iter().copied().collect();
    let selected: Vec<Protocol> = unique.into_iter().collect();

    for left in &selected {
        for right in &selected {
            if let Some(path) = left.conflicts_with(*right) {
                bail!(
                    "{} и {} несовместимы: оба монопольно владеют {}",
                    left.display(),
                    right.display(),
                    path
                );
            }
        }
    }

    let mut legacy = Vec::new();
    for protocol in &selected {
        match protocol.availability() {
            Availability::Available => {}
            Availability::ViaLegacy { packages, suites } => legacy.push(LegacyNeed {
                protocol: *protocol,
                packages,
                suites,
            }),
            Availability::Unavailable(packages) => bail!(
                "{} недоступен: пакеты {} не публиковались ни в одном выпуске Ubuntu",
                protocol.display(),
                packages.join(", ")
            ),
        }
    }

    let installed = state::installed_protocols();
    let mut replaced = Vec::new();
    for candidate in &selected {
        for existing in &installed {
            if selected.contains(existing) {
                continue;
            }
            if candidate.conflicts_with(*existing).is_some() && !replaced.contains(existing) {
                replaced.push(*existing);
            }
        }
    }

    let mut warnings = Vec::new();
    for protocol in &selected {
        for port in protocol.ports() {
            if let Some(process) = net::port_listener(*port) {
                let ours = protocol
                    .units()
                    .iter()
                    .any(|unit| unit.split('@').next() == Some(process.as_str()))
                    || process == "xl2tpd"
                    || process == "charon";
                if !ours {
                    warnings.push(format!(
                        "порт {port} уже слушает «{process}» — {} может не запуститься",
                        protocol.display()
                    ));
                }
            }
        }
    }

    if certificate.domain().is_some() && !selected.contains(&Protocol::Sstp) {
        bail!("сертификат Let's Encrypt запрашивается для SSTP, но SSTP не выбран");
    }

    Ok(Plan {
        certificate,
        selected,
        replaced,
        first_run: installed.is_empty(),
        warnings,
        legacy,
    })
}

pub fn preflight() -> Result<()> {
    crate::sys::require_root()?;
    net::require_ubuntu()?;
    systemd::require()?;
    for tool in ["iptables", "curl", "ip"] {
        if !crate::sys::cmd::which(tool) {
            bail!("не найдена обязательная утилита: {tool}");
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Outcome {
    pub certificate: certs::Certificate,
    pub user: String,
    pub password: String,
    pub psk: String,
    pub public_ip: Ipv4Addr,
    pub installed: Vec<Protocol>,
}

/// Выполняет план. Любая ошибка откатывает все изменённые файлы к исходному
/// состоянию: система не остаётся в наполовину настроенном виде.
pub fn execute(plan: &Plan, user: &str, progress: &mut dyn Progress) -> Result<Outcome> {
    state::ensure_state_dir()?;

    let mut transaction = Transaction::new();
    let result = run_steps(plan, user, progress, &mut transaction);

    match result {
        Ok(outcome) => {
            transaction.commit();
            Ok(outcome)
        }
        Err(error) => {
            let touched = transaction.touched();
            let failures = transaction.rollback();
            if failures.is_empty() {
                progress.warn(&format!("изменения отменены, восстановлено файлов: {touched}"));
            } else {
                for failure in &failures {
                    progress.warn(&format!("откат не удался: {failure}"));
                }
            }
            Err(error)
        }
    }
}

fn run_steps(
    plan: &Plan,
    user: &str,
    progress: &mut dyn Progress,
    transaction: &mut Transaction,
) -> Result<Outcome> {
    progress.step("Сетевые параметры");
    let public_ip = net::public_ipv4()?;
    progress.ok(&format!("публичный адрес: {public_ip}"));

    let network = match Network::load()? {
        Some(existing) if net::interface_exists(&existing.wan_interface) => existing,
        _ => Network {
            wan_interface: net::wan_interface()?,
            public_ip: Some(public_ip),
        },
    };
    progress.ok(&format!("внешний интерфейс: {}", network.wan_interface));
    let network = Network {
        wan_interface: network.wan_interface,
        public_ip: Some(public_ip),
    };
    transaction.guard(std::path::Path::new("/etc/atlastunnel/network.conf"))?;
    network.save()?;

    if plan.first_run {
        progress.step("Базовые пакеты");
        pkg::preseed("iptables-persistent", "iptables-persistent/autosave_v4", "boolean true")?;
        pkg::preseed("iptables-persistent", "iptables-persistent/autosave_v6", "boolean false")?;
        pkg::update()?;
        pkg::install(&["iptables-persistent", "curl", "iproute2"])?;
        progress.ok("базовые пакеты установлены");

        progress.step("Параметры ядра");
        sysctl::apply(transaction, progress)?;
    }

    if plan.needs_legacy() {
        progress.step("Архивы прошлых выпусков");
        let suites: Vec<&str> = plan
            .legacy
            .iter()
            .flat_map(|need| need.suites.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for need in &plan.legacy {
            for line in legacy::warning_lines(need.protocol.display(), &need.packages, need.suites) {
                if !line.is_empty() {
                    progress.warn(&line);
                }
            }
        }
        let targets: Vec<&str> = plan
            .legacy
            .iter()
            .flat_map(|need| need.packages.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        transaction.guard(legacy::sources_path())?;
        transaction.guard(legacy::preferences_path())?;
        legacy::enable(&suites, &targets)?;
        progress.ok(&format!("подключены архивы: {}", suites.join(", ")));
    }

    let password = state::random_password();
    let psk = state::random_psk();
    let today = state::today();
    let mut installed = Vec::new();

    for protocol in &plan.selected {
        progress.step(protocol.display());

        match plan.legacy_for(*protocol) {
            None => {
                pkg::install(protocol.packages())?;
            }
            Some(need) => {
                let sourced = legacy::install(protocol.packages(), need.suites)?;
                for item in &sourced {
                    progress.warn(&format!(
                        "«{}» установлен из архива {}",
                        item.package, item.suite
                    ));
                }
                LegacyRecord::record(
                    &sourced
                        .iter()
                        .map(|item| (item.package.clone(), item.suite.clone()))
                        .collect::<Vec<_>>(),
                )?;
                progress.info(&format!(
                    "закреплено версий: {} (остальные зависимости из текущего выпуска)",
                    sourced.len()
                ));
            }
        }
        progress.info("пакеты установлены");

        let context = protocols::Context {
            public_ip,
            certificate: &plan.certificate,
            user,
            password: &password,
            psk: &psk,
        };
        protocols::configure(*protocol, transaction, progress, &context)?;
        progress.info("конфигурация записана");

        firewall::apply(*protocol, &network.wan_interface)?;
        progress.info("правила iptables применены");

        for unit in protocol.units() {
            systemd::enable(unit)?;
            systemd::restart(unit)?;
        }
        verify(*protocol, progress)?;

        Marker {
            protocol: *protocol,
            user: user.to_string(),
            password: password.clone(),
            psk: if *protocol == Protocol::L2tpIpsec {
                Some(psk.clone())
            } else {
                None
            },
            installed: today.clone(),
        }
        .save()?;
        installed.push(*protocol);
        progress.ok(&format!("{} установлен и запущен", protocol.display()));
    }

    progress.step("Завершение");
    for protocol in &plan.replaced {
        Marker::remove(*protocol)?;
        let _ = firewall::revoke(*protocol);
        forget_secrets(*protocol, progress);
        progress.warn(&format!(
            "{} заменён и снят с учёта",
            protocol.display()
        ));
    }

    if let Err(error) = firewall::persist() {
        progress.warn(&format!("правила iptables не сохранены: {error:#}"));
    } else {
        progress.ok("правила iptables сохранены");
    }

    Ok(Outcome {
        certificate: plan.certificate.clone(),
        user: user.to_string(),
        password,
        psk,
        public_ip,
        installed,
    })
}

/// Проверка, что служба действительно поднялась. Прежняя версия сообщала
/// об успехе, даже если демон падал сразу после старта.
fn verify(protocol: Protocol, progress: &mut dyn Progress) -> Result<()> {
    for unit in protocol.units() {
        let state = systemd::state(unit);
        if !state.is_active() {
            let log = systemd::recent_log(unit, 12);
            for line in &log {
                progress.warn(line);
            }
            bail!(
                "служба {unit} не запустилась ({}) — подробности в журнале",
                state.label()
            );
        }
    }
    Ok(())
}

/// Удаляет учётные данные снятого протокола, но только если тот же способ
/// хранения не используется другим установленным протоколом: PPTP, L2TP и SSTP
/// делят chap-secrets, а L2TP/IPsec и IKEv2 — ipsec.secrets.
fn forget_secrets(protocol: Protocol, progress: &mut dyn Progress) {
    // Общий ключ принадлежит только L2TP/IPsec, поэтому снимается независимо
    // от того, остались ли другие протоколы в том же файле паролей.
    if protocol == Protocol::L2tpIpsec {
        let path = std::path::Path::new(crate::model::protocol::IPSEC_SECRETS);
        if let Ok(mut secrets) = crate::model::secrets::IpsecSecrets::load(path) {
            if secrets.psk.take().is_some() {
                let _ = crate::fsx::write_atomic(path, &secrets.render(), 0o600);
                progress.info("общий ключ PSK удалён");
            }
        }
    }

    let Some(kind) = protocol.secrets_kind() else {
        return;
    };
    let shared = state::installed_protocols()
        .into_iter()
        .any(|other| other != protocol && other.secrets_kind() == Some(kind));
    if shared {
        progress.info("учётные записи сохранены: файл паролей используется другим протоколом");
        return;
    }

    let logins: Vec<String> = crate::model::secrets::Store::list(protocol)
        .unwrap_or_default()
        .into_iter()
        .map(|client| client.login)
        .collect();
    for login in &logins {
        let _ = crate::model::secrets::Store::remove(protocol, login);
    }
    if !logins.is_empty() {
        progress.info(&format!(
            "удалены учётные записи {}: {}",
            protocol.display(),
            logins.len()
        ));
    }
}

/// Снимает закрепление версий архивных пакетов, если их больше не использует
/// ни один установленный протокол.
fn release_legacy_holds(protocol: Protocol, progress: &mut dyn Progress) {
    if protocol.legacy_suites().is_empty() {
        return;
    }
    // Реестр снимается целиком только когда не остаётся ни одного протокола,
    // которому нужны архивные пакеты: они общие для всех таких протоколов.
    let still_needed = state::installed_protocols()
        .into_iter()
        .any(|other| other != protocol && !other.legacy_suites().is_empty());
    if still_needed {
        return;
    }
    let Ok(record) = LegacyRecord::load() else {
        return;
    };
    if record.is_empty() {
        return;
    }
    let names: Vec<&str> = record.entries.keys().map(String::as_str).collect();
    legacy::unhold(&names);
    progress.info(&format!("снято закрепление версий: {}", names.join(", ")));
    let _ = LegacyRecord::clear();
}

/// Снятие протокола: маркер, правила, юниты и учётные записи.
pub fn uninstall(protocol: Protocol, progress: &mut dyn Progress) -> Result<()> {
    if !protocol.is_installed() {
        bail!("{} не установлен", protocol.display());
    }

    let shared_units: BTreeSet<&str> = state::installed_protocols()
        .into_iter()
        .filter(|other| *other != protocol)
        .flat_map(|other| other.units().iter().copied())
        .collect();

    if protocol == Protocol::Sstp {
        sstp::remove(progress)?;
    }

    for unit in protocol.units() {
        if shared_units.contains(unit) {
            progress.info(&format!("{unit} используется другим протоколом и остаётся запущенным"));
            continue;
        }
        let _ = systemd::stop(unit);
        systemd::disable(unit);
        progress.info(&format!("{unit} остановлен"));
    }

    let removed = firewall::revoke(protocol)?;
    progress.info(&format!("снято правил iptables: {removed}"));
    let _ = firewall::persist();

    Marker::remove(protocol)?;
    forget_secrets(protocol, progress);
    release_legacy_holds(protocol, progress);
    progress.ok(&format!("{} удалён", protocol.display()));
    Ok(())
}
