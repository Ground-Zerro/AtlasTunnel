mod cli;
mod doctor;
mod fsx;
mod install;
mod model;
mod sys;
mod ui;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::json;
use std::path::Path;

use cli::{Cli, ClientCommand, Command, InstallArgs};
use install::certs::Certificate;
use install::tx::Console;
use model::protocol::{compatible_set, Protocol};
use model::secrets::{validate_login, Store};
use model::state::{self, random_password};
use sys::systemd;

const LOG_PATH: &str = "/var/log/atlastunnel/atlas.log";
const LOCK_PATH: &str = "/run/atlastunnel.lock";

fn main() {
    let cli = Cli::parse();
    if let Err(error) = dispatch(&cli) {
        if cli.json {
            let payload = json!({ "ok": false, "error": format!("{error:#}") });
            println!("{payload}");
        } else {
            eprintln!("\nОшибка: {error:#}");
        }
        std::process::exit(1);
    }
}

fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        None => manager(cli),
        Some(Command::Install(args)) => install_command(args),
        Some(Command::Uninstall { protocol, yes }) => uninstall_command(protocol, *yes),
        Some(Command::List) => list_command(cli.json),
        Some(Command::Start { protocol }) => service_command(protocol.as_deref(), systemd::start, "запущен"),
        Some(Command::Stop { protocol }) => service_command(protocol.as_deref(), systemd::stop, "остановлен"),
        Some(Command::Restart { protocol }) => {
            service_command(protocol.as_deref(), systemd::restart, "перезапущен")
        }
        Some(Command::Client(command)) => client_command(command, cli.json),
        Some(Command::Doctor) => doctor_command(cli.json),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol> {
    Protocol::parse(value).with_context(|| {
        format!(
            "неизвестный протокол «{value}»; доступны: {}",
            Protocol::ALL
                .iter()
                .map(|protocol| protocol.id())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn open_log() -> Result<String> {
    let path = sys::cmd::open_transcript(Path::new(LOG_PATH))?;
    Ok(path.display().to_string())
}

fn manager(cli: &Cli) -> Result<()> {
    sys::require_root()?;
    let _lock = fsx::lock::Lock::acquire(Path::new(LOCK_PATH))?;
    open_log()?;

    if state::installed_protocols().is_empty() {
        bail!("протоколы VPN не установлены — выполните: atlas install");
    }

    let public_ip = sys::net::public_ipv4()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "недоступен".into());

    let _ = cli;
    let mut session = ui::Session::open()?;
    let result = ui::manager::Manager::new(public_ip).run(&mut session);
    session.close();
    result
}

fn install_command(args: &InstallArgs) -> Result<()> {
    install::preflight()?;
    let _lock = fsx::lock::Lock::acquire(Path::new(LOCK_PATH))?;
    let log_path = open_log()?;

    let explicit: Vec<Protocol> = if args.all {
        compatible_set()
    } else {
        args.protocols
            .iter()
            .map(|value| parse_protocol(value))
            .collect::<Result<_>>()?
    };

    validate_login(&args.user).context("имя учётной записи")?;

    let certificate = match &args.domain {
        Some(domain) => Certificate::LetsEncrypt {
            domain: domain.clone(),
            email: args.email.clone(),
        },
        None => Certificate::SelfSigned,
    };

    if !explicit.is_empty() {
        return install_headless(explicit, args, certificate, &log_path);
    }
    install_interactive(args, certificate, log_path)
}

fn install_headless(
    selected: Vec<Protocol>,
    args: &InstallArgs,
    certificate: Certificate,
    log_path: &str,
) -> Result<()> {
    let plan = install::plan(&selected, certificate)?;

    println!("Будут установлены:");
    for protocol in &plan.selected {
        println!("  · {} — {}", protocol.display(), protocol.summary());
    }
    for protocol in &plan.replaced {
        println!("  ! {} будет заменён и снят с учёта", protocol.display());
    }
    for warning in &plan.warnings {
        println!("  ! {warning}");
    }

    if plan.needs_legacy() {
        if args.no_legacy_packages {
            bail!(
                "выбранные протоколы требуют пакеты из архивов прошлых выпусков, \
                 но указан --no-legacy-packages"
            );
        }
        println!();
        for need in &plan.legacy {
            for line in sys::legacy::warning_lines(
                need.protocol.display(),
                &need.packages,
                need.suites,
            ) {
                if line.is_empty() {
                    println!();
                } else {
                    println!("  ! {line}");
                }
            }
        }
        println!();
    }

    if !args.yes {
        bail!("для неинтерактивной установки требуется флаг --yes");
    }

    let outcome = install::execute(&plan, &args.user, &mut Console)?;
    println!("\nУстановка завершена. Журнал: {log_path}");
    println!("  IP сервера : {}", outcome.public_ip);
    println!("  Логин      : {}", outcome.user);
    println!("  Пароль     : {}", outcome.password);
    if outcome.installed.contains(&Protocol::L2tpIpsec) {
        println!("  PSK        : {}", outcome.psk);
    }
    if outcome.installed.contains(&Protocol::Sstp) {
        match outcome.certificate.domain() {
            Some(domain) => {
                println!("  SSTP       : https://{domain} (Let's Encrypt, продление автоматическое)")
            }
            None => println!("  SSTP       : самоподписанный сертификат — импортируйте на клиенте"),
        }
    }
    if outcome.installed.contains(&Protocol::OpenVpn) {
        println!(
            "  Профиль    : /etc/atlastunnel/clients/{}.ovpn",
            outcome.user
        );
    }
    Ok(())
}

fn install_interactive(
    args: &InstallArgs,
    certificate: Certificate,
    log_path: String,
) -> Result<()> {
    let mut session = ui::Session::open()?;
    let mut installer = ui::installer::Installer::new(log_path);

    let result = (|| -> Result<()> {
        loop {
            let selected = match installer.select(&mut session)? {
                ui::installer::Selection::Chosen(selected) => selected,
                ui::installer::Selection::Cancelled => return Ok(()),
            };
            let chosen = if selected.contains(&Protocol::Sstp)
                && certificate == Certificate::SelfSigned
            {
                match installer.certificate(&mut session)? {
                    Some(choice) => choice,
                    None => continue,
                }
            } else {
                certificate.clone()
            };
            let plan = install::plan(&selected, chosen)?;
            if !installer.confirm(&mut session, &plan)? {
                continue;
            }
            let outcome = installer.execute(&mut session, plan, args.user.clone())?;
            installer.summary(&mut session, &outcome)?;
            return Ok(());
        }
    })();

    session.close();
    result
}

fn uninstall_command(protocol: &str, yes: bool) -> Result<()> {
    sys::require_root()?;
    let _lock = fsx::lock::Lock::acquire(Path::new(LOCK_PATH))?;
    open_log()?;

    let protocol = parse_protocol(protocol)?;
    if !yes {
        bail!(
            "удаление {} снимет службы, правила iptables и учётные записи; повторите с --yes",
            protocol.display()
        );
    }
    install::uninstall(protocol, &mut Console)
}

fn list_command(as_json: bool) -> Result<()> {
    let installed = state::installed_protocols();
    if as_json {
        let rows: Vec<_> = installed
            .iter()
            .map(|protocol| {
                json!({
                    "protocol": protocol.id(),
                    "name": protocol.display(),
                    "units": protocol.units().iter().map(|unit| json!({
                        "unit": unit,
                        "state": systemd::state(unit).label(),
                        "active": systemd::state(unit).is_active(),
                    })).collect::<Vec<_>>(),
                    "clients": Store::list(*protocol).map(|clients| clients.len()).unwrap_or(0),
                })
            })
            .collect();
        println!("{}", json!({ "ok": true, "protocols": rows }));
        return Ok(());
    }

    if installed.is_empty() {
        println!("Протоколы не установлены.");
        return Ok(());
    }
    for protocol in installed {
        let active = protocol
            .units()
            .iter()
            .all(|unit| systemd::state(unit).is_active());
        let clients = Store::list(protocol).map(|list| list.len()).unwrap_or(0);
        println!(
            "{:<14} {:<12} клиентов: {}",
            protocol.id(),
            if active { "запущен" } else { "остановлен" },
            clients
        );
    }
    Ok(())
}

fn service_command(
    protocol: Option<&str>,
    action: fn(&str) -> Result<()>,
    verb: &str,
) -> Result<()> {
    sys::require_root()?;
    open_log()?;

    let targets = match protocol {
        Some(value) => vec![parse_protocol(value)?],
        None => state::installed_protocols(),
    };
    if targets.is_empty() {
        bail!("протоколы не установлены");
    }
    for protocol in targets {
        for unit in protocol.units() {
            action(unit).with_context(|| format!("{} / {unit}", protocol.display()))?;
        }
        println!("{} {verb}", protocol.display());
    }
    Ok(())
}

fn client_command(command: &ClientCommand, as_json: bool) -> Result<()> {
    sys::require_root()?;
    let _lock = fsx::lock::Lock::acquire(Path::new(LOCK_PATH))?;
    open_log()?;

    match command {
        ClientCommand::List { protocol, reveal } => {
            let protocol = parse_protocol(protocol)?;
            let clients = Store::list(protocol)?;
            if as_json {
                let rows: Vec<_> = clients
                    .iter()
                    .map(|client| {
                        json!({
                            "login": client.login,
                            "password": if *reveal { Some(client.password.clone()) } else { None },
                        })
                    })
                    .collect();
                println!("{}", json!({ "ok": true, "clients": rows }));
            } else if clients.is_empty() {
                println!("Учётных записей нет.");
            } else {
                for client in clients {
                    let secret = if *reveal {
                        client.password
                    } else {
                        "•".repeat(8)
                    };
                    println!("{:<24} {}", client.login, secret);
                }
            }
            Ok(())
        }
        ClientCommand::Add { protocol, login } => {
            let protocol = parse_protocol(protocol)?;
            validate_login(login)?;
            if Store::exists(protocol, login)? {
                bail!("клиент «{login}» уже существует");
            }
            let password = random_password();
            Store::upsert(protocol, login, &password)?;
            reload(protocol);
            report_secret(as_json, login, &password);
            Ok(())
        }
        ClientCommand::Remove { protocol, login } => {
            let protocol = parse_protocol(protocol)?;
            Store::remove(protocol, login)?;
            reload(protocol);
            if as_json {
                println!("{}", json!({ "ok": true, "login": login, "removed": true }));
            } else {
                println!("Клиент «{login}» удалён.");
            }
            Ok(())
        }
        ClientCommand::Passwd { protocol, login } => {
            let protocol = parse_protocol(protocol)?;
            if !Store::exists(protocol, login)? {
                bail!("клиент «{login}» не найден");
            }
            let password = random_password();
            Store::upsert(protocol, login, &password)?;
            reload(protocol);
            report_secret(as_json, login, &password);
            Ok(())
        }
    }
}

fn report_secret(as_json: bool, login: &str, password: &str) {
    if as_json {
        println!(
            "{}",
            json!({ "ok": true, "login": login, "password": password })
        );
    } else {
        println!("Логин  : {login}");
        println!("Пароль : {password}");
    }
}

fn reload(protocol: Protocol) {
    if protocol.uses_ipsec() {
        systemd::reload_or_restart("strongswan-starter");
    }
}

fn doctor_command(as_json: bool) -> Result<()> {
    sys::require_root()?;
    let findings = doctor::run();

    if as_json {
        println!(
            "{}",
            json!({
                "ok": doctor::worst(&findings) != doctor::Severity::Error,
                "findings": findings,
            })
        );
    } else {
        for finding in &findings {
            println!("[{}] {}", finding.severity.label(), finding.subject);
            println!("    {}", finding.detail);
            if let Some(remedy) = &finding.remedy {
                println!("    → {remedy}");
            }
        }
    }

    if doctor::worst(&findings) == doctor::Severity::Error {
        std::process::exit(2);
    }
    Ok(())
}
