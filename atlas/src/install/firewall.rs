use anyhow::Result;

use crate::model::protocol::Protocol;
use crate::sys::cmd::Cmd;
use crate::sys::net::Transport;

/// Все правила помечаются комментарием, поэтому их можно снять при удалении
/// протокола, не трогая чужие правила в тех же цепочках.
fn tag(protocol: Protocol) -> String {
    format!("atlas:{}", protocol.id())
}

fn rule_exists(table: &str, chain: &str, spec: &[String]) -> bool {
    Cmd::new("iptables")
        .arg("-t")
        .arg(table)
        .arg("-C")
        .arg(chain)
        .args(spec)
        .succeeded()
}

fn append(table: &str, chain: &str, spec: Vec<String>) -> Result<()> {
    if rule_exists(table, chain, &spec) {
        return Ok(());
    }
    Cmd::new("iptables")
        .arg("-t")
        .arg(table)
        .arg("-A")
        .arg(chain)
        .args(&spec)
        .run()?;
    Ok(())
}

fn with_tag(protocol: Protocol, mut spec: Vec<String>) -> Vec<String> {
    let target = spec.pop().expect("правило заканчивается целью -j");
    let jump = spec.pop().expect("правило заканчивается целью -j");
    spec.extend([
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        tag(protocol),
        jump,
        target,
    ]);
    spec
}

fn s(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

pub fn apply(protocol: Protocol, wan: &str) -> Result<()> {
    let subnet = protocol.subnet();

    append(
        "nat",
        "POSTROUTING",
        with_tag(protocol, s(&["-s", subnet, "-o", wan, "-j", "MASQUERADE"])),
    )?;
    append(
        "filter",
        "FORWARD",
        with_tag(protocol, s(&["-s", subnet, "-j", "ACCEPT"])),
    )?;
    append(
        "filter",
        "FORWARD",
        with_tag(protocol, s(&["-d", subnet, "-j", "ACCEPT"])),
    )?;

    for port in protocol.ports() {
        let proto = match port.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        };
        let number = port.number.to_string();
        append(
            "filter",
            "INPUT",
            with_tag(protocol, s(&["-p", proto, "--dport", &number, "-j", "ACCEPT"])),
        )?;
    }

    if protocol == Protocol::Pptp {
        append(
            "filter",
            "INPUT",
            with_tag(protocol, s(&["-p", "gre", "-j", "ACCEPT"])),
        )?;
    }

    if protocol.uses_ipsec() {
        append(
            "filter",
            "INPUT",
            with_tag(protocol, s(&["-p", "esp", "-j", "ACCEPT"])),
        )?;
    }

    let interface = match protocol {
        Protocol::OpenVpn => "tun+",
        _ => "ppp+",
    };
    if protocol != Protocol::Ikev2 && protocol != Protocol::Ikev2Ipsec {
        append(
            "filter",
            "FORWARD",
            with_tag(protocol, s(&["-i", interface, "-o", wan, "-j", "ACCEPT"])),
        )?;
        append(
            "filter",
            "FORWARD",
            with_tag(protocol, s(&["-i", wan, "-o", interface, "-j", "ACCEPT"])),
        )?;
    } else {
        const IKEV2_ESP_SAFE_TCP_MSS: &str = "1200";
        for flag in ["-s", "-d"] {
            append(
                "mangle",
                "FORWARD",
                with_tag(
                    protocol,
                    s(&[
                        flag, subnet, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j",
                        "TCPMSS", "--set-mss", IKEV2_ESP_SAFE_TCP_MSS,
                    ]),
                ),
            )?;
        }
    }

    Ok(())
}

/// Снимает все правила протокола по его метке.
pub fn revoke(protocol: Protocol) -> Result<usize> {
    let marker = tag(protocol);
    let mut removed = 0;

    for table in ["filter", "nat", "mangle"] {
        let listing = Cmd::new("iptables-save").arg("-t").arg(table).capture()?;
        if !listing.ok() {
            continue;
        }
        for line in listing.stdout.lines() {
            if !line.starts_with("-A") || !line.contains(&marker) {
                continue;
            }
            let spec: Vec<String> = line
                .split_whitespace()
                .skip(1)
                .map(|token| token.trim_matches('"').to_string())
                .collect();
            let Some((chain, rest)) = spec.split_first() else { continue };
            if Cmd::new("iptables")
                .arg("-t")
                .arg(table)
                .arg("-D")
                .arg(chain)
                .args(rest)
                .succeeded()
            {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

pub fn persist() -> Result<()> {
    if crate::sys::cmd::which("netfilter-persistent") {
        let output = Cmd::new("netfilter-persistent").arg("save").capture()?;
        if !output.ok() {
            anyhow::bail!("netfilter-persistent save: {}", output.failure_reason());
        }
    }
    Ok(())
}
