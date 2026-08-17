use anyhow::{bail, Result};
use std::net::Ipv4Addr;
use std::str::FromStr;

use super::cmd::Cmd;

const IP_SOURCES: [&str; 3] = [
    "https://ipinfo.io/ip",
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
];

/// Публичный адрес спрашивается у нескольких источников и проверяется на то,
/// что это действительно маршрутизируемый IPv4: он попадает в CN сертификата
/// и в leftid, где строка-заглушка сделала бы сервер неработоспособным.
pub fn public_ipv4() -> Result<Ipv4Addr> {
    let mut attempts = Vec::new();
    for source in IP_SOURCES {
        let output = Cmd::new("curl")
            .arg("-fsS")
            .arg("--max-time")
            .arg("5")
            .arg(source)
            .timeout(15)
            .capture()?;
        if !output.ok() {
            attempts.push(format!("{source}: {}", output.failure_reason()));
            continue;
        }
        let text = output.trimmed();
        match Ipv4Addr::from_str(text) {
            Ok(address) if is_public(&address) => return Ok(address),
            Ok(address) => attempts.push(format!("{source}: адрес {address} не является публичным")),
            Err(_) => attempts.push(format!("{source}: ответ не похож на IPv4")),
        }
    }
    bail!(
        "не удалось определить публичный IPv4 сервера:\n  {}",
        attempts.join("\n  ")
    )
}

pub fn is_public(address: &Ipv4Addr) -> bool {
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.octets()[0] == 100 && (64..128).contains(&address.octets()[1]))
}

/// Интерфейс, через который уходит трафик по умолчанию. Проверяется, что он
/// действительно существует, иначе правило MASQUERADE получит пустое имя.
pub fn wan_interface() -> Result<String> {
    let candidates = [
        vec!["route", "get", "1.1.1.1"],
        vec!["-o", "-4", "route", "show", "default"],
    ];

    for args in candidates {
        let output = Cmd::new("ip").args(&args).capture()?;
        if !output.ok() {
            continue;
        }
        if let Some(name) = parse_dev(output.trimmed()) {
            if interface_exists(&name) {
                return Ok(name);
            }
        }
    }
    bail!("не удалось определить внешний сетевой интерфейс (нет маршрута по умолчанию)")
}

fn parse_dev(text: &str) -> Option<String> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    fields
        .iter()
        .position(|field| *field == "dev")
        .and_then(|index| fields.get(index + 1))
        .map(|name| name.to_string())
}

pub fn interface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn flag(&self) -> &'static str {
        match self {
            Transport::Tcp => "-t",
            Transport::Udp => "-u",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port {
    pub transport: Transport,
    pub number: u16,
}

impl Port {
    pub const fn tcp(number: u16) -> Self {
        Self { transport: Transport::Tcp, number }
    }

    pub const fn udp(number: u16) -> Self {
        Self { transport: Transport::Udp, number }
    }
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.transport.label(), self.number)
    }
}

/// Имя процесса, уже слушающего порт. Пустой результат — порт свободен.
pub fn port_listener(port: Port) -> Option<String> {
    let output = Cmd::new("ss")
        .arg("-lnp")
        .arg(port.transport.flag())
        .timeout(20)
        .capture()
        .ok()?;
    if !output.ok() {
        return None;
    }
    let needle = format!(":{}", port.number);
    for line in output.stdout.lines().skip(1) {
        // Позиция колонки локального адреса у ss различается между версиями и
        // семействами сокетов, поэтому ищется поле, оканчивающееся на нужный порт,
        // а колонка Peer (`0.0.0.0:*`) отсеивается несовпадением.
        let listening = line
            .split_whitespace()
            .any(|field| field.ends_with(&needle) && field.contains(':'));
        if !listening {
            continue;
        }
        let process = line
            .split("users:((\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("неизвестный процесс");
        return Some(process.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS_UDP: &str = "\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
UNCONN 0      0            0.0.0.0:4500       0.0.0.0:*     users:((\"charon\",pid=6349,fd=13))
UNCONN 0      0            0.0.0.0:500        0.0.0.0:*     users:((\"charon\",pid=6349,fd=12))
UNCONN 0      0            0.0.0.0:1701       0.0.0.0:*     users:((\"xl2tpd\",pid=6317,fd=3))
UNCONN 0      0  31.59.37.185%eth0:68         0.0.0.0:*     users:((\"systemd-network\",pid=500,fd=18))
";

    fn find(text: &str, port: u16) -> Option<String> {
        let needle = format!(":{port}");
        text.lines().skip(1).find_map(|line| {
            line.split_whitespace()
                .any(|field| field.ends_with(&needle) && field.contains(':'))
                .then(|| {
                    line.split("users:((\"")
                        .nth(1)
                        .and_then(|rest| rest.split('"').next())
                        .unwrap_or("неизвестный процесс")
                        .to_string()
                })
        })
    }

    #[test]
    fn listener_is_found_regardless_of_column_position() {
        assert_eq!(find(SS_UDP, 4500).as_deref(), Some("charon"));
        assert_eq!(find(SS_UDP, 1701).as_deref(), Some("xl2tpd"));
        assert_eq!(find(SS_UDP, 68).as_deref(), Some("systemd-network"));
        assert_eq!(find(SS_UDP, 1194), None);
    }

    #[test]
    fn peer_column_wildcard_is_not_matched() {
        assert_eq!(find(SS_UDP, 500).as_deref(), Some("charon"));
        assert!(find(SS_UDP, 1723).is_none());
    }

    #[test]
    fn distribution_is_read_without_lsb_release() {
        // ID может быть в кавычках и в любом регистре.
        let parse = |text: &str| -> Option<String> {
            text.lines()
                .find_map(|line| line.strip_prefix("ID="))
                .map(|value| value.trim().trim_matches('"').to_lowercase())
        };
        assert_eq!(parse("NAME=\"Ubuntu\"\nID=ubuntu\n").as_deref(), Some("ubuntu"));
        assert_eq!(parse("ID=\"Ubuntu\"\n").as_deref(), Some("ubuntu"));
        assert_eq!(parse("ID=debian\n").as_deref(), Some("debian"));
        assert_eq!(parse("NAME=x\n"), None);
    }

    #[test]
    fn private_ranges_are_rejected_as_public() {
        assert!(is_public(&"31.59.37.185".parse().unwrap()));
        assert!(!is_public(&"10.0.0.1".parse().unwrap()));
        assert!(!is_public(&"192.168.1.1".parse().unwrap()));
        assert!(!is_public(&"100.64.0.1".parse().unwrap()));
        assert!(!is_public(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn wan_device_is_extracted_from_ip_route() {
        assert_eq!(
            parse_dev("1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0").as_deref(),
            Some("eth0")
        );
        assert_eq!(parse_dev("default via 10.0.0.1").as_deref(), None);
    }
}



/// Определение дистрибутива по /etc/os-release: он есть на любой systemd-системе,
/// тогда как `lsb_release` — отдельный пакет, отсутствующий в минимальных образах.
pub fn distribution_id() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("ID="))
        .map(|value| value.trim().trim_matches('"').to_lowercase())
}

/// Кодовое имя выпуска (jammy, noble) — нужно для строк apt-репозиториев.
pub fn codename() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("VERSION_CODENAME="))
        .map(|value| value.trim().trim_matches('"').to_string())
}

pub fn require_ubuntu() -> Result<()> {
    match distribution_id() {
        Some(id) if id == "ubuntu" => Ok(()),
        Some(id) => bail!("поддерживается только Ubuntu (обнаружено: {id})"),
        None => bail!("не удалось определить дистрибутив: нет /etc/os-release"),
    }
}
