use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::sys::net::Port;

pub const STATE_DIR: &str = "/etc/atlastunnel";
pub const CHAP_SECRETS: &str = "/etc/ppp/chap-secrets";
pub const IPSEC_SECRETS: &str = "/etc/ipsec.secrets";
pub const IPSEC_CONF: &str = "/etc/ipsec.conf";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Pptp,
    L2tp,
    L2tpIpsec,
    Ikev2,
    Ikev2Ipsec,
    Sstp,
    OpenVpn,
}

/// Как протокол обращается с файлом.
///
/// `Exclusive` — содержимое специфично для протокола, второй владелец затрёт первого.
/// `Shared` — файл дописывается или собирается из записей нескольких протоколов,
/// либо содержимое у владельцев идентично; совместное владение безопасно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, Copy)]
pub struct OwnedFile {
    pub path: &'static str,
    pub ownership: Ownership,
}

const fn exclusive(path: &'static str) -> OwnedFile {
    OwnedFile { path, ownership: Ownership::Exclusive }
}

const fn shared(path: &'static str) -> OwnedFile {
    OwnedFile { path, ownership: Ownership::Shared }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Все пакеты есть в репозиториях текущего выпуска.
    Available,
    /// Пакетов нет в текущем выпуске, но они есть в архивах прошлых выпусков.
    ViaLegacy {
        packages: Vec<&'static str>,
        suites: &'static [&'static str],
    },
    /// Пакетов нет ни в текущем выпуске, ни в поддерживаемых архивах.
    Unavailable(Vec<&'static str>),
}

impl Availability {
    /// Протокол можно выбрать — при необходимости с загрузкой из старого выпуска.
    pub fn is_selectable(&self) -> bool {
        !matches!(self, Availability::Unavailable(_))
    }

    pub fn needs_legacy(&self) -> bool {
        matches!(self, Availability::ViaLegacy { .. })
    }

    pub fn note(&self) -> Option<String> {
        match self {
            Availability::Available => None,
            Availability::ViaLegacy { packages, suites } => Some(format!(
                "пакет {} — из архива {}",
                packages.join(", "),
                suites.first().copied().unwrap_or("прошлого выпуска")
            )),
            Availability::Unavailable(packages) => {
                Some(format!("нет ни в одном выпуске Ubuntu: {}", packages.join(", ")))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsKind {
    Chap { service: &'static str },
    Eap,
}

impl Protocol {
    pub const ALL: [Protocol; 7] = [
        Protocol::Pptp,
        Protocol::L2tp,
        Protocol::L2tpIpsec,
        Protocol::Ikev2,
        Protocol::Ikev2Ipsec,
        Protocol::Sstp,
        Protocol::OpenVpn,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            Protocol::Pptp => "pptp",
            Protocol::L2tp => "l2tp",
            Protocol::L2tpIpsec => "l2tp-ipsec",
            Protocol::Ikev2 => "ikev2",
            Protocol::Ikev2Ipsec => "ikev2-ipsec",
            Protocol::Sstp => "sstp",
            Protocol::OpenVpn => "openvpn",
        }
    }

    pub fn parse(value: &str) -> Option<Protocol> {
        Protocol::ALL
            .into_iter()
            .find(|protocol| protocol.id() == value.trim().to_lowercase())
    }

    pub fn display(&self) -> &'static str {
        match self {
            Protocol::Pptp => "PPTP",
            Protocol::L2tp => "L2TP",
            Protocol::L2tpIpsec => "L2TP/IPsec",
            Protocol::Ikev2 => "IKEv2",
            Protocol::Ikev2Ipsec => "IKEv2/IPsec",
            Protocol::Sstp => "SSTP",
            Protocol::OpenVpn => "OpenVPN",
        }
    }

    pub fn summary(&self) -> &'static str {
        match self {
            Protocol::Pptp => "Максимальная скорость, шифрование MPPE-128",
            Protocol::L2tp => "Без шифрования, минимальные накладные расходы",
            Protocol::L2tpIpsec => "Шифрование IPsec с общим ключом PSK",
            Protocol::Ikev2 => "Null cipher, скорость вместо шифрования",
            Protocol::Ikev2Ipsec => "Шифрование IPsec с CA-сертификатом",
            Protocol::Sstp => "SSL поверх TCP 443, проходит через firewall",
            Protocol::OpenVpn => "Универсальное решение, UDP 1194",
        }
    }

    /// Юниты, определяющие работоспособность протокола. Первый — основной.
    pub fn units(&self) -> &'static [&'static str] {
        match self {
            Protocol::Pptp => &["pptpd"],
            Protocol::L2tp => &["xl2tpd"],
            Protocol::L2tpIpsec => &["xl2tpd", "strongswan-starter"],
            Protocol::Ikev2 | Protocol::Ikev2Ipsec => &["strongswan-starter"],
            Protocol::Sstp => &["sstp-server"],
            Protocol::OpenVpn => &["openvpn@server"],
        }
    }

    pub fn packages(&self) -> &'static [&'static str] {
        match self {
            Protocol::Pptp => &["pptpd"],
            Protocol::L2tp => &["xl2tpd", "ppp"],
            Protocol::L2tpIpsec => &["xl2tpd", "ppp", "strongswan"],
            Protocol::Ikev2 | Protocol::Ikev2Ipsec => &[
                "strongswan",
                "strongswan-pki",
                "libcharon-extra-plugins",
                "libcharon-extauth-plugins",
                "libstrongswan-extra-plugins",
            ],
            Protocol::Sstp => &["ppp", "python3-venv"],
            Protocol::OpenVpn => &["openvpn", "easy-rsa"],
        }
    }

    pub fn owned_files(&self) -> &'static [OwnedFile] {
        const PPTP: &[OwnedFile] = &[
            exclusive("/etc/pptpd.conf"),
            exclusive("/etc/ppp/pptpd-options"),
            shared(CHAP_SECRETS),
        ];
        // xl2tpd.conf, options.l2tpd и юнит у L2TP и L2TP/IPsec совпадают
        // побайтово, поэтому владение общее и конфликта между ними нет.
        const L2TP: &[OwnedFile] = &[
            shared("/etc/xl2tpd/xl2tpd.conf"),
            shared("/etc/ppp/options.l2tpd"),
            shared("/etc/systemd/system/xl2tpd.service"),
            shared(CHAP_SECRETS),
        ];
        const L2TP_IPSEC: &[OwnedFile] = &[
            shared("/etc/xl2tpd/xl2tpd.conf"),
            shared("/etc/ppp/options.l2tpd"),
            shared("/etc/systemd/system/xl2tpd.service"),
            shared(CHAP_SECRETS),
            exclusive(IPSEC_CONF),
            shared(IPSEC_SECRETS),
        ];
        const IKEV2: &[OwnedFile] = &[exclusive(IPSEC_CONF), shared(IPSEC_SECRETS)];
        const SSTP: &[OwnedFile] = &[
            exclusive("/etc/ppp/sstp-options"),
            exclusive("/etc/systemd/system/sstp-server.service"),
            shared(CHAP_SECRETS),
        ];
        const OPENVPN: &[OwnedFile] = &[exclusive("/etc/openvpn/server.conf")];
        match self {
            Protocol::Pptp => PPTP,
            Protocol::L2tp => L2TP,
            Protocol::L2tpIpsec => L2TP_IPSEC,
            Protocol::Ikev2 | Protocol::Ikev2Ipsec => IKEV2,
            Protocol::Sstp => SSTP,
            Protocol::OpenVpn => OPENVPN,
        }
    }

    pub fn ports(&self) -> &'static [Port] {
        const PPTP: &[Port] = &[Port::tcp(1723)];
        const L2TP: &[Port] = &[Port::udp(1701)];
        const L2TP_IPSEC: &[Port] = &[Port::udp(1701), Port::udp(500), Port::udp(4500)];
        const IKEV2: &[Port] = &[Port::udp(500), Port::udp(4500)];
        const SSTP: &[Port] = &[Port::tcp(443)];
        const OPENVPN: &[Port] = &[Port::udp(1194)];
        match self {
            Protocol::Pptp => PPTP,
            Protocol::L2tp => L2TP,
            Protocol::L2tpIpsec => L2TP_IPSEC,
            Protocol::Ikev2 | Protocol::Ikev2Ipsec => IKEV2,
            Protocol::Sstp => SSTP,
            Protocol::OpenVpn => OPENVPN,
        }
    }

    pub fn subnet(&self) -> &'static str {
        match self {
            Protocol::Pptp => "10.20.30.0/24",
            Protocol::L2tp | Protocol::L2tpIpsec => "10.30.40.0/24",
            Protocol::Ikev2 | Protocol::Ikev2Ipsec => "10.40.50.0/24",
            Protocol::Sstp => "10.50.60.0/24",
            Protocol::OpenVpn => "10.60.70.0/24",
        }
    }

    pub fn secrets_kind(&self) -> Option<SecretsKind> {
        match self {
            Protocol::Pptp => Some(SecretsKind::Chap { service: "pptpd" }),
            Protocol::L2tp | Protocol::L2tpIpsec => Some(SecretsKind::Chap { service: "*" }),
            Protocol::Sstp => Some(SecretsKind::Chap { service: "sstp" }),
            Protocol::Ikev2 | Protocol::Ikev2Ipsec => Some(SecretsKind::Eap),
            Protocol::OpenVpn => None,
        }
    }


    /// Архивы прошлых выпусков, откуда берутся пакеты, удалённые из текущего.
    /// Пустой список означает, что подмены нет и протокол просто недоступен.
    pub fn legacy_suites(&self) -> &'static [&'static str] {
        // Только jammy: pptpd из focal требует ppp < 2.4.7, которого нет ни в
        // одном актуальном выпуске, поэтому focal здесь бесполезен. Версия из
        // jammy зависит от ppp >= 2.4.9 и совместима с 24.04.
        const JAMMY: &[&str] = &["jammy"];
        match self {
            // pptpd удалён начиная с Ubuntu 24.04, последний выпуск с ним — 22.04.
            Protocol::Pptp => JAMMY,
            // sstp-server не публиковался ни в одном выпуске Ubuntu.
            _ => &[],
        }
    }

    /// Доступен ли протокол на этом выпуске и какой ценой.
    pub fn availability(&self) -> Availability {
        let missing: Vec<&'static str> = self
            .packages()
            .iter()
            .copied()
            .filter(|package| {
                !crate::sys::pkg::is_installed(package) && !crate::sys::pkg::has_candidate(package)
            })
            .collect();
        if missing.is_empty() {
            return Availability::Available;
        }
        let suites = self.legacy_suites();
        if suites.is_empty() {
            Availability::Unavailable(missing)
        } else {
            Availability::ViaLegacy { packages: missing, suites }
        }
    }

    pub fn uses_ipsec(&self) -> bool {
        matches!(self, Protocol::L2tpIpsec | Protocol::Ikev2 | Protocol::Ikev2Ipsec)
    }

    pub fn needs_ca_certificate(&self) -> bool {
        matches!(self, Protocol::Ikev2 | Protocol::Ikev2Ipsec)
    }

    pub fn marker(&self) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{}.conf", self.id()))
    }

    pub fn is_installed(&self) -> bool {
        self.marker().exists()
    }

    /// Конфликт выводится из модели владения, а не задаётся списком: два протокола
    /// несовместимы, если претендуют на один и тот же файл в монопольном режиме.
    pub fn conflicts_with(&self, other: Protocol) -> Option<&'static str> {
        if *self == other {
            return None;
        }
        for mine in self.owned_files() {
            if mine.ownership != Ownership::Exclusive {
                continue;
            }
            for theirs in other.owned_files() {
                if theirs.ownership == Ownership::Exclusive && theirs.path == mine.path {
                    return Some(mine.path);
                }
            }
        }
        None
    }

}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display())
    }
}

/// Наибольший набор протоколов, устанавливаемых вместе без конфликтов.
/// Порядок предпочтения — как в `Protocol::ALL`.
pub fn compatible_set() -> Vec<Protocol> {
    let mut chosen: Vec<Protocol> = Vec::new();
    for candidate in Protocol::ALL {
        if chosen
            .iter()
            .all(|taken| taken.conflicts_with(candidate).is_none())
        {
            chosen.push(candidate);
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipsec_protocols_are_mutually_exclusive() {
        let ipsec = [Protocol::L2tpIpsec, Protocol::Ikev2, Protocol::Ikev2Ipsec];
        for left in ipsec {
            for right in ipsec {
                if left == right {
                    continue;
                }
                assert_eq!(
                    left.conflicts_with(right),
                    Some(IPSEC_CONF),
                    "{left} и {right} обязаны конфликтовать на {IPSEC_CONF}"
                );
            }
        }
    }

    #[test]
    fn plain_l2tp_does_not_conflict_with_l2tp_ipsec() {
        assert_eq!(Protocol::L2tp.conflicts_with(Protocol::L2tpIpsec), None);
    }

    #[test]
    fn chap_users_do_not_create_conflicts() {
        assert_eq!(Protocol::Pptp.conflicts_with(Protocol::Sstp), None);
        assert_eq!(Protocol::Pptp.conflicts_with(Protocol::L2tp), None);
    }

    #[test]
    fn compatible_set_has_no_internal_conflicts() {
        let set = compatible_set();
        for left in &set {
            for right in &set {
                assert_eq!(left.conflicts_with(*right), None);
            }
        }
        assert!(set.contains(&Protocol::Pptp));
        assert!(set.contains(&Protocol::L2tpIpsec));
        assert!(!set.contains(&Protocol::Ikev2Ipsec));
    }

    #[test]
    fn only_pptp_has_a_legacy_fallback() {
        assert_eq!(Protocol::Pptp.legacy_suites(), &["jammy"]);
        for protocol in Protocol::ALL {
            if protocol != Protocol::Pptp {
                assert!(
                    protocol.legacy_suites().is_empty(),
                    "{protocol} не должен тянуть пакеты из архивов"
                );
            }
        }
    }

    #[test]
    fn identifiers_round_trip() {
        for protocol in Protocol::ALL {
            assert_eq!(Protocol::parse(protocol.id()), Some(protocol));
        }
        assert_eq!(Protocol::parse("нет такого"), None);
    }
}
