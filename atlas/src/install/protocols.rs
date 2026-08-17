use anyhow::{bail, Result};
use std::net::Ipv4Addr;
use std::path::Path;

use super::certs;
use super::tx::{Progress, Transaction};
use crate::model::protocol::{Protocol, IPSEC_CONF, IPSEC_SECRETS};
use crate::model::secrets::Store;
use crate::sys::{cmd::Cmd, systemd};

pub const DNS_PRIMARY: &str = "8.8.8.8";
pub const DNS_SECONDARY: &str = "1.1.1.1";

pub struct Context<'a> {
    pub public_ip: Ipv4Addr,
    pub certificate: &'a certs::Certificate,
    pub user: &'a str,
    pub password: &'a str,
    pub psk: &'a str,
}

pub fn configure(
    protocol: Protocol,
    tx: &mut Transaction,
    progress: &mut dyn Progress,
    ctx: &Context<'_>,
) -> Result<()> {
    match protocol {
        Protocol::Pptp => pptp(tx, ctx),
        Protocol::L2tp => l2tp(tx, ctx),
        Protocol::L2tpIpsec => l2tp_ipsec(tx, ctx),
        Protocol::Ikev2 | Protocol::Ikev2Ipsec => ikev2(protocol, tx, progress, ctx),
        Protocol::Sstp => sstp(tx, progress, ctx),
        Protocol::OpenVpn => openvpn(tx, progress, ctx),
    }
}

fn pptp(tx: &mut Transaction, ctx: &Context<'_>) -> Result<()> {
    tx.write(
        Path::new("/etc/pptpd.conf"),
        "option /etc/ppp/pptpd-options\nlogwtmp\nlocalip 10.20.30.1\nremoteip 10.20.30.40-200\n",
        0o644,
    )?;

    // MPPE включён по-настоящему: в прежней версии рядом с `+mppe-128` стояли
    // `nomppe` и `noccp`, из-за чего PPTP работал вообще без шифрования.
    tx.write(
        Path::new("/etc/ppp/pptpd-options"),
        &format!(
            "name pptpd\n\
             refuse-pap\n\
             refuse-chap\n\
             refuse-mschap\n\
             require-mschap-v2\n\
             require-mppe-128\n\
             ms-dns {DNS_PRIMARY}\n\
             ms-dns {DNS_SECONDARY}\n\
             nobsdcomp\n\
             nodeflate\n\
             noipx\n\
             lock\n\
             auth\n\
             mtu 1400\n\
             mru 1400\n\
             lcp-echo-interval 30\n\
             lcp-echo-failure 4\n"
        ),
        0o644,
    )?;

    tx.guard(Path::new(crate::model::protocol::CHAP_SECRETS))?;
    Store::upsert(Protocol::Pptp, ctx.user, ctx.password)?;
    Ok(())
}

const XL2TPD_CONF: &str = "\
[global]
port = 1701

[lns default]
ip range = 10.30.40.10-100
local ip = 10.30.40.1
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.l2tpd
length bit = yes
";

const XL2TPD_UNIT: &str = "\
[Unit]
Description=Layer 2 Tunnelling Protocol Daemon (L2TP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /var/run/xl2tpd
ExecStartPre=/bin/touch /var/run/xl2tpd/l2tp-control
ExecStart=/usr/sbin/xl2tpd -D
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
";

fn l2tpd_options() -> String {
    format!(
        "require-mschap-v2\n\
         refuse-pap\n\
         refuse-chap\n\
         refuse-mschap\n\
         nomppe\n\
         noccp\n\
         ms-dns {DNS_PRIMARY}\n\
         ms-dns {DNS_SECONDARY}\n\
         asyncmap 0\n\
         auth\n\
         hide-password\n\
         mtu 1360\n\
         mru 1360\n\
         lcp-echo-failure 4\n\
         lcp-echo-interval 30\n"
    )
}

/// Общая для L2TP и L2TP/IPsec часть: файлы совпадают побайтово, поэтому
/// протоколы делят их без конфликта.
fn l2tp_common(tx: &mut Transaction, ctx: &Context<'_>, protocol: Protocol) -> Result<()> {
    tx.write(Path::new("/etc/xl2tpd/xl2tpd.conf"), XL2TPD_CONF, 0o644)?;
    tx.write(Path::new("/etc/ppp/options.l2tpd"), &l2tpd_options(), 0o644)?;
    tx.write(
        Path::new("/etc/systemd/system/xl2tpd.service"),
        XL2TPD_UNIT,
        0o644,
    )?;
    systemd::daemon_reload()?;
    tx.guard(Path::new(crate::model::protocol::CHAP_SECRETS))?;
    Store::upsert(protocol, ctx.user, ctx.password)?;
    Ok(())
}

fn l2tp(tx: &mut Transaction, ctx: &Context<'_>) -> Result<()> {
    l2tp_common(tx, ctx, Protocol::L2tp)
}

fn l2tp_ipsec(tx: &mut Transaction, ctx: &Context<'_>) -> Result<()> {
    l2tp_common(tx, ctx, Protocol::L2tpIpsec)?;

    tx.write(
        Path::new(IPSEC_CONF),
        "config setup\n\
         \x20   charondebug=\"ike 1, knl 1, cfg 0\"\n\
         \x20   uniqueids=no\n\
         \n\
         conn L2TP-PSK\n\
         \x20   authby=secret\n\
         \x20   pfs=no\n\
         \x20   auto=add\n\
         \x20   keyexchange=ikev1\n\
         \x20   type=transport\n\
         \x20   left=%any\n\
         \x20   leftprotoport=17/1701\n\
         \x20   right=%any\n\
         \x20   rightprotoport=17/%any\n\
         \x20   ike=aes256-sha256-modp2048,aes128-sha1-modp1024!\n\
         \x20   esp=aes256-sha256,aes128-sha1!\n",
        0o644,
    )?;

    tx.guard(Path::new(IPSEC_SECRETS))?;
    let mut secrets = crate::model::secrets::IpsecSecrets::load(Path::new(IPSEC_SECRETS))?;
    secrets.psk = Some(ctx.psk.to_string());
    crate::fsx::write_atomic(Path::new(IPSEC_SECRETS), &secrets.render(), 0o600)?;
    Ok(())
}

fn ikev2(
    protocol: Protocol,
    tx: &mut Transaction,
    progress: &mut dyn Progress,
    ctx: &Context<'_>,
) -> Result<()> {
    certs::issue_ipsec(tx, progress, ctx.public_ip)?;

    // Единственное различие между IKEv2 и IKEv2/IPsec — набор шифров ESP.
    let esp = if protocol == Protocol::Ikev2 {
        "null-sha256,null-sha1!"
    } else {
        "aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1!"
    };

    tx.write(
        Path::new(IPSEC_CONF),
        &format!(
            "config setup\n\
             \x20   charondebug=\"ike 1, knl 1, cfg 0\"\n\
             \x20   uniqueids=no\n\
             \n\
             conn ikev2-vpn\n\
             \x20   auto=add\n\
             \x20   compress=no\n\
             \x20   type=tunnel\n\
             \x20   keyexchange=ikev2\n\
             \x20   fragmentation=yes\n\
             \x20   forceencaps=yes\n\
             \x20   dpdaction=clear\n\
             \x20   dpddelay=300s\n\
             \x20   rekey=no\n\
             \x20   ike=aes256-sha256-modp2048,aes128-sha256-modp2048!\n\
             \x20   esp={esp}\n\
             \x20   left=%any\n\
             \x20   leftid={ip}\n\
             \x20   leftcert=server-cert.pem\n\
             \x20   leftsendcert=always\n\
             \x20   leftsubnet=0.0.0.0/0\n\
             \x20   leftauth=pubkey\n\
             \x20   right=%any\n\
             \x20   rightid=%any\n\
             \x20   rightauth=eap-mschapv2\n\
             \x20   rightsourceip={subnet}\n\
             \x20   rightdns={dns1},{dns2}\n\
             \x20   rightsendcert=never\n\
             \x20   eap_identity=%identity\n",
            esp = esp,
            ip = ctx.public_ip,
            subnet = protocol.subnet(),
            dns1 = DNS_PRIMARY,
            dns2 = DNS_SECONDARY,
        ),
        0o644,
    )?;

    tx.guard(Path::new(IPSEC_SECRETS))?;
    let mut secrets = crate::model::secrets::IpsecSecrets::load(Path::new(IPSEC_SECRETS))?;
    secrets.rsa_key = Some("server-key.pem".into());
    secrets.upsert_eap(ctx.user, ctx.password);
    crate::fsx::write_atomic(Path::new(IPSEC_SECRETS), &secrets.render(), 0o600)?;
    Ok(())
}

fn sstp(
    tx: &mut Transaction,
    progress: &mut dyn Progress,
    ctx: &Context<'_>,
) -> Result<()> {
    let paths = match ctx.certificate {
        certs::Certificate::SelfSigned => {
            progress.info("самоподписанный сертификат: на клиенте потребуется импорт");
            certs::issue_sstp(tx, ctx.public_ip)?
        }
        certs::Certificate::LetsEncrypt { domain, email } => {
            certs::issue_letsencrypt(tx, progress, domain, email.as_deref(), ctx.public_ip)?
        }
    };

    super::sstp::provision(
        tx,
        progress,
        "10.50.60.1",
        Protocol::Sstp.subnet(),
        "10.50.60.10-100",
        &paths,
    )?;

    // sstpd запускает pppd как `pppd notty file <config> 115200 <address>` и не
    // передаёт `name`, поэтому pppd взял бы имя хоста и не нашёл бы запись в
    // chap-secrets, где колонка службы — «sstp». Имя задаётся здесь.
    tx.write(
        Path::new("/etc/ppp/sstp-options"),
        &format!(
            "name sstp\n\
             require-mschap-v2\n\
             refuse-pap\n\
             refuse-chap\n\
             refuse-mschap\n\
             nodefaultroute\n\
             usepeerdns\n\
             proxyarp\n\
             nobsdcomp\n\
             novj\n\
             novjccomp\n\
             mtu 1400\n\
             mru 1400\n\
             lcp-echo-failure 4\n\
             lcp-echo-interval 30\n\
             ms-dns {DNS_PRIMARY}\n\
             ms-dns {DNS_SECONDARY}\n"
        ),
        0o644,
    )?;

    // Прежняя версия писала chap-secrets через `>`, стирая клиентов PPTP и L2TP.
    tx.guard(Path::new(crate::model::protocol::CHAP_SECRETS))?;
    Store::upsert(Protocol::Sstp, ctx.user, ctx.password)?;
    Ok(())
}

const EASY_RSA_DIR: &str = "/etc/openvpn/easy-rsa";

fn easyrsa(args: &[&str]) -> Cmd {
    Cmd::new(format!("{EASY_RSA_DIR}/easyrsa"))
        .env("EASYRSA_BATCH", "1")
        .env("EASYRSA_PKI", format!("{EASY_RSA_DIR}/pki"))
        .env("EASYRSA_REQ_CN", "AtlasTunnel CA")
        .env("EASYRSA_CA_EXPIRE", "3650")
        .env("EASYRSA_CERT_EXPIRE", "1825")
        .env("EASYRSA_ALGO", "rsa")
        .env("EASYRSA_KEY_SIZE", "2048")
        .args(args)
}

fn openvpn(tx: &mut Transaction, progress: &mut dyn Progress, ctx: &Context<'_>) -> Result<()> {
    if !Path::new(&format!("{EASY_RSA_DIR}/easyrsa")).exists() {
        let output = Cmd::new("make-cadir").arg(EASY_RSA_DIR).capture()?;
        if !output.ok() {
            bail!("подготовка easy-rsa: {}", output.failure_reason());
        }
    }

    if !Path::new(&format!("{EASY_RSA_DIR}/pki/ca.crt")).exists() {
        progress.info("Инициализация PKI");
        easyrsa(&["init-pki"]).run()?;
        easyrsa(&["build-ca", "nopass"]).run()?;
        progress.info("Выпуск серверного сертификата");
        easyrsa(&["build-server-full", "server", "nopass"]).run()?;
        progress.info("Генерация параметров Диффи-Хеллмана, это занимает минуты");
        easyrsa(&["gen-dh"]).run()?;
        Cmd::new("openvpn")
            .args(["--genkey", "secret", &format!("{EASY_RSA_DIR}/pki/ta.key")])
            .run()?;
    }

    // Клиентский сертификат и готовый .ovpn — прежняя версия их не создавала,
    // из-за чего установленный OpenVPN был неработоспособен.
    progress.info(&format!("Выпуск клиентского профиля {}", ctx.user));
    if !Path::new(&format!("{EASY_RSA_DIR}/pki/issued/{}.crt", ctx.user)).exists() {
        easyrsa(&["build-client-full", ctx.user, "nopass"]).run()?;
    }

    std::fs::create_dir_all("/etc/openvpn")?;
    for (source, target, mode) in [
        ("pki/ca.crt", "/etc/openvpn/ca.crt", 0o644),
        ("pki/issued/server.crt", "/etc/openvpn/server.crt", 0o644),
        ("pki/private/server.key", "/etc/openvpn/server.key", 0o600),
        ("pki/dh.pem", "/etc/openvpn/dh.pem", 0o644),
        ("pki/ta.key", "/etc/openvpn/ta.key", 0o600),
    ] {
        let contents = std::fs::read_to_string(format!("{EASY_RSA_DIR}/{source}"))
            .map_err(|err| anyhow::anyhow!("чтение {source}: {err}"))?;
        tx.write(Path::new(target), &contents, mode)?;
    }

    tx.write(
        Path::new("/etc/openvpn/server.conf"),
        &format!(
            "port 1194\n\
             proto udp\n\
             dev tun\n\
             ca ca.crt\n\
             cert server.crt\n\
             key server.key\n\
             dh dh.pem\n\
             tls-auth ta.key 0\n\
             server 10.60.70.0 255.255.255.0\n\
             ifconfig-pool-persist ipp.txt\n\
             push \"redirect-gateway def1 bypass-dhcp\"\n\
             push \"dhcp-option DNS {DNS_PRIMARY}\"\n\
             push \"dhcp-option DNS {DNS_SECONDARY}\"\n\
             keepalive 10 120\n\
             data-ciphers AES-256-GCM:AES-128-GCM\n\
             auth SHA256\n\
             user nobody\n\
             group nogroup\n\
             persist-key\n\
             persist-tun\n\
             status /var/log/openvpn-status.log\n\
             verb 3\n\
             explicit-exit-notify 1\n"
        ),
        0o644,
    )?;

    write_ovpn_profile(tx, ctx)?;
    Ok(())
}

fn write_ovpn_profile(tx: &mut Transaction, ctx: &Context<'_>) -> Result<()> {
    let read = |relative: &str| -> Result<String> {
        std::fs::read_to_string(format!("{EASY_RSA_DIR}/{relative}"))
            .map_err(|err| anyhow::anyhow!("чтение {relative}: {err}"))
    };

    let profile = format!(
        "client\n\
         dev tun\n\
         proto udp\n\
         remote {ip} 1194\n\
         resolv-retry infinite\n\
         nobind\n\
         persist-key\n\
         persist-tun\n\
         remote-cert-tls server\n\
         data-ciphers AES-256-GCM:AES-128-GCM\n\
         auth SHA256\n\
         key-direction 1\n\
         verb 3\n\
         <ca>\n{ca}</ca>\n\
         <cert>\n{cert}</cert>\n\
         <key>\n{key}</key>\n\
         <tls-auth>\n{ta}</tls-auth>\n",
        ip = ctx.public_ip,
        ca = read("pki/ca.crt")?,
        cert = strip_certificate(&read(&format!("pki/issued/{}.crt", ctx.user))?),
        key = read(&format!("pki/private/{}.key", ctx.user))?,
        ta = read("pki/ta.key")?,
    );

    let target = format!("/etc/atlastunnel/clients/{}.ovpn", ctx.user);
    std::fs::create_dir_all("/etc/atlastunnel/clients")?;
    tx.write(Path::new(&target), &profile, 0o600)?;
    Ok(())
}

/// easy-rsa кладёт перед PEM текстовое описание сертификата — в .ovpn оно лишнее.
fn strip_certificate(text: &str) -> String {
    match text.find("-----BEGIN CERTIFICATE-----") {
        Some(start) => text[start..].to_string(),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_preamble_is_removed() {
        let raw = "Certificate:\n  Data:\n-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n";
        assert!(strip_certificate(raw).starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn l2tp_options_do_not_promise_encryption() {
        let options = l2tpd_options();
        assert!(options.contains("nomppe"));
        assert!(options.contains("require-mschap-v2"));
    }
}
