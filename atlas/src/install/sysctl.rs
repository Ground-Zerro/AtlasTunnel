use anyhow::Result;
use std::path::Path;

use super::tx::{Progress, Transaction};
use crate::sys::cmd::Cmd;

const PATH: &str = "/etc/sysctl.d/99-atlastunnel.conf";

/// Настройки ядра. IPv6 намеренно не отключается: прежняя версия глушила его
/// глобально, ломая всё остальное на сервере ради протоколов, которые
/// работают только по IPv4.
const TUNING: &str = "\
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1

net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.rmem_default=16777216
net.core.wmem_default=16777216
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192

net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_slow_start_after_idle=0

net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192
";

pub fn apply(tx: &mut Transaction, progress: &mut dyn Progress) -> Result<()> {
    tx.write(Path::new(PATH), TUNING, 0o644)?;

    let output = Cmd::new("sysctl").arg("-p").arg(PATH).capture()?;
    if !output.ok() {
        progress.warn(&format!(
            "часть параметров ядра не применилась: {}",
            output.failure_reason()
        ));
    }

    if !bbr_active() {
        progress.warn("BBR недоступен в этом ядре — используется текущий алгоритм TCP");
    } else {
        progress.ok("BBR, TCP Fast Open и увеличенные буферы включены");
    }

    if !forwarding_enabled() {
        anyhow::bail!("не удалось включить net.ipv4.ip_forward — маршрутизация VPN работать не будет");
    }
    Ok(())
}

fn read_flag(key: &str) -> Option<String> {
    Cmd::new("sysctl").arg("-n").arg(key).stdout().ok()
}

fn bbr_active() -> bool {
    read_flag("net.ipv4.tcp_congestion_control").as_deref() == Some("bbr")
}

fn forwarding_enabled() -> bool {
    read_flag("net.ipv4.ip_forward").as_deref() == Some("1")
}
