#!/bin/bash

configure_sysctl() {
    log "Настройка kernel параметров..."

    cat > /etc/sysctl.d/99-atlastunnel.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.ipv4.tcp_fastopen=3

net.ipv4.tcp_mtu_probing=1
net.ipv4.ip_no_pmtu_disc=0

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
net.ipv4.tcp_low_latency=1
net.ipv4.tcp_slow_start_after_idle=0

net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries=3

net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192

net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF

    sysctl -p /etc/sysctl.d/99-atlastunnel.conf >/dev/null 2>&1 || warn "Некоторые sysctl настройки не применились"
    ok "Kernel tuning применен (BBR, TCP Fast Open, увеличенные буферы)"
}

detect_wan_interface() {
    ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}'
}

install_base_packages() {
    log "Установка базовых пакетов..."
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq >/dev/null 2>&1
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections

    apt-get install -y iptables-persistent curl wget iproute2 >/dev/null 2>&1
    ok "Базовые пакеты установлены"
}

setup_iptables_for_protocol() {
    local protocol="$1"
    local subnet="$2"
    local wan_iface="$3"

    iptables -t nat -C POSTROUTING -s "$subnet" -o "$wan_iface" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$subnet" -o "$wan_iface" -j MASQUERADE

    iptables -C FORWARD -s "$subnet" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s "$subnet" -j ACCEPT

    iptables -C FORWARD -d "$subnet" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -d "$subnet" -j ACCEPT

    case "$protocol" in
        pptp)
            iptables -C INPUT -p tcp --dport 1723 -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
            iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p gre -j ACCEPT
            iptables -C FORWARD -i ppp+ -o ppp+ -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i ppp+ -o ppp+ -j ACCEPT
            iptables -C FORWARD -i ppp+ -o "$wan_iface" -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i ppp+ -o "$wan_iface" -j ACCEPT
            iptables -C FORWARD -i "$wan_iface" -o ppp+ -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i "$wan_iface" -o ppp+ -j ACCEPT
            ;;

        l2tp|l2tp-ipsec)
            iptables -C INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p udp --dport 1701 -j ACCEPT
            if [[ "$protocol" == "l2tp-ipsec" ]]; then
                iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || \
                    iptables -A INPUT -p udp --dport 500 -j ACCEPT
                iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || \
                    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
                iptables -C INPUT -p esp -j ACCEPT 2>/dev/null || \
                    iptables -A INPUT -p esp -j ACCEPT
            fi
            iptables -C FORWARD -i ppp+ -o "$wan_iface" -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i ppp+ -o "$wan_iface" -j ACCEPT
            iptables -C FORWARD -i "$wan_iface" -o ppp+ -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i "$wan_iface" -o ppp+ -j ACCEPT
            ;;

        ikev2|ikev2-ipsec)
            iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p udp --dport 500 -j ACCEPT
            iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p udp --dport 4500 -j ACCEPT
            iptables -C INPUT -p esp -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p esp -j ACCEPT
            ;;

        sstp)
            iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p tcp --dport 443 -j ACCEPT
            iptables -C FORWARD -i ppp+ -o "$wan_iface" -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i ppp+ -o "$wan_iface" -j ACCEPT
            iptables -C FORWARD -i "$wan_iface" -o ppp+ -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i "$wan_iface" -o ppp+ -j ACCEPT
            ;;

        openvpn)
            iptables -C INPUT -p udp --dport 1194 -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p udp --dport 1194 -j ACCEPT
            iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i tun+ -j ACCEPT
            iptables -C FORWARD -i tun+ -o "$wan_iface" -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i tun+ -o "$wan_iface" -j ACCEPT
            iptables -C FORWARD -i "$wan_iface" -o tun+ -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i "$wan_iface" -o tun+ -j ACCEPT
            ;;
    esac
}
