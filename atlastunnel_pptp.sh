#!/bin/sh

set -e

VPN_USER="vpnuser"
VPN_PASS="vpnpass"
VPN_LOCAL_IP="10.20.30.1"
VPN_REMOTE_IP_RANGE="10.20.30.40-200"

echo "[*] Установка необходимых пакетов..."
apt-get update
apt-get install -y pptpd iptables-persistent

echo "[*] Настройка /etc/pptpd.conf..."
PPTPD_CONF="/etc/pptpd.conf"
if [ ! -f "$PPTPD_CONF" ]; then
    touch "$PPTPD_CONF"
fi

cat > "$PPTPD_CONF" <<EOF
option /etc/ppp/pptpd-options
logwtmp
localip $VPN_LOCAL_IP
remoteip $VPN_REMOTE_IP_RANGE
EOF

echo "[*] Настройка /etc/ppp/pptpd-options..."
PPTPD_OPTIONS="/etc/ppp/pptpd-options"
cat > "$PPTPD_OPTIONS" <<EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
nomppe
noccp
ms-dns 8.8.8.8
ms-dns 1.1.1.1
nobsdcomp
nodeflate
noipx
debug
lock
auth
mtu 1400
mru 1400
lcp-echo-interval 30
lcp-echo-failure 4
EOF

echo "[*] Настройка пользователя..."
CHAP_SECRETS="/etc/ppp/chap-secrets"
if ! grep -q "$VPN_USER" "$CHAP_SECRETS"; then
    echo "$VPN_USER pptpd $VPN_PASS *" >> "$CHAP_SECRETS"
fi

echo "[*] Включение IP маршрутизации..."
SYSCTL_CONF="/etc/sysctl.conf"
if ! grep -q "^net.ipv4.ip_forward=1" "$SYSCTL_CONF"; then
    echo "net.ipv4.ip_forward=1" >> "$SYSCTL_CONF"
fi
sysctl -w net.ipv4.ip_forward=1

echo "[*] Настройка iptables..."
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

iptables -C FORWARD -i ppp+ -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o ppp+ -j ACCEPT

iptables -C FORWARD -i ppp+ -o eth0 -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o eth0 -j ACCEPT

iptables -C FORWARD -i eth0 -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i eth0 -o ppp+ -j ACCEPT

echo "[*] Сохранение iptables и включение автозапуска..."
netfilter-persistent save
systemctl enable netfilter-persistent
systemctl restart netfilter-persistent

echo "[*] Включение и перезапуск pptpd..."
systemctl enable pptpd
systemctl restart pptpd

echo "[✓] Установка и настройка завершены. Используйте:"
echo "    логин: $VPN_USER"
echo "    пароль: $VPN_PASS"