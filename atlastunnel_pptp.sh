#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Запустите от root"
  exit 1
fi

VPN_USER="${VPN_USER:-vpnuser}"
VPN_PASSWORD="${VPN_PASSWORD:-vpnpass}"
VPN_LOCAL_IP="192.168.18.1"
VPN_REMOTE_IP_RANGE="192.168.18.10-192.168.18.100"
VPN_SUBNET="192.168.18.0/24"
VPN_INTERFACE="$(ip route | grep default | awk '{print $5}' | head -n1)"

echo "Настраиваем L2TP без IPsec"
echo "VPN_USER=$VPN_USER, VPN_PASSWORD=$VPN_PASSWORD, Интерфейс=$VPN_INTERFACE"

# Установка нужных пакетов
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y pptpd ppp iptables-persistent

# Настройка pptpd
cat > /etc/pptpd/pptpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $VPN_REMOTE_IP_RANGE
local ip = $VPN_LOCAL_IP
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.pptpd
length bit = yes
EOF

# Настройка PPP
cat > /etc/ppp/options.pptpd <<EOF
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 1.1.1.1
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOF

# Учетка
cat > /etc/ppp/chap-secrets <<EOF
EOF

# Настройка sysctl (без дублирования)
declare -A sysctl_settings=(
  ["net.ipv4.ip_forward"]=1
  ["net.ipv4.conf.all.accept_redirects"]=0
  ["net.ipv4.conf.all.send_redirects"]=0
  ["net.ipv4.conf.default.accept_redirects"]=0
  ["net.ipv4.conf.default.send_redirects"]=0
)

for key in "${!sysctl_settings[@]}"; do
  value="${sysctl_settings[$key]}"
  if grep -q "^${key}=" /etc/sysctl.conf; then
    sed -i "s|^${key}=.*|${key}=${value}|" /etc/sysctl.conf
  elif grep -q "^#\?${key}[[:space:]]\?=" /etc/sysctl.conf; then
    sed -i "s|^#\?${key}[[:space:]]\?=.*|${key} = ${value}|" /etc/sysctl.conf
  else
    echo "${key} = ${value}" >> /etc/sysctl.conf
  fi
done

sysctl -p

# Настройка iptables (без дублирования)
iptables -C FORWARD -s $VPN_SUBNET -j ACCEPT 2>/dev/null || iptables -A FORWARD -s $VPN_SUBNET -j ACCEPT
iptables -C FORWARD -d $VPN_SUBNET -j ACCEPT 2>/dev/null || iptables -A FORWARD -d $VPN_SUBNET -j ACCEPT
iptables -C INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 1701 -j ACCEPT
iptables -t nat -C POSTROUTING -s $VPN_SUBNET -o $VPN_INTERFACE -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o $VPN_INTERFACE -j MASQUERADE

iptables-save > /etc/iptables/rules.v4

# Удаляем strongSwan если установлен
apt-get remove -y strongswan* || true

# Включаем и запускаем L2TP
systemctl enable pptpd
systemctl restart pptpd

echo
echo "✅ L2TP сервер без IPsec запущен."
echo "ℹ️ Подключение:"
echo "IP сервера: $(curl -s ifconfig.me)"
echo "Имя пользователя: $VPN_USER"
echo "Пароль: $VPN_PASSWORD"
echo "⚠️ Без IPsec (незашифрованный L2TP)."