#!/bin/bash

set -e

# Проверка запуска от root
if [ "$EUID" -ne 0 ]; then
  echo "Пожалуйста, запустите скрипт от root."
  exit 1
fi

# Параметры
VPN_IPSEC_PSK="${VPN_IPSEC_PSK:-vpnsharedkey}"
VPN_USER="${VPN_USER:-vpnuser}"
VPN_PASSWORD="${VPN_PASSWORD:-vpnpassword}"
VPN_SUBNET="192.168.18.0/24"
VPN_LOCAL_IP="192.168.18.1"
VPN_REMOTE_IP_RANGE="192.168.18.10-192.168.18.100"
VPN_INTERFACE="$(ip route | grep default | awk '{print $5}' | head -n1)"

echo "Используемые параметры:"
echo "  VPN_USER=$VPN_USER"
echo "  VPN_PASSWORD=$VPN_PASSWORD"
echo "  VPN_IPSEC_PSK=$VPN_IPSEC_PSK"
echo "  Интерфейс выхода в интернет: $VPN_INTERFACE"
echo

# Отключаем UFW
if command -v ufw >/dev/null 2>&1; then
  ufw disable
fi

# Установка пакетов
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  strongswan xl2tpd ppp lsof wget iptables-persistent

# ipsec.conf
cat > /etc/ipsec.conf <<EOF
config setup
  uniqueids=no

conn %default
  keyexchange=ikev1
  authby=secret
  ike=aes256-sha1-modp1024!
  esp=aes256-sha1!
  keyingtries=3
  ikelifetime=8h
  lifetime=1h
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear

conn L2TP-PSK
  keyexchange=ikev1
  left=%defaultroute
  leftprotoport=17/1701
  right=%any
  rightid=%any
  rightprotoport=17/%any
  auto=add
EOF

# ipsec.secrets
cat > /etc/ipsec.secrets <<EOF
%any %any : PSK "$VPN_IPSEC_PSK"
EOF

# xl2tpd.conf
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $VPN_REMOTE_IP_RANGE
local ip = $VPN_LOCAL_IP
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# options.xl2tpd
cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 1.1.1.1
ms-dns 8.8.8.8
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
multilink
lcp-echo-interval 30
lcp-echo-failure 4
EOF

# chap-secrets
cat > /etc/ppp/chap-secrets <<EOF
$VPN_USER l2tpd $VPN_PASSWORD *
EOF

# Обновление sysctl.conf без дублирования
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

# iptables (без дублирования)
iptables -C FORWARD -s $VPN_SUBNET -j ACCEPT 2>/dev/null || iptables -A FORWARD -s $VPN_SUBNET -j ACCEPT
iptables -C FORWARD -d $VPN_SUBNET -j ACCEPT 2>/dev/null || iptables -A FORWARD -d $VPN_SUBNET -j ACCEPT
iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -C INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -C INPUT -p udp --dport 1701 -j DROP 2>/dev/null || iptables -A INPUT -p udp --dport 1701 -j DROP
iptables -t nat -C POSTROUTING -s $VPN_SUBNET -o $VPN_INTERFACE -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o $VPN_INTERFACE -j MASQUERADE

iptables-save > /etc/iptables/rules.v4

# Службы
systemctl enable strongswan-starter
systemctl enable xl2tpd
systemctl restart strongswan-starter
systemctl restart xl2tpd

# Готово
echo
echo "✅ VPN-сервер установлен."
echo "🔐 Подключение:"
echo "IP сервера: $(curl -s ifconfig.me)"
echo "IPSec PSK: $VPN_IPSEC_PSK"
echo "Имя пользователя: $VPN_USER"
echo "Пароль: $VPN_PASSWORD"