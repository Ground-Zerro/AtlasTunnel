#!/bin/sh
set -e

VPN_USER="vpnuser"
VPN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
VPN_PSK=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c16)
VPN_LOCAL_IP="10.30.40.1"
VPN_REMOTE_IP_RANGE="10.30.40.10-100"
VPN_PUBLIC_IP=$(curl -s https://ipinfo.io/ip)

echo "[*] Установка необходимых пакетов..."
apt-get update
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y xl2tpd strongswan ppp iptables-persistent curl

echo "[*] Настройка IPsec (strongSwan)..."
cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"

conn L2TP-PSK
    authby=secret
    pfs=no
    auto=add
    keyexchange=ikev1
    type=transport
    left=%any
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    ike=aes128-sha1-modp1024
    esp=aes128-sha1
EOF

cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_PSK"
EOF

echo "[*] Настройка xl2tpd..."
mkdir -p /etc/xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $VPN_REMOTE_IP_RANGE
local ip = $VPN_LOCAL_IP
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd
length bit = yes
EOF

echo "[*] Настройка PPP options..."
cat > /etc/ppp/options.l2tpd <<EOF
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
nomppe
noccp
noauth
ms-dns 8.8.8.8
ms-dns 1.1.1.1
asyncmap 0
auth
hide-password
mtu 1360
mru 1360
lcp-echo-failure 4
lcp-echo-interval 30
EOF

echo "[*] Очистка устаревших pppd-опций (modem, lock)..."
sed -i '/^modem$/d' /etc/ppp/options.l2tpd
sed -i '/^lock$/d' /etc/ppp/options.l2tpd

echo "[*] Добавление пользователя..."
echo "\"$VPN_USER\" * $VPN_PASS *" >> /etc/ppp/chap-secrets

echo "[*] Включение IP маршрутизации..."
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1

echo "[*] Определение внешнего интерфейса..."
WAN_IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')
echo "    Используется интерфейс: $WAN_IFACE"

echo "[*] Настройка iptables..."
iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

iptables -C FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT

iptables -C FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT

netfilter-persistent save
systemctl enable netfilter-persistent

echo "[*] Подготовка /var/run/xl2tpd..."
mkdir -p /var/run/xl2tpd
touch /var/run/xl2tpd/l2tp-control

echo "[*] Настройка systemd сервиса для xl2tpd..."
cat > /etc/systemd/system/xl2tpd.service <<EOF
[Unit]
Description=Layer 2 Tunnelling Protocol Daemon (L2TP)
After=network.target strongswan-starter.service

[Service]
ExecStart=/usr/sbin/xl2tpd -D
PIDFile=/run/xl2tpd/xl2tpd.pid
ExecStartPre=/bin/mkdir -p /var/run/xl2tpd
ExecStartPre=/bin/touch /var/run/xl2tpd/l2tp-control
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Активация сервисов..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable strongswan-starter
systemctl restart strongswan-starter
systemctl enable xl2tpd
systemctl restart xl2tpd

echo "[*] Установка менеджера клиентов Atlas..."
mkdir -p /etc/atlastunnel
cp /etc/ppp/chap-secrets /etc/atlastunnel/chap-secrets.backup
cat << 'EOF' > /etc/atlastunnel/manager.sh
#!/bin/sh
CHAP="/etc/ppp/chap-secrets"

list() {
  echo "[*] Клиенты:"
  grep -vE '^\s*#|^\s*$' "$CHAP" | awk '{printf "  %-20s %-20s\n", $1, $3}'
}

add() {
  printf "Логин: "
  read LOGIN
  grep -q "^\"$LOGIN\"" "$CHAP" && echo "❌ Уже есть." && return
  PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
  echo "\"$LOGIN\" * $PASS *" >> "$CHAP"
  echo "✅ Добавлен: $LOGIN | $PASS"
}

del() {
  printf "Удалить логин: "
  read LOGIN
  sed -i "/^\"$LOGIN\" /d" "$CHAP"
  echo "✅ Удалён: $LOGIN"
}

passwd() {
  printf "Логин: "
  read LOGIN
  PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
  sed -i "s|^\"$LOGIN\" .*|\"$LOGIN\" * $PASS *|" "$CHAP"
  echo "✅ Новый пароль: $PASS"
}

while true; do
  echo; echo "===== Меню Atlas ====="
  echo "1) Список"
  echo "2) Добавить"
  echo "3) Удалить"
  echo "4) Новый пароль"
  echo "0) Выход"
  printf "Выбор: "
  read x
  case $x in
    1) list ;;
    2) add ;;
    3) del ;;
    4) passwd ;;
    0) break ;;
    *) echo "❌ Неверный выбор" ;;
  esac
done
EOF

chmod +x /etc/atlastunnel/manager.sh
ln -sf /etc/atlastunnel/manager.sh /usr/local/bin/atlas

echo
echo "[✓] Установка завершена."
echo
echo "📡  Подключение к VPN:"
echo "    Сервер IP : $VPN_PUBLIC_IP"
echo "    Логин     : $VPN_USER"
echo "    Пароль    : $VPN_PASS"
echo "    PSK (ключ): $VPN_PSK"
echo
echo "⚙ Менеджер клиентов: команда 'atlas'"