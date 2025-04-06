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
mkdir -p /etc/ppp
cat > /etc/ppp/options.l2tpd <<EOF
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
nomppe
noccp
ms-dns 8.8.8.8
ms-dns 1.1.1.1
asyncmap 0
auth
crtscts
lock
hide-password
modem
mtu 1400
mru 1400
lcp-echo-failure 4
lcp-echo-interval 30
EOF

echo "[*] Добавление пользователя..."
echo "$VPN_USER * $VPN_PASS *" >> /etc/ppp/chap-secrets

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
L2TP_SERVICE="xl2tpd"
CHAP_SECRETS="/etc/ppp/chap-secrets"

print_status() {
    echo "[*] Статус L2TP сервера:"
    systemctl is-active "$L2TP_SERVICE" >/dev/null 2>&1 && echo "    СТАТУС: ✅ ЗАПУЩЕН" || echo "    СТАТУС: ❌ ОСТАНОВЛЕН"
}

list_clients() {
    echo "[*] Список клиентов:"
    grep -vE '^\s*#|^\s*$' "$CHAP_SECRETS" | awk '{printf "  %-20s %-20s\n", $1, $3}'
}

add_client() {
    printf "Введите логин: "
    read LOGIN
    grep -q "^$LOGIN " "$CHAP_SECRETS" && echo "  ❌ Уже существует." && return
    PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
    echo "$LOGIN * $PASS *" >> "$CHAP_SECRETS"
    echo "  ✅ Добавлен: $LOGIN | Пароль: $PASS"
}

delete_client() {
    printf "Введите логин для удаления: "
    read LOGIN
    sed -i "/^$LOGIN\s\+/d" "$CHAP_SECRETS"
    echo "  ✅ Удалён: $LOGIN"
}

change_password() {
    printf "Введите логин для смены пароля: "
    read LOGIN
    NEWPASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
    sed -i "s|^$LOGIN\s\+\*\s\+\S\+\s\+\*|$LOGIN * $NEWPASS *|" "$CHAP_SECRETS"
    echo "  ✅ Новый пароль: $NEWPASS"
}

menu() {
    while true; do
        echo
        print_status
        list_clients
        echo "===== МЕНЮ ====="
        echo "1) Запуск"
        echo "2) Остановка"
        echo "3) Перезапуск"
        echo "4) Добавить клиента"
        echo "5) Удалить клиента"
        echo "6) Сменить пароль"
        echo "0) Выход"
        printf "Выбор: "
        read CHOICE
        case "$CHOICE" in
            1) systemctl start "$L2TP_SERVICE" ;;
            2) systemctl stop "$L2TP_SERVICE" ;;
            3) systemctl restart "$L2TP_SERVICE" ;;
            4) add_client ;;
            5) delete_client ;;
            6) change_password ;;
            0) break ;;
            *) echo "❌ Неверный выбор." ;;
        esac
    done
}

menu
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