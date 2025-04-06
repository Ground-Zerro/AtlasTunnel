#!/bin/sh
set -e

VPN_USER="vpnuser"
VPN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
VPN_LOCAL_IP="10.30.40.1"
VPN_REMOTE_IP_RANGE="10.30.40.10-100"

echo "[*] Установка пакетов..."
apt-get update
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y xl2tpd ppp iptables-persistent

echo "[*] Настройка xl2tpd..."
mkdir -p /etc/xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $VPN_REMOTE_IP_RANGE
local ip = $VPN_LOCAL_IP
refuse pap = yes
refuse chap = yes
refuse mschap = yes
require mschap-v2 = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd
length bit = yes
EOF

echo "[*] Настройка ppp options..."
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

echo "[*] Настройка iptables..."
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

iptables -C FORWARD -i ppp+ -o eth0 -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o eth0 -j ACCEPT

iptables -C FORWARD -i eth0 -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i eth0 -o ppp+ -j ACCEPT

netfilter-persistent save
systemctl enable netfilter-persistent

echo "[*] Подготовка /var/run/xl2tpd..."
mkdir -p /var/run/xl2tpd
touch /var/run/xl2tpd/l2tp-control

echo "[*] Настройка systemd сервиса для xl2tpd..."
cat > /etc/systemd/system/xl2tpd.service <<EOF
[Unit]
Description=Layer 2 Tunnelling Protocol Daemon (L2TP)
After=network.target

[Service]
ExecStart=/usr/sbin/xl2tpd -D
PIDFile=/run/xl2tpd/xl2tpd.pid
ExecStartPre=/bin/mkdir -p /var/run/xl2tpd
ExecStartPre=/bin/touch /var/run/xl2tpd/l2tp-control
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload

echo "[*] Включение и запуск xl2tpd..."
systemctl enable xl2tpd
systemctl restart xl2tpd

echo "[*] Установка L2TP Tunnel manager (atlas)..."
mkdir -p /etc/atlastunnel
cp /etc/ppp/chap-secrets /etc/atlastunnel/chap-secrets.backup

cat << 'EOF' > /etc/atlastunnel/manager.sh
#!/bin/sh
L2TP_SERVICE="xl2tpd"
CHAP_SECRETS="/etc/ppp/chap-secrets"
CLIENT_LOGINS=""

print_status() {
    echo "[*] Статус L2TP сервера:"
    systemctl is-active "$L2TP_SERVICE" >/dev/null 2>&1 && echo "    СТАТУС: ✅ ЗАПУЩЕН" || echo "    СТАТУС: ❌ ОСТАНОВЛЕН"
}

list_clients() {
    echo
    echo "[*] Список клиентов:"
    CLIENT_LOGINS=""
    if [ ! -f "$CHAP_SECRETS" ] || ! grep -qvE '^\s*#|^\s*$' "$CHAP_SECRETS"; then
        echo "    Нет добавленных клиентов."
        return
    fi
    printf "\n  %-4s %-20s %-20s\n" "№" "ЛОГИН" "ПАРОЛЬ"
    echo "  ---------------------------------------------------------"
    i=1
    while IFS= read -r line; do
        USER=$(echo "$line" | awk '{print $1}')
        PASS=$(echo "$line" | awk '{print $3}')
        printf "  %-4s %-20s %-20s\n" "$i" "$USER" "$PASS"
        CLIENT_LOGINS="$CLIENT_LOGINS $USER"
        i=$((i + 1))
    done <<EOF_CHAP
$(grep -vE '^\s*#|^\s*$' "$CHAP_SECRETS")
EOF_CHAP
    echo
}

get_login_by_index() {
    INDEX=$1
    i=1
    for login in $CLIENT_LOGINS; do
        [ "$i" = "$INDEX" ] && echo "$login" && return
        i=$((i + 1))
    done
    echo ""
}

start_l2tp() {
    echo "[*] Запуск L2TP сервера..."
    systemctl start "$L2TP_SERVICE"
}

stop_l2tp() {
    echo "[*] Остановка L2TP сервера..."
    systemctl stop "$L2TP_SERVICE"
}

restart_l2tp() {
    echo "[*] Перезапуск L2TP сервера..."
    systemctl restart "$L2TP_SERVICE"
}

add_client() {
    printf "  Введите логин: "
    read LOGIN
    if grep -q "^$LOGIN " "$CHAP_SECRETS"; then
        echo "  ❌ Такой логин уже есть."
    else
        PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
        echo "$LOGIN * $PASS *" >> "$CHAP_SECRETS"
        echo "  ✅ Добавлен: $LOGIN | Пароль: $PASS"
    fi
}

delete_client() {
    printf "  Введите номер клиента для удаления: "
    read NUM
    LOGIN=$(get_login_by_index "$NUM")
    [ -z "$LOGIN" ] && echo "❌ Неверный номер." && return
    sed -i "/^$LOGIN\s\+/d" "$CHAP_SECRETS"
    echo "  ✅ Удалён: $LOGIN"
}

change_password() {
    printf "  Введите номер клиента для смены пароля: "
    read NUM
    LOGIN=$(get_login_by_index "$NUM")
    [ -z "$LOGIN" ] && echo "❌ Неверный номер." && return
    NEWPASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
    sed -i "s|^$LOGIN\s\+\*\s\+\S\+\s\+\*|$LOGIN * $NEWPASS *|" "$CHAP_SECRETS"
    echo "  ✅ Новый пароль для $LOGIN: $NEWPASS"
}

menu() {
    while true; do
        print_status
        list_clients
        echo "===== МЕНЮ ====="
        echo "1) Запуск сервера"
        echo "2) Остановка"
        echo "3) Перезапуск"
        echo "4) Добавить клиента"
        echo "5) Удалить клиента"
        echo "6) Сменить пароль"
        echo "0) Выход"
        printf "Выберите действие: "
        read CHOICE
        case "$CHOICE" in
            1) start_l2tp ;;
            2) stop_l2tp ;;
            3) restart_l2tp ;;
            4) add_client ;;
            5) delete_client ;;
            6) change_password ;;
            0) echo "Выход."; break ;;
            *) echo "❌ Неверный выбор." ;;
        esac
    done
}

menu
EOF

chmod +x /etc/atlastunnel/manager.sh
ln -sf /etc/atlastunnel/manager.sh /usr/local/bin/atlas

echo "[✓] Готово! Используйте:"
echo "    IP сервера: $(curl -s https://ipinfo.io/ip)"
echo "    Логин: $VPN_USER"
echo "    Пароль: $VPN_PASS"