#!/bin/sh

set -e

VPN_USER="vpnuser"
VPN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
VPN_LOCAL_IP="10.20.30.1"
VPN_REMOTE_IP_RANGE="10.20.30.40-200"

echo "[*] Установка необходимых пакетов..."
apt-get update
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections

UBUNTU_VER=$(lsb_release -rs | cut -d'.' -f1,2)

echo "[*] Установка pptpd..."
if dpkg --compare-versions "$UBUNTU_VER" gt "22.04"; then
    echo "    Обнаружена Ubuntu $UBUNTU_VER — установка вручную: libssl1.1, ppp, bcrelay, pptpd."

    echo "    Загрузка libssl1.1..."
    wget -O /tmp/libssl1.1.deb "http://nova.clouds.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb"

    echo "    Загрузка ppp..."
    wget -O /tmp/ppp.deb "http://ru.archive.ubuntu.com/ubuntu/pool/main/p/ppp/ppp_2.4.9-1%2b1ubuntu3_amd64.deb"

    echo "    Загрузка bcrelay..."
    wget -O /tmp/bcrelay.deb "http://nova.clouds.archive.ubuntu.com/ubuntu/pool/main/p/pptpd/bcrelay_1.4.0-11build1_amd64.deb"

    echo "    Загрузка pptpd..."
    wget -O /tmp/pptpd.deb "http://ru.archive.ubuntu.com/ubuntu/pool/main/p/pptpd/pptpd_1.4.0-12build2_amd64.deb"

    echo "    Установка libssl1.1..."
    dpkg -i /tmp/libssl1.1.deb

    echo "    Установка ppp..."
    dpkg -i /tmp/ppp.deb

    echo "    Установка bcrelay..."
    dpkg -i /tmp/bcrelay.deb

    echo "    Установка pptpd..."
    dpkg -i /tmp/pptpd.deb

    echo "    Устранение возможных зависимостей..."
    apt-get install -f -y

    echo "    Блокировка обновлений для установленных пакетов..."
    apt-mark hold libssl1.1 ppp pptpd bcrelay
else
    echo "    Обнаружена Ubuntu $UBUNTU_VER — установка pptpd из репозитория."
    DEBIAN_FRONTEND=noninteractive apt-get install -y pptpd
fi

echo "[*] Установка iptables-persistent..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent

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
+mppe-128
+mppe-40
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

echo "[*] Определение внешнего интерфейса..."
WAN_IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')
echo "    Используется интерфейс: $WAN_IFACE"

echo "[*] Настройка iptables..."
iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

iptables -C FORWARD -i ppp+ -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o ppp+ -j ACCEPT

iptables -C FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT

iptables -C FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT

echo "[*] Сохранение iptables и включение автозапуска..."
netfilter-persistent save
systemctl enable netfilter-persistent
systemctl restart netfilter-persistent

echo "[*] Включение и перезапуск pptpd..."
systemctl enable pptpd
systemctl restart pptpd

echo "[*] Установка Atlas Tunnel manager..."
mkdir -p /etc/atlastunnel
cat << 'EOF' > /etc/atlastunnel/manager.sh
#!/bin/sh

PPTP_SERVICE="pptpd"
CHAP_SECRETS="/etc/ppp/chap-secrets"
CLIENT_LOGINS=""

print_status() {
    echo "[*] Статус PPTP сервера:"
    systemctl is-active "$PPTP_SERVICE" >/dev/null 2>&1 && echo "    СТАТУС: ✅ ЗАПУЩЕН" || echo "    СТАТУС: ❌ ОСТАНОВЛЕН"
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
        if [ "$i" -eq "$INDEX" ]; then
            echo "$login"
            return
        fi
        i=$((i + 1))
    done
    echo ""
}

start_pptp() {
    echo "[*] Запуск PPTP сервера..."
    systemctl start "$PPTP_SERVICE"
    systemctl enable "$PPTP_SERVICE"
}

stop_pptp() {
    echo "[*] Остановка PPTP сервера..."
    systemctl stop "$PPTP_SERVICE"
}

restart_pptp() {
    echo "[*] Перезапуск PPTP сервера..."
    systemctl restart "$PPTP_SERVICE"
}

add_client() {
    echo "[*] Добавление клиента..."
    printf "  Введите логин: "
    read LOGIN

    if grep -q "^$LOGIN " "$CHAP_SECRETS"; then
        echo "  ❌ Клиент с таким именем уже существует."
    else
        PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
        echo "$LOGIN pptpd $PASS *" >> "$CHAP_SECRETS"
        echo "  ✅ Клиент добавлен."
        echo "  🔐 Пароль для \"$LOGIN\": $PASS"
    fi
}

delete_client() {
    echo "[*] Удаление клиента..."
    if [ -z "$CLIENT_LOGINS" ]; then
        echo "  ❌ Нет клиентов для удаления."
        return
    fi

    printf "  Введите номер клиента для удаления: "
    read NUM

    LOGIN=$(get_login_by_index "$NUM")
    if [ -z "$LOGIN" ]; then
        echo "  ❌ Неверный номер клиента."
        return
    fi

    sed -i "/^$LOGIN\s\+pptpd\s\+/d" "$CHAP_SECRETS"
    echo "  ✅ Клиент \"$LOGIN\" удалён."
}

change_password() {
    echo "[*] Смена пароля клиента..."
    if [ -z "$CLIENT_LOGINS" ]; then
        echo "  ❌ Нет клиентов для изменения пароля."
        return
    fi

    printf "  Введите номер клиента: "
    read NUM

    LOGIN=$(get_login_by_index "$NUM")
    if [ -z "$LOGIN" ]; then
        echo "  ❌ Неверный номер клиента."
        return
    fi

    NEWPASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
    sed -i "s|^$LOGIN\s\+pptpd\s\+\S\+\s\+\*|$LOGIN pptpd $NEWPASS *|" "$CHAP_SECRETS"
    echo "  ✅ Новый пароль клиента \"$LOGIN\": $NEWPASS"
}

menu() {
    while true; do
        echo
        print_status
        list_clients
        echo "===== Меню Atlas PPTP ====="
        echo "1) Запустить PPTP сервер"
        echo "2) Остановить PPTP сервер"
        echo "3) Перезапустить PPTP сервер"
        echo "4) Добавить клиента"
        echo "5) Удалить клиента"
        echo "6) Сменить пароль клиента"
        echo "0) Выход"
        echo "================"
        printf "Выберите действие: "
        read CHOICE
        echo

        case "$CHOICE" in
            1) start_pptp ;;
            2) stop_pptp ;;
            3) restart_pptp ;;
            4) add_client ;;
            5) delete_client ;;
            6) change_password ;;
            0) echo "Выход."; break ;;
            *) echo "❌ Неверный выбор. Попробуйте снова." ;;
        esac
    done
}

menu
EOF

ln -sf /etc/atlastunnel/manager.sh /usr/local/bin/atlas
chmod +x /etc/atlastunnel/manager.sh

echo "[✓] Установка и настройка завершены. Используйте:"
echo "    IP сервера: $(curl -s https://ipinfo.io/ip)"
echo "    логин: $VPN_USER"
echo "    пароль: $VPN_PASS"