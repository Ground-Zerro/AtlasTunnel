#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

LOG_FILE="/var/log/vpn-setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

VPN_CONF="/etc/vpn.conf"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Запустите скрипт от root."
        exit 1
    fi
}

check_server_installed() {
    [ -f /etc/ipsec.conf ] && [ -f /etc/ppp/chap-secrets ]
}

detect_interface() {
    ip route | awk '/default/ {print $5}' | head -n1
}

install_packages() {
    local REQUIRED_PACKAGES=(libreswan ppp lsof iptables iptables-persistent dialog unbound curl)
    apt update

    for PACKAGE in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l | grep -qw "$PACKAGE"; then
            echo "Устанавливаем $PACKAGE..."
            apt install -y "$PACKAGE"
        else
            echo "$PACKAGE уже установлен."
        fi
    done
}

generate_psk() {
    tr -dc 'a-zA-Z' </dev/urandom | head -c16
}

get_external_ip() {
    local IP
    IP=$(curl -s http://checkip.amazonaws.com)
    if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$IP"
    else
        echo "Ошибка: не удалось определить внешний IP."
        exit 1
    fi
}

save_vpn_config() {
    cat > "$VPN_CONF" <<EOF
VPN_SERVER_IP=$VPN_SERVER_IP
VPN_IPSEC_PSK=$VPN_IPSEC_PSK
EOF
}

load_vpn_config() {
    if [ -f "$VPN_CONF" ]; then
        # shellcheck disable=SC1090
        source "$VPN_CONF"
    else
        echo "Файл конфигурации VPN не найден."
        exit 1
    fi
}

setup_server() {
    install_packages

    VPN_SERVER_IP=$(get_external_ip)
    VPN_IPSEC_PSK=$(generate_psk)
    DEFAULT_IF=$(detect_interface)

    echo "Настраиваем VPN-сервер..."

    cat > /etc/ipsec.conf <<EOF
config setup
    uniqueids=no

conn L2TP-PSK
    authby=secret
    pfs=no
    auto=start
    ike=aes256-sha1-modp1024
    phase2alg=aes256-sha1
    type=transport
    left=$VPN_SERVER_IP
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/1701
    dpdaction=clear
    dpddelay=300s
    dpdtimeout=1h
    rekey=no
    leftsubnet=0.0.0.0/0
EOF

    echo ": PSK \"$VPN_IPSEC_PSK\"" > /etc/ipsec.secrets

    cat > /etc/ppp/options.l2tpd <<EOF
require-mschap-v2
ms-dns 127.0.0.1
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
EOF

    mkdir -p /etc/unbound/unbound.conf.d
    cat > /etc/unbound/unbound.conf.d/dot.conf <<EOF
server:
    interface: 127.0.0.1
    access-control: 127.0.0.1/32 allow
    use-syslog: yes
    forward-zone:
        name: "."
        forward-tls-upstream: yes
        forward-addr: 1.1.1.1@853
        forward-addr: 1.0.0.1@853
        forward-addr: 9.9.9.9@853
        forward-addr: 149.112.112.112@853
EOF

    systemctl restart unbound || echo "Unbound не запущен."

    echo "Включаем IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

    echo "Настраиваем iptables..."
    iptables -t nat -A POSTROUTING -o "$DEFAULT_IF" -j MASQUERADE
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
    netfilter-persistent save

    systemctl enable ipsec
    systemctl restart ipsec

    save_vpn_config

    echo "VPN-сервер настроен."
}

setup_user() {
    echo -n "Введите имя пользователя: "
    read VPN_USER
    read -s -p "Введите пароль: " VPN_PASSWORD
    echo

    if [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
        echo "Ошибка: имя или пароль пусты."
        return 1
    fi

    if grep -q "^$VPN_USER[[:space:]]" /etc/ppp/chap-secrets; then
        echo "Пользователь уже существует."
        return 1
    fi

    echo "$VPN_USER    *    $VPN_PASSWORD    *" >> /etc/ppp/chap-secrets
    echo "Пользователь $VPN_USER добавлен."
}

show_users() {
    if [ -f /etc/ppp/chap-secrets ]; then
        echo "Пользователи:"
        awk '!/^#/ && NF >= 3 {print $1 " - " $3}' /etc/ppp/chap-secrets
    else
        echo "Файл пользователей не найден."
    fi
}

delete_user() {
    if [ ! -f /etc/ppp/chap-secrets ]; then
        echo "Файл не найден."
        return 1
    fi

    USERS=($(awk '!/^#/ && NF >= 3 {print $1}' /etc/ppp/chap-secrets))
    if [ ${#USERS[@]} -eq 0 ]; then
        echo "Нет пользователей."
        return 1
    fi

    echo "Выберите пользователя для удаления:"
    for i in "${!USERS[@]}"; do
        echo "$((i+1))) ${USERS[$i]}"
    done

    read -p "Номер: " CHOICE
    if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || [ "$CHOICE" -lt 1 ] || [ "$CHOICE" -gt ${#USERS[@]} ]; then
        echo "Неверный выбор."
        return 1
    fi

    USER_TO_DELETE=${USERS[$((CHOICE - 1))]}
    escaped_user=$(printf '%s\n' "$USER_TO_DELETE" | sed 's/[][\.*^$/]/\\&/g')
    sed -i "/^$escaped_user[[:space:]]/d" /etc/ppp/chap-secrets
    echo "Пользователь $USER_TO_DELETE удалён."
}

show_configuration() {
    load_vpn_config
    echo "Данные для подключения:"
    echo "Сервер: $VPN_SERVER_IP"
    echo "IPSec PSK: $VPN_IPSEC_PSK"
}

main_menu() {
    echo
    echo "=== Управление VPN ==="
    echo "1) Добавить пользователя"
    echo "2) Показать пользователей"
    echo "3) Удалить пользователя"
    echo "4) Показать конфигурацию"
    echo "0) Выход"
    echo "======================"

    read -p "Выбор: " CHOICE
    case "$CHOICE" in
        1) setup_user ;;
        2) show_users ;;
        3) delete_user ;;
        4) show_configuration ;;
        0) exit 0 ;;
        *) echo "Неверный выбор" ;;
    esac
}

### Запуск
check_root

if check_server_installed; then
    load_vpn_config
    show_configuration
    while true; do
        main_menu
    done
else
    setup_server
    show_configuration
    setup_user
fi