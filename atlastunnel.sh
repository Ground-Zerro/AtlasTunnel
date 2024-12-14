#!/bin/bash

set -e

LOG_FILE="/var/log/l2tp_vpn_setup.log"
exec 2>>$LOG_FILE

# Функция проверки установленного сервера
check_server_installed() {
    [ -f /etc/ipsec.conf ] && [ -f /etc/xl2tpd/xl2tpd.conf ] && [ -f /etc/ppp/chap-secrets ]
}

# Функция проверки и установки пакетов
install_packages() {
    echo "Проверка и установка необходимых пакетов..."
    REQUIRED_PACKAGES=(strongswan xl2tpd ppp lsof iptables iptables-persistent libstrongswan-standard-plugins libcharon-extra-plugins dialog unbound)

    apt update

    for PACKAGE in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l | grep -qw "$PACKAGE"; then
            echo "Установка $PACKAGE..."
            apt install -y "$PACKAGE" || {
                echo "Ошибка: не удалось установить $PACKAGE. Проверьте подключение к интернету или репозитории."
                exit 1
            }
        else
            echo "$PACKAGE уже установлен."
        fi
    done
}

# Функция для удаления сервера
remove_server() {
    echo "Удаление VPN сервера..."
    systemctl stop strongswan xl2tpd unbound || true
    systemctl disable strongswan xl2tpd unbound || true
    apt purge -y strongswan xl2tpd ppp lsof iptables-persistent unbound || true
    rm -rf /etc/ipsec.conf /etc/ipsec.secrets /etc/xl2tpd /etc/ppp/options.xl2tpd /etc/ppp/chap-secrets /etc/unbound/unbound.conf.d/dot.conf || true
    echo "VPN сервер успешно удалён."
}

# Функция для добавления нового пользователя
add_user() {
    local USERNAME=$1
    local PASSWORD=$2

    if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        echo "Ошибка: Имя пользователя или пароль не указаны."
        return 1
    fi

    echo "$USERNAME l2tpd $PASSWORD *" >> /etc/ppp/chap-secrets
    echo "Пользователь $USERNAME успешно добавлен."
}

# Функция настройки и создания пользователя
setup_user() {
    echo -n "Введите имя пользователя для VPN: "
    read VPN_USER
    echo -n "Введите пароль для VPN: "
    read -s VPN_PASSWORD
    echo
    add_user "$VPN_USER" "$VPN_PASSWORD"
}

# Функция настройки сервера
setup_server() {
    install_packages

    VPN_IPSEC_PSK=$(tr -dc 'a-zA-Z' < /dev/urandom | head -c6)
    VPN_SERVER_IP=$(ip -4 addr show dev eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

    cat > /etc/ipsec.conf <<EOF
config setup
    uniqueids=never
conn L2TP-PSK
    authby=secret
    pfs=no
    auto=add
    keyexchange=ikev1
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
    type=transport
    left=%any
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/1701
EOF

    cat > /etc/ipsec.secrets <<EOF
: PSK "$VPN_IPSEC_PSK"
EOF

    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
[lns default]
ip range = 10.10.10.2-10.10.10.20
local ip = 10.10.10.1
require chap = yes
refuse pap = yes
require authentication = yes
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

    cat > /etc/ppp/options.xl2tpd <<EOF
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

    systemctl restart unbound || echo "Unbound не настроен."
    sysctl -w net.ipv4.ip_forward=1
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

    iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -C FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT

    netfilter-persistent save

    systemctl enable strongswan xl2tpd
    systemctl restart strongswan xl2tpd

    echo "VPN сервер успешно настроен."
    echo "Сервер: $VPN_SERVER_IP"
    echo "IPSec PSK: $VPN_IPSEC_PSK"
}

list_users() {
    echo "Список пользователей:"
    awk '/^[^#]/ {print NR ") Логин: "$1", Пароль: "$3}' /etc/ppp/chap-secrets
}

delete_user() {
    echo "Выберите пользователя для удаления:"
    mapfile -t USERS < <(awk '/^[^#]/ {print $1}' /etc/ppp/chap-secrets)

    for i in "${!USERS[@]}"; do
        echo "$((i+1))) ${USERS[$i]}"
    done

    echo "0) Отмена"
    read -p "Ваш выбор: " CHOICE

    if [[ "$CHOICE" -eq 0 ]]; then
        echo "Отмена удаления."
    elif [[ "$CHOICE" -gt 0 && "$CHOICE" -le "${#USERS[@]}" ]]; then
        sed -i "/^${USERS[$CHOICE-1]} /d" /etc/ppp/chap-secrets
        echo "Пользователь ${USERS[$CHOICE-1]} удалён."
    else
        echo "Неверный выбор."
    fi
}

if check_server_installed; then
    echo "Обнаружена установленная конфигурация VPN сервера. Выберите действие:"
    echo "1) Переустановить сервер"
    echo "2) Удалить сервер"
    echo "3) Добавить нового клиента"
    echo "4) Список пользователей"
    echo "5) Удалить пользователя"
    read -p "Ваш выбор (1-5): " CHOICE

    case $CHOICE in
        1)
            remove_server
            setup_server
            ;;
        2)
            remove_server
            ;;
        3)
            setup_user
            ;;
        4)
            list_users
            ;;
        5)
            delete_user
            ;;
        *)
            echo "Неверный выбор. Завершение работы."
            exit 1
            ;;
    esac
else
    setup_server
    setup_user
fi
