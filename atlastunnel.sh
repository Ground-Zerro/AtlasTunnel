#!/bin/bash

set -e

LOG_FILE="/var/log/l2tp_vpn_setup.log"
exec 2>>$LOG_FILE

# Функция проверки установленного сервера
check_server_installed() {
    if [ -f /etc/ipsec.conf ] && [ -f /etc/xl2tpd/xl2tpd.conf ] && [ -f /etc/ppp/chap-secrets ]; then
        return 0
    else
        return 1
    fi
}

# Функция проверки и установки пакетов
install_packages() {
    echo "Проверка и установка необходимых пакетов..."
    REQUIRED_PACKAGES=(strongswan xl2tpd ppp lsof iptables iptables-persistent libstrongswan-standard-plugins libcharon-extra-plugins dialog unbound)

    apt update -o Dir::Etc::sourcelist="sources.list" -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"

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
    apt remove -y strongswan xl2tpd ppp lsof iptables-persistent unbound || true
    rm -rf /etc/ipsec.conf /etc/ipsec.secrets /etc/xl2tpd /etc/ppp/options.xl2tpd /etc/ppp/chap-secrets /etc/unbound/unbound.conf.d/dot.conf || true
    echo "VPN сервер успешно удалён."
    exit 0
}

# Функция для добавления нового клиента
add_client() {
    read -p "Введите имя нового пользователя для VPN: " NEW_USER
    read -s -p "Введите пароль для нового пользователя: " NEW_PASSWORD
    echo
    echo "$NEW_USER       l2tpd   $NEW_PASSWORD          *" >> /etc/ppp/chap-secrets
    echo "Пользователь $NEW_USER успешно добавлен."
    exit 0
}

# Проверка на установленный сервер
if check_server_installed; then
    echo "Обнаружена установленная конфигурация VPN сервера. Выберите действие:"
    echo "1) Переустановить сервер"
    echo "2) Удалить сервер"
    echo "3) Добавить нового клиента"
    read -p "Ваш выбор (1-3): " CHOICE

    case $CHOICE in
        1)
            echo "Переустановка сервера..."
            remove_server
            ;;

        2)
            remove_server
            ;;

        3)
            add_client
            ;;

        *)
            echo "Неверный выбор. Завершение работы."
            exit 1
            ;;
    esac
fi

# Установка необходимых пакетов
install_packages

# Запрос имени пользователя и пароля
read -p "Введите имя пользователя для VPN: " VPN_USER
read -s -p "Введите пароль для VPN: " VPN_PASSWORD
echo

# Генерация случайного IPSec PSK
VPN_IPSEC_PSK=$(tr -dc 'a-zA-Z' < /dev/urandom | head -c6)

# Определение IP-адреса сервера
VPN_SERVER_IP=$(hostname -I | awk '{print $1}')

# Настройка IPsec
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

# Настройка xl2tpd
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

# Настройка Unbound для DoT
mkdir -p /etc/unbound/unbound.conf.d
cat > /etc/unbound/unbound.conf.d/dot.conf <<EOF
server:
    interface: 127.0.0.1
    access-control: 127.0.0.1/32 allow
    use-syslog: yes
    forward-zone:
        name: "."
        forward-tls-upstream: yes
        forward-addr: 1.1.1.1@853    # Cloudflare
        forward-addr: 1.0.0.1@853    # Cloudflare
        forward-addr: 9.9.9.9@853    # Quad9
        forward-addr: 149.112.112.112@853  # Quad9
EOF

# Перезапуск Unbound
systemctl enable unbound
systemctl restart unbound

# Создание учетной записи пользователя VPN
cat > /etc/ppp/chap-secrets <<EOF
# Secrets for authentication using CHAP
# client        server  secret                  IP addresses
$VPN_USER       l2tpd   $VPN_PASSWORD          *
EOF

# Включение пересылки IP
sysctl -w net.ipv4.ip_forward=1
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

# Настройка брандмауэра
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT

# Сохранение правил iptables
netfilter-persistent save

# Перезапуск служб
systemctl enable strongswan xl2tpd
systemctl restart strongswan xl2tpd

# Вывод информации о конфигурации
echo "VPN сервер успешно настроен."
echo "Данные для подключения:"
echo "Сервер: $VPN_SERVER_IP"
echo "IPSec PSK: $VPN_IPSEC_PSK"
echo "Пользователь: $VPN_USER"
echo "Пароль: $VPN_PASSWORD"
