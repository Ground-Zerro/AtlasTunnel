#!/bin/bash

check_server_installed() {
    if [ -f /etc/ipsec.conf ] && [ -f /etc/ppp/chap-secrets ]; then
        return 0
    else
        return 1
    fi
}

install_packages() {
    REQUIRED_PACKAGES=(libreswan ppp lsof iptables iptables-persistent dialog unbound)

    apt update -o Dir::Etc::sourcelist="sources.list" -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"

    for PACKAGE in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l | grep -qw "$PACKAGE"; then
            apt install -y "$PACKAGE" || {
                echo "Ошибка: не удалось установить $PACKAGE. Проверьте подключение к интернету или репозитории."
                exit 1
            }
        else
            echo "$PACKAGE уже установлен."
        fi
    done
}

setup_user() {
    echo -n "Введите имя пользователя для VPN: "
    read VPN_USER
    echo -n "Введите пароль для VPN: "
    read -s VPN_PASSWORD
    echo

    if [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
        echo "Ошибка: Имя пользователя или пароль не указаны."
        return 1
    fi

    echo "$VPN_USER       *       $VPN_PASSWORD          *" >> /etc/ppp/chap-secrets
    echo "Пользователь $VPN_USER успешно добавлен."
}

delete_user() {
    if [ ! -f /etc/ppp/chap-secrets ]; then
        echo "Ошибка: файл /etc/ppp/chap-secrets не найден."
        return 1
    fi

    echo "Список пользователей:"
    USERS=($(awk -F'[: ]+' '!/^#/ && NF >= 3 {print $1}' /etc/ppp/chap-secrets))

    if [ ${#USERS[@]} -eq 0 ]; then
        echo "Нет пользователей для удаления."
        return 1
    fi

    for i in "${!USERS[@]}"; do
        echo "$((i + 1))) ${USERS[$i]}"
    done

    echo -n "Введите номер пользователя для удаления: "
    read USER_INDEX

    if ! [[ "$USER_INDEX" =~ ^[0-9]+$ ]] || [ "$USER_INDEX" -lt 1 ] || [ "$USER_INDEX" -gt ${#USERS[@]} ]; then
        echo "Ошибка: некорректный номер пользователя."
        return 1
    fi

    USER_TO_DELETE=${USERS[$((USER_INDEX - 1))]}

    sed -i "/^$USER_TO_DELETE[[:space:]]/d" /etc/ppp/chap-secrets
    echo "Пользователь $USER_TO_DELETE успешно удалён."
}

setup_server() {
    install_packages

    VPN_IPSEC_PSK=$(tr -dc 'a-zA-Z' < /dev/urandom | head -c6)

    # Получаем внешний IP адрес
    VPN_SERVER_IP=$(curl -s http://checkip.amazonaws.com)

    # Корректируем файл /etc/ipsec.conf для динамических соединений
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

    # Создаем файл /etc/ipsec.secrets для хранения PSK
    cat > /etc/ipsec.secrets <<EOF
: PSK "$VPN_IPSEC_PSK"
EOF

    # Корректируем файл /etc/ppp/options.l2tpd
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

    # Конфигурируем Unbound DNS
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

    # Перезапускаем Unbound, если он включен
    if systemctl is-enabled --quiet unbound; then
        systemctl restart unbound
    else
        echo "Сервис Unbound не найден. Пропускаем перезапуск."
    fi

    # Включаем и настраиваем IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

    # Применяем правила iptables для NAT и форвардинга
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT

    # Сохраняем правила iptables
    netfilter-persistent save -y >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Правила iptables успешно сохранены."
    else
        echo "Ошибка при сохранении правил iptables."
    fi

    # Включаем и перезапускаем сервис ipsec
    systemctl enable ipsec
    systemctl restart ipsec || {
        echo "Ошибка при запуске сервиса ipsec. Проверьте конфигурацию."
        exit 1
    }

    echo "VPN сервер сконфигурирован."
}

show_configuration() {
    echo "Данные для подключения:"
    echo "Сервер: $VPN_SERVER_IP"
    echo "IPSec PSK: $VPN_IPSEC_PSK"
}

show_users() {
    if [ -f /etc/ppp/chap-secrets ]; then
        echo "Пользователь - Пароль:"
        awk -F'[: ]+' '!/^#/ && NF >= 3 {print $1 " - " $3}' /etc/ppp/chap-secrets
    else
        echo "Ошибка: файл /etc/ppp/chap-secrets не найден."
    fi
}

main_menu() {
    echo "Выберите действие:"
    echo "1) Добавить нового пользователя"
    echo "2) Показать список пользователей"
    echo "3) Удалить пользователя"
    read -p "Ваш выбор (1-3): " CHOICE

    case $CHOICE in
        1)
            setup_user
            ;;

        2)
            show_users
            ;;

        3)
            delete_user
            ;;

        *)
            echo "Неверный выбор. Завершение работы."
            exit 1
            ;;
    esac
}

if check_server_installed; then
    VPN_SERVER_IP=$(hostname -I | awk '{print $1}')
    VPN_IPSEC_PSK=$(grep -oP '(?<=: PSK ").*?(?=")' /etc/ipsec.secrets)
    show_configuration
    main_menu
else
    setup_server
    show_configuration
    setup_user
fi

