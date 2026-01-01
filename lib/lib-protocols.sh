#!/bin/bash

update_ipsec_secrets() {
    local mode="$1"
    local vpn_user="$2"
    local vpn_pass="$3"
    local vpn_psk="${4:-}"

    local tmp_file="/tmp/ipsec.secrets.tmp"
    touch "$tmp_file"
    chmod 600 "$tmp_file"

    if [ -f "/etc/ipsec.secrets" ]; then
        if [ "$mode" = "l2tp-ipsec" ]; then
            grep -v "^%any.*PSK" /etc/ipsec.secrets > "$tmp_file" || true
            echo "%any  %any  : PSK \"$vpn_psk\"" >> "$tmp_file"
        elif [ "$mode" = "ikev2" ] || [ "$mode" = "ikev2-ipsec" ]; then
            grep -v "^:" /etc/ipsec.secrets | grep -v "^[^:]*:.*EAP" > "$tmp_file" || true
            echo ": RSA \"server-key.pem\"" >> "$tmp_file"

            if [ -n "$vpn_user" ]; then
                local existing_users=$(grep "^[^:]*:.*EAP" /etc/ipsec.secrets 2>/dev/null | awk '{print $1}' || true)
                echo "$existing_users" | while read -r user; do
                    if [ -n "$user" ] && [ "$user" != "$vpn_user" ]; then
                        local old_pass=$(grep "^${user}.*EAP" /etc/ipsec.secrets | awk -F'"' '{print $2}')
                        echo "$user : EAP \"$old_pass\"" >> "$tmp_file"
                    fi
                done
                echo "$vpn_user : EAP \"$vpn_pass\"" >> "$tmp_file"
            fi
        fi
    else
        if [ "$mode" = "l2tp-ipsec" ]; then
            echo "%any  %any  : PSK \"$vpn_psk\"" > "$tmp_file"
        elif [ "$mode" = "ikev2" ] || [ "$mode" = "ikev2-ipsec" ]; then
            echo ": RSA \"server-key.pem\"" > "$tmp_file"
            echo "$vpn_user : EAP \"$vpn_pass\"" >> "$tmp_file"
        fi
    fi

    mv "$tmp_file" /etc/ipsec.secrets
    chmod 600 /etc/ipsec.secrets
}

SUBNET_PPTP="10.20.30.0/24"
VPN_LOCAL_IP_PPTP="10.20.30.1"
VPN_REMOTE_IP_RANGE_PPTP="10.20.30.40-200"

SUBNET_L2TP="10.30.40.0/24"
VPN_LOCAL_IP_L2TP="10.30.40.1"
VPN_REMOTE_IP_RANGE_L2TP="10.30.40.10-100"

SUBNET_IKEV2="10.40.50.0/24"

SUBNET_SSTP="10.50.60.0/24"
VPN_LOCAL_IP_SSTP="10.50.60.1"
VPN_REMOTE_IP_RANGE_SSTP="10.50.60.10-100"

SUBNET_OPENVPN="10.60.70.0/24"

VPN_DNS1="8.8.8.8"
VPN_DNS2="1.1.1.1"

save_protocol_config() {
    local protocol="$1"
    local vpn_user="$2"
    local vpn_pass="$3"
    local vpn_psk="${4:-}"

    mkdir -p /etc/atlastunnel

    cat > "/etc/atlastunnel/${protocol}.conf" <<EOF
PROTOCOL=$protocol
VPN_USER=$vpn_user
VPN_PASS=$vpn_pass
VPN_PSK=$vpn_psk
INSTALLED_DATE=$(date +%Y-%m-%d)
EOF

    chmod 600 "/etc/atlastunnel/${protocol}.conf"
}

install_pptp_manual() {
    local ubuntu_ver="$1"

    log "Обнаружена Ubuntu $ubuntu_ver — установка вручную: libssl1.1, ppp, bcrelay, pptpd"

    log "Загрузка libssl1.1..."
    wget -q -O /tmp/libssl1.1.deb "http://nova.clouds.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb"

    log "Загрузка ppp..."
    wget -q -O /tmp/ppp.deb "http://ru.archive.ubuntu.com/ubuntu/pool/main/p/ppp/ppp_2.4.9-1%2b1ubuntu3_amd64.deb"

    log "Загрузка bcrelay..."
    wget -q -O /tmp/bcrelay.deb "http://nova.clouds.archive.ubuntu.com/ubuntu/pool/main/p/pptpd/bcrelay_1.4.0-11build1_amd64.deb"

    log "Загрузка pptpd..."
    wget -q -O /tmp/pptpd.deb "http://ru.archive.ubuntu.com/ubuntu/pool/main/p/pptpd/pptpd_1.4.0-12build2_amd64.deb"

    log "Установка libssl1.1..."
    dpkg -i /tmp/libssl1.1.deb >/dev/null 2>&1

    log "Установка ppp..."
    dpkg -i /tmp/ppp.deb >/dev/null 2>&1

    log "Установка bcrelay..."
    dpkg -i /tmp/bcrelay.deb >/dev/null 2>&1

    log "Установка pptpd..."
    dpkg -i /tmp/pptpd.deb >/dev/null 2>&1

    log "Устранение возможных зависимостей..."
    apt-get install -f -y >/dev/null 2>&1

    log "Блокировка обновлений для установленных пакетов..."
    apt-mark hold libssl1.1 ppp pptpd bcrelay >/dev/null 2>&1

    rm -f /tmp/libssl1.1.deb /tmp/ppp.deb /tmp/bcrelay.deb /tmp/pptpd.deb
}

install_pptp() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local wan_iface="$3"

    log "Установка PPTP сервера..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1

    local ubuntu_ver=$(get_ubuntu_version)

    if dpkg --compare-versions "$ubuntu_ver" gt "22.04"; then
        install_pptp_manual "$ubuntu_ver"
    else
        log "Обнаружена Ubuntu $ubuntu_ver — установка pptpd из репозитория"
        apt-get install -y pptpd >/dev/null 2>&1
    fi

    log "Настройка /etc/pptpd.conf..."
    cat > /etc/pptpd.conf <<EOF
option /etc/ppp/pptpd-options
logwtmp
localip $VPN_LOCAL_IP_PPTP
remoteip $VPN_REMOTE_IP_RANGE_PPTP
EOF

    log "Настройка /etc/ppp/pptpd-options..."
    cat > /etc/ppp/pptpd-options <<EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
+mppe-128
+mppe-40
nomppe
noccp
ms-dns $VPN_DNS1
ms-dns $VPN_DNS2
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

    log "Настройка пользователя..."
    if ! grep -q "$vpn_user" /etc/ppp/chap-secrets 2>/dev/null; then
        echo "$vpn_user pptpd $vpn_pass *" >> /etc/ppp/chap-secrets
    fi

    setup_iptables_for_protocol "pptp" "$SUBNET_PPTP" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1
    systemctl restart netfilter-persistent >/dev/null 2>&1

    log "Включение и запуск pptpd..."
    systemctl enable pptpd >/dev/null 2>&1
    systemctl restart pptpd

    save_protocol_config "pptp" "$vpn_user" "$vpn_pass"

    ok "PPTP сервер установлен и запущен"
}

install_l2tp() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local wan_iface="$3"

    log "Установка L2TP сервера..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y xl2tpd ppp >/dev/null 2>&1

    log "Настройка xl2tpd..."
    mkdir -p /etc/xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $VPN_REMOTE_IP_RANGE_L2TP
local ip = $VPN_LOCAL_IP_L2TP
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd
length bit = yes
EOF

    log "Настройка PPP options..."
    cat > /etc/ppp/options.l2tpd <<EOF
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
nomppe
noccp
noauth
ms-dns $VPN_DNS1
ms-dns $VPN_DNS2
asyncmap 0
auth
hide-password
mtu 1360
mru 1360
lcp-echo-failure 4
lcp-echo-interval 30
EOF

    log "Очистка устаревших pppd-опций (modem, lock)..."
    sed -i '/^modem$/d' /etc/ppp/options.l2tpd 2>/dev/null
    sed -i '/^lock$/d' /etc/ppp/options.l2tpd 2>/dev/null

    log "Добавление пользователя..."
    echo "\"$vpn_user\" * $vpn_pass *" >> /etc/ppp/chap-secrets

    setup_iptables_for_protocol "l2tp" "$SUBNET_L2TP" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1

    log "Подготовка /var/run/xl2tpd..."
    mkdir -p /var/run/xl2tpd
    touch /var/run/xl2tpd/l2tp-control

    log "Настройка systemd сервиса для xl2tpd..."
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

    log "Активация сервиса xl2tpd..."
    systemctl daemon-reexec >/dev/null 2>&1
    systemctl daemon-reload
    systemctl enable xl2tpd >/dev/null 2>&1
    systemctl restart xl2tpd

    save_protocol_config "l2tp" "$vpn_user" "$vpn_pass"

    ok "L2TP сервер установлен и запущен"
}

install_l2tp_ipsec() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local vpn_psk="$3"
    local wan_iface="$4"

    log "Установка L2TP/IPsec сервера..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y xl2tpd strongswan ppp >/dev/null 2>&1

    log "Настройка IPsec (strongSwan)..."
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

    update_ipsec_secrets "l2tp-ipsec" "$vpn_user" "$vpn_pass" "$vpn_psk"

    log "Настройка xl2tpd..."
    mkdir -p /etc/xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $VPN_REMOTE_IP_RANGE_L2TP
local ip = $VPN_LOCAL_IP_L2TP
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd
length bit = yes
EOF

    log "Настройка PPP options..."
    cat > /etc/ppp/options.l2tpd <<EOF
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
nomppe
noccp
noauth
ms-dns $VPN_DNS1
ms-dns $VPN_DNS2
asyncmap 0
auth
hide-password
mtu 1360
mru 1360
lcp-echo-failure 4
lcp-echo-interval 30
EOF

    log "Очистка устаревших pppd-опций (modem, lock)..."
    sed -i '/^modem$/d' /etc/ppp/options.l2tpd 2>/dev/null
    sed -i '/^lock$/d' /etc/ppp/options.l2tpd 2>/dev/null

    log "Добавление пользователя..."
    echo "\"$vpn_user\" * $vpn_pass *" >> /etc/ppp/chap-secrets

    setup_iptables_for_protocol "l2tp-ipsec" "$SUBNET_L2TP" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1

    log "Подготовка /var/run/xl2tpd..."
    mkdir -p /var/run/xl2tpd
    touch /var/run/xl2tpd/l2tp-control

    log "Настройка systemd сервиса для xl2tpd..."
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

    log "Активация сервисов..."
    systemctl daemon-reexec >/dev/null 2>&1
    systemctl daemon-reload
    systemctl enable strongswan-starter >/dev/null 2>&1
    systemctl restart strongswan-starter
    systemctl enable xl2tpd >/dev/null 2>&1
    systemctl restart xl2tpd

    save_protocol_config "l2tp-ipsec" "$vpn_user" "$vpn_pass" "$vpn_psk"

    ok "L2TP/IPsec сервер установлен и запущен"
}

install_ikev2() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local wan_iface="$3"
    local vpn_public_ip=$(get_public_ip)

    log "Установка IKEv2 сервера (без IPsec шифрования)..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins >/dev/null 2>&1

    log "Генерация сертификатов для IKEv2..."
    mkdir -p /etc/ipsec.d/{cacerts,certs,private}
    chmod 700 /etc/ipsec.d/private

    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem 2>/dev/null
    ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN Root CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem 2>/dev/null

    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem 2>/dev/null
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa 2>/dev/null | \
        ipsec pki --issue --lifetime 1825 \
        --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
        --cakey /etc/ipsec.d/private/ca-key.pem \
        --dn "CN=$vpn_public_ip" --san "$vpn_public_ip" \
        --flag serverAuth --flag ikeIntermediate --outform pem \
        > /etc/ipsec.d/certs/server-cert.pem 2>/dev/null

    log "Экспорт CA-сертификата для клиентов..."
    mkdir -p /var/www/html 2>/dev/null || mkdir -p /usr/share/atlastunnel
    if [ -d "/var/www/html" ]; then
        cp /etc/ipsec.d/cacerts/ca-cert.pem /var/www/html/ca-cert.pem
        chmod 644 /var/www/html/ca-cert.pem
    else
        cp /etc/ipsec.d/cacerts/ca-cert.pem /usr/share/atlastunnel/ca-cert.pem
        chmod 644 /usr/share/atlastunnel/ca-cert.pem
    fi

    update_ipsec_secrets "ikev2" "$vpn_user" "$vpn_pass"

    log "Настройка IKEv2 без IPsec шифрования..."
    cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes

    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,3des-sha1-modp1024!

    esp=null-sha256-modp2048,null-sha1-modp2048,null-sha256,null-sha1,null-md5!

    dpdaction=clear
    dpddelay=300s
    rekey=no

    left=%any
    leftid=$vpn_public_ip
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftauth=pubkey

    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=$SUBNET_IKEV2
    rightdns=$VPN_DNS1,$VPN_DNS2
    rightsendcert=never

    eap_identity=%identity

    mobike=no
EOF

    setup_iptables_for_protocol "ikev2" "$SUBNET_IKEV2" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1

    log "Активация сервисов..."
    systemctl daemon-reload
    systemctl enable strongswan-starter >/dev/null 2>&1
    systemctl restart strongswan-starter

    save_protocol_config "ikev2" "$vpn_user" "$vpn_pass"

    ok "IKEv2 сервер (без IPsec) установлен и запущен"
}

install_ikev2_ipsec() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local wan_iface="$3"
    local vpn_public_ip=$(get_public_ip)

    log "Установка IKEv2/IPsec сервера..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins >/dev/null 2>&1

    log "Генерация сертификатов для IKEv2..."
    mkdir -p /etc/ipsec.d/{cacerts,certs,private}
    chmod 700 /etc/ipsec.d/private

    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem 2>/dev/null
    ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN Root CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem 2>/dev/null

    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem 2>/dev/null
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa 2>/dev/null | \
        ipsec pki --issue --lifetime 1825 \
        --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
        --cakey /etc/ipsec.d/private/ca-key.pem \
        --dn "CN=$vpn_public_ip" --san "$vpn_public_ip" \
        --flag serverAuth --flag ikeIntermediate --outform pem \
        > /etc/ipsec.d/certs/server-cert.pem 2>/dev/null

    log "Экспорт CA-сертификата для клиентов..."
    mkdir -p /var/www/html 2>/dev/null || mkdir -p /usr/share/atlastunnel
    if [ -d "/var/www/html" ]; then
        cp /etc/ipsec.d/cacerts/ca-cert.pem /var/www/html/ca-cert.pem
        chmod 644 /var/www/html/ca-cert.pem
    else
        cp /etc/ipsec.d/cacerts/ca-cert.pem /usr/share/atlastunnel/ca-cert.pem
        chmod 644 /usr/share/atlastunnel/ca-cert.pem
    fi

    update_ipsec_secrets "ikev2-ipsec" "$vpn_user" "$vpn_pass"

    log "Настройка IPsec (strongSwan)..."
    cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes

    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048!
    esp=aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1!

    dpdaction=clear
    dpddelay=300s
    rekey=no

    left=%any
    leftid=$vpn_public_ip
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0

    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=$SUBNET_IKEV2
    rightdns=$VPN_DNS1,$VPN_DNS2
    rightsendcert=never

    eap_identity=%identity
EOF

    log "Настройка iptables с политикой IPsec..."
    iptables -t nat -C POSTROUTING -s $SUBNET_IKEV2 -o "$wan_iface" -m policy --dir out --pol ipsec -j ACCEPT 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s $SUBNET_IKEV2 -o "$wan_iface" -m policy --dir out --pol ipsec -j ACCEPT

    setup_iptables_for_protocol "ikev2-ipsec" "$SUBNET_IKEV2" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1

    log "Активация сервисов..."
    systemctl daemon-reload
    systemctl enable strongswan-starter >/dev/null 2>&1
    systemctl restart strongswan-starter

    save_protocol_config "ikev2-ipsec" "$vpn_user" "$vpn_pass"

    ok "IKEv2/IPsec сервер установлен и запущен"
}

install_sstp() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local wan_iface="$3"
    local vpn_public_ip=$(get_public_ip)

    log "Установка SSTP сервера..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y sstp-server ppp >/dev/null 2>&1

    log "Настройка SSTP-сервера..."
    mkdir -p /etc/sstp-server

    cat > /etc/sstp-server/sstp-server.conf <<EOF
cert=/etc/sstp-server/cert.pem
key=/etc/sstp-server/key.pem
listen=0.0.0.0:443
pppd=/usr/sbin/pppd
pppd_options=/etc/ppp/sstp-options
EOF

    log "Генерация самоподписанного SSL-сертификата..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/sstp-server/key.pem -out /etc/sstp-server/cert.pem \
        -subj "/CN=$vpn_public_ip" >/dev/null 2>&1

    chmod 600 /etc/sstp-server/*.pem

    log "Настройка PPP для SSTP..."
    cat > /etc/ppp/sstp-options <<EOF
require-mschap-v2
refuse-pap
refuse-chap
refuse-mschap
nodefaultroute
usepeerdns
proxyarp
lock
nobsdcomp
novj
novjccomp
nologfd
mtu 1400
mru 1400
lcp-echo-failure 4
lcp-echo-interval 30
ms-dns $VPN_DNS1
ms-dns $VPN_DNS2
EOF

    log "Добавление пользователя..."
    cat > /etc/ppp/chap-secrets <<EOF
"$vpn_user" sstp "$vpn_pass" *
EOF

    setup_iptables_for_protocol "sstp" "$SUBNET_SSTP" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1

    log "Активация и запуск сервиса SSTP..."
    systemctl enable sstp-server >/dev/null 2>&1
    systemctl restart sstp-server

    save_protocol_config "sstp" "$vpn_user" "$vpn_pass"

    ok "SSTP сервер установлен и запущен"
}

install_openvpn() {
    local vpn_user="$1"
    local vpn_pass="$2"
    local wan_iface="$3"

    log "Установка OpenVPN сервера..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y openvpn easy-rsa >/dev/null 2>&1

    log "Настройка PKI инфраструктуры..."
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa

    cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "US"
set_var EASYRSA_REQ_PROVINCE   "California"
set_var EASYRSA_REQ_CITY       "San Francisco"
set_var EASYRSA_REQ_ORG        "AtlasTunnel"
set_var EASYRSA_REQ_EMAIL      "admin@atlastunnel.local"
set_var EASYRSA_REQ_OU         "VPN"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_ALGO           rsa
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    1825
EOF

    log "Генерация CA и серверных сертификатов..."
    ./easyrsa --batch init-pki >/dev/null 2>&1
    ./easyrsa --batch build-ca nopass >/dev/null 2>&1
    ./easyrsa --batch gen-req server nopass >/dev/null 2>&1
    ./easyrsa --batch sign-req server server >/dev/null 2>&1
    ./easyrsa --batch gen-dh >/dev/null 2>&1
    openvpn --genkey secret pki/ta.key 2>/dev/null

    log "Копирование сертификатов..."
    cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem pki/ta.key /etc/openvpn/

    log "Настройка server.conf..."
    cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem

server ${SUBNET_OPENVPN%.*}.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $VPN_DNS1"
push "dhcp-option DNS $VPN_DNS2"

keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
auth SHA256

user nobody
group nogroup
persist-key
persist-tun

status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF

    setup_iptables_for_protocol "openvpn" "$SUBNET_OPENVPN" "$wan_iface"

    log "Сохранение iptables..."
    netfilter-persistent save >/dev/null 2>&1
    systemctl enable netfilter-persistent >/dev/null 2>&1

    log "Активация и запуск OpenVPN..."
    systemctl enable openvpn@server >/dev/null 2>&1
    systemctl restart openvpn@server

    save_protocol_config "openvpn" "$vpn_user" "$vpn_pass"

    ok "OpenVPN сервер установлен и запущен"
}
