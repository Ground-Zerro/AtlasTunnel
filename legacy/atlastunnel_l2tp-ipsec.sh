#!/bin/sh
set -e

VPN_USER="vpnuser"
VPN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
VPN_PSK=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
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
L2TP_SERVICE="xl2tpd"
IPSEC_SERVICE="strongswan-starter"
IPSEC_SECRET_FILE="/etc/ipsec.secrets"
CLIENT_LOGINS=""

get_public_ip() {
  curl -s https://ipinfo.io/ip
}

get_psk() {
  grep -vE '^\s*#|^\s*$' "$IPSEC_SECRET_FILE" | awk -F'"' '{print $2}'
}

print_status() {
  echo "[*] Статус L2TP/IPsec сервера:"
  systemctl is-active "$IPSEC_SERVICE" >/dev/null 2>&1 && echo "    IPsec: ✅ ЗАПУЩЕН" || echo "    IPsec: ❌ ОСТАНОВЛЕН"
  systemctl is-active "$L2TP_SERVICE" >/dev/null 2>&1 && echo "    L2TP : ✅ ЗАПУЩЕН" || echo "    L2TP : ❌ ОСТАНОВЛЕН"
  echo "    IP сервера: $(get_public_ip)"
  echo "    PSK (ключ): $(get_psk)"
}

list_clients() {
  echo
  echo "[*] Клиенты:"
  CLIENT_LOGINS=""
  if [ ! -f "$CHAP" ] || ! grep -qvE '^\s*#|^\s*$' "$CHAP"; then
    echo "    Нет добавленных клиентов."
    return
  fi

  printf "\n  %-4s %-20s %-20s\n" "№" "ЛОГИН" "ПАРОЛЬ"
  echo "  ---------------------------------------------------------"
  i=1
  while IFS= read -r line; do
    LOGIN=$(echo "$line" | awk '{print $1}' | sed 's/"//g')
    PASS=$(echo "$line" | awk '{print $3}')
    printf "  %-4s %-20s %-20s\n" "$i" "$LOGIN" "$PASS"
    CLIENT_LOGINS="$CLIENT_LOGINS $LOGIN"
    i=$((i + 1))
  done <<EOF_CHAP
$(grep -vE '^\s*#|^\s*$' "$CHAP")
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

add_client() {
  printf "Логин: "
  read LOGIN
  grep -q "^\"$LOGIN\"" "$CHAP" && echo "❌ Уже есть." && return
  PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
  echo "\"$LOGIN\" * $PASS *" >> "$CHAP"
  echo "✅ Добавлен: $LOGIN | $PASS"
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

  sed -i "/^\"$LOGIN\"\s\+\*/d" "$CHAP"
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
  sed -i "s|^\"$LOGIN\" * \S\+ \*|\"$LOGIN\" * $NEWPASS *|" "$CHAP"
  echo "  ✅ Новый пароль клиента \"$LOGIN\": $NEWPASS"
}

start_l2tp() {
  echo "[*] Запуск L2TP и IPsec..."
  systemctl start "$IPSEC_SERVICE"
  systemctl start "$L2TP_SERVICE"
  echo "✅ Запущено."
}

stop_l2tp() {
  echo "[*] Остановка L2TP и IPsec..."
  systemctl stop "$L2TP_SERVICE"
  systemctl stop "$IPSEC_SERVICE"
  echo "🛑 Остановлено."
}

restart_l2tp() {
  echo "[*] Перезапуск L2TP и IPsec..."
  systemctl restart "$IPSEC_SERVICE"
  systemctl restart "$L2TP_SERVICE"
  echo "🔄 Перезапущено."
}

while true; do
  echo
  print_status
  list_clients
  echo "===== Меню Atlas L2TP/IPsec ====="
  echo "1) Запустить сервер"
  echo "2) Остановить сервер"
  echo "3) Перезапустить сервер"
  echo "4) Добавить клиента"
  echo "5) Удалить клиента"
  echo "6) Сменить пароль клиента"
  echo "0) Выход"
  echo "==========================="
  printf "Выбор: "
  read x
  echo
  case $x in
    1) start_l2tp ;;
    2) stop_l2tp ;;
    3) restart_l2tp ;;
    4) add_client ;;
    5) delete_client ;;
    6) change_password ;;
    0) echo "Выход."; break ;;
    *) echo "❌ Неверный выбор. Попробуйте снова." ;;
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