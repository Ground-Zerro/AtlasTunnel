#!/bin/bash
set -e

VPN_USER="vpnuser"
VPN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
VPN_LOCAL_IP="10.30.40.1"
VPN_REMOTE_IP_RANGE="10.30.40.10"
VPN_PUBLIC_IP=$(curl -s https://ipinfo.io/ip)

echo "[*] Установка необходимых пакетов..."
apt-get update
apt-get install -y sstp-server ppp iptables-persistent curl

echo "[*] Настройка SSTP-сервера..."

cat > /etc/sstp-server/sstp-server.conf <<EOF
cert=/etc/sstp-server/cert.pem
key=/etc/sstp-server/key.pem
listen=0.0.0.0:443
pppd=/usr/sbin/pppd
pppd_options=/etc/ppp/sstp-options
EOF

echo "[*] Генерация самоподписанного SSL-сертификата..."
mkdir -p /etc/sstp-server
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/sstp-server/key.pem -out /etc/sstp-server/cert.pem \
  -subj "/CN=$VPN_PUBLIC_IP"

chmod 600 /etc/sstp-server/*.pem

echo "[*] Настройка PPP для SSTP..."
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
ms-dns 8.8.8.8
ms-dns 1.1.1.1
EOF

echo "[*] Добавление пользователя..."
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" sstp "$VPN_PASS" *
EOF

echo "[*] Включение IP маршрутизации..."
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1

echo "[*] Настройка iptables..."
WAN_IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')
iptables -t nat -C POSTROUTING -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -j MASQUERADE

iptables -C FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i ppp+ -o "$WAN_IFACE" -j ACCEPT

iptables -C FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$WAN_IFACE" -o ppp+ -j ACCEPT

netfilter-persistent save

echo "[*] Активация и запуск сервиса SSTP..."
systemctl enable sstp-server
systemctl restart sstp-server

echo "[*] Установка менеджера клиентов Atlas..."
# менеджер почти не изменился, кроме имени сервиса и исключения PSK
mkdir -p /etc/atlastunnel
cp /etc/ppp/chap-secrets /etc/atlastunnel/chap-secrets.backup

cat << 'EOF' > /etc/atlastunnel/manager.sh
#!/bin/bash

CHAP="/etc/ppp/chap-secrets"
SSTP_SERVICE="sstp-server"
CLIENT_LOGINS=""

get_public_ip() {
  curl -s https://ipinfo.io/ip
}

print_status() {
  echo "[*] Статус SSTP-сервера:"
  systemctl is-active "$SSTP_SERVICE" >/dev/null 2>&1 && echo "    SSTP: ✅ ЗАПУЩЕН" || echo "    SSTP: ❌ ОСТАНОВЛЕН"
  echo "    IP сервера: $(get_public_ip)"
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
  echo "\"$LOGIN\" sstp \"$PASS\" *" >> "$CHAP"
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

  sed -i "/^\"$LOGIN\" sstp/d" "$CHAP"
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
  sed -i "s|^\"$LOGIN\" sstp \".*\"|\"$LOGIN\" sstp \"$NEWPASS\"|" "$CHAP"
  echo "  ✅ Новый пароль клиента \"$LOGIN\": $NEWPASS"
}

start_sstp() {
  systemctl start "$SSTP_SERVICE"
  echo "✅ Запущен."
}

stop_sstp() {
  systemctl stop "$SSTP_SERVICE"
  echo "🛑 Остановлен."
}

restart_sstp() {
  systemctl restart "$SSTP_SERVICE"
  echo "🔄 Перезапущен."
}

while true; do
  echo
  print_status
  list_clients
  echo "===== Меню Atlas SSTP ====="
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
    1) start_sstp ;;
    2) stop_sstp ;;
    3) restart_sstp ;;
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
echo "📡  Подключение к SSTP VPN:"
echo "    Сервер IP : $VPN_PUBLIC_IP"
echo "    Логин     : $VPN_USER"
echo "    Пароль    : $VPN_PASS"
echo
echo "⚙ Менеджер клиентов: команда 'atlas'"