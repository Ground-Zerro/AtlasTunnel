#!/bin/sh
set -e

VPN_USER="vpnuser"
VPN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
VPN_LOCAL_SUBNET="10.40.50.0/24"
VPN_DNS1="8.8.8.8"
VPN_DNS2="1.1.1.1"
VPN_PUBLIC_IP=$(curl -s https://ipinfo.io/ip)

echo "[*] Установка необходимых пакетов..."
apt-get update
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins iptables-persistent curl

echo "[*] Генерация сертификатов для IKEv2..."
mkdir -p /etc/ipsec.d/{cacerts,certs,private}
chmod 700 /etc/ipsec.d/private

# Генерация CA
ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
    --type rsa --dn "CN=VPN Root CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem

# Генерация серверного сертификата
ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa | \
    ipsec pki --issue --lifetime 1825 \
    --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
    --cakey /etc/ipsec.d/private/ca-key.pem \
    --dn "CN=$VPN_PUBLIC_IP" --san "$VPN_PUBLIC_IP" \
    --flag serverAuth --flag ikeIntermediate --outform pem \
    > /etc/ipsec.d/certs/server-cert.pem

echo "[*] Настройка IKEv2 без IPsec шифрования..."
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

    # Параметры IKE (управляющий канал) - должен быть зашифрован
    ike=aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,3des-sha1-modp1024!

    # ESP без шифрования (null cipher) - только аутентификация
    # Важно: добавляем варианты с разными хэшами для совместимости
    esp=null-sha256-modp2048,null-sha1-modp2048,null-sha256,null-sha1,null-md5!

    # Мёртвый пир обнаружение
    dpdaction=clear
    dpddelay=300s
    rekey=no

    # Левая сторона (сервер)
    left=%any
    leftid=$VPN_PUBLIC_IP
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftauth=pubkey

    # Правая сторона (клиенты)
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=$VPN_LOCAL_SUBNET
    rightdns=$VPN_DNS1,$VPN_DNS2
    rightsendcert=never

    # EAP аутентификация
    eap_identity=%identity

    # Дополнительные параметры для совместимости
    mobike=no
EOF

cat > /etc/ipsec.secrets <<EOF
: RSA "server-key.pem"
$VPN_USER : EAP "$VPN_PASS"
EOF

chmod 600 /etc/ipsec.secrets

echo "[*] Включение IP маршрутизации..."
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
grep -q "^net.ipv4.conf.all.accept_redirects=0" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
grep -q "^net.ipv4.conf.all.send_redirects=0" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

echo "[*] Определение внешнего интерфейса..."
WAN_IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1); exit}')
echo "    Используется интерфейс: $WAN_IFACE"

echo "[*] Настройка iptables..."
# NAT для VPN клиентов (без политики ipsec, так как шифрование отключено)
iptables -t nat -C POSTROUTING -s $VPN_LOCAL_SUBNET -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s $VPN_LOCAL_SUBNET -o "$WAN_IFACE" -j MASQUERADE

# Форвардинг
iptables -C FORWARD -s $VPN_LOCAL_SUBNET -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s $VPN_LOCAL_SUBNET -j ACCEPT

iptables -C FORWARD -d $VPN_LOCAL_SUBNET -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -d $VPN_LOCAL_SUBNET -j ACCEPT

# Разрешаем IKEv2 трафик
iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p udp --dport 500 -j ACCEPT

iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

iptables -C INPUT -p esp -j ACCEPT 2>/dev/null || \
iptables -A INPUT -p esp -j ACCEPT

netfilter-persistent save
systemctl enable netfilter-persistent

echo "[*] Активация сервисов..."
systemctl daemon-reload
systemctl enable strongswan-starter
systemctl restart strongswan-starter

echo "[*] Установка менеджера клиентов Atlas..."
mkdir -p /etc/atlastunnel
cp /etc/ipsec.secrets /etc/atlastunnel/ipsec.secrets.backup
cat << 'EOF' > /etc/atlastunnel/manager.sh
#!/bin/sh

IPSEC_SECRETS="/etc/ipsec.secrets"
IPSEC_SERVICE="strongswan-starter"
CA_CERT="/etc/ipsec.d/cacerts/ca-cert.pem"
CLIENT_LOGINS=""

get_public_ip() {
  curl -s https://ipinfo.io/ip
}

print_status() {
  echo "[*] Статус IKEv2 сервера:"
  systemctl is-active "$IPSEC_SERVICE" >/dev/null 2>&1 && echo "    IKEv2: ✅ ЗАПУЩЕН" || echo "    IKEv2: ❌ ОСТАНОВЛЕН"
  echo "    IP сервера: $(get_public_ip)"
}

list_clients() {
  echo
  echo "[*] Клиенты:"
  CLIENT_LOGINS=""

  # Получаем список пользователей (пропускаем строки с RSA)
  USERS=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$IPSEC_SECRETS" 2>/dev/null || true)

  if [ -z "$USERS" ]; then
    echo "    Нет добавленных клиентов."
    return
  fi

  printf "\n  %-4s %-20s %-20s\n" "№" "ЛОГИН" "ПАРОЛЬ"
  echo "  ---------------------------------------------------------"
  i=1
  echo "$USERS" | while IFS= read -r line; do
    LOGIN=$(echo "$line" | awk '{print $1}')
    PASS=$(echo "$line" | awk -F'"' '{print $2}')
    printf "  %-4s %-20s %-20s\n" "$i" "$LOGIN" "$PASS"
    CLIENT_LOGINS="$CLIENT_LOGINS $LOGIN"
    i=$((i + 1))
  done

  # Сохраняем логины для использования в других функциях
  CLIENT_LOGINS=$(echo "$USERS" | awk '{print $1}' | tr '\n' ' ')
  echo
}

get_login_by_index() {
  INDEX=$1
  i=1
  USERS=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$IPSEC_SECRETS" | awk '{print $1}')
  for login in $USERS; do
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
  grep -q "^$LOGIN : EAP" "$IPSEC_SECRETS" && echo "❌ Уже есть." && return
  PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c8)
  echo "$LOGIN : EAP \"$PASS\"" >> "$IPSEC_SECRETS"
  systemctl reload "$IPSEC_SERVICE"
  echo "✅ Добавлен: $LOGIN | $PASS"
}

delete_client() {
  echo "[*] Удаление клиента..."
  USERS=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$IPSEC_SECRETS" 2>/dev/null || true)

  if [ -z "$USERS" ]; then
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

  sed -i "/^$LOGIN : EAP/d" "$IPSEC_SECRETS"
  systemctl reload "$IPSEC_SERVICE"
  echo "  ✅ Клиент \"$LOGIN\" удалён."
}

change_password() {
  echo "[*] Смена пароля клиента..."
  USERS=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$IPSEC_SECRETS" 2>/dev/null || true)

  if [ -z "$USERS" ]; then
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
  sed -i "s|^$LOGIN : EAP \".*\"|$LOGIN : EAP \"$NEWPASS\"|" "$IPSEC_SECRETS"
  systemctl reload "$IPSEC_SERVICE"
  echo "  ✅ Новый пароль клиента \"$LOGIN\": $NEWPASS"
}

export_ca_cert() {
  echo "[*] Экспорт CA-сертификата..."
  if [ ! -f "$CA_CERT" ]; then
    echo "  ❌ CA-сертификат не найден."
    return
  fi

  cat "$CA_CERT"
  echo
  echo "  ✅ Сохраните этот сертификат на клиентском устройстве."
  echo "  📱 Для импорта на Android/iOS сохраните в файл ca-cert.pem"
}

start_ikev2() {
  echo "[*] Запуск IKEv2..."
  systemctl start "$IPSEC_SERVICE"
  echo "✅ Запущено."
}

stop_ikev2() {
  echo "[*] Остановка IKEv2..."
  systemctl stop "$IPSEC_SERVICE"
  echo "🛑 Остановлено."
}

restart_ikev2() {
  echo "[*] Перезапуск IKEv2..."
  systemctl restart "$IPSEC_SERVICE"
  echo "🔄 Перезапущено."
}

show_connections() {
  echo "[*] Активные подключения:"
  ipsec status
  echo
  echo "[*] Последние 20 строк логов:"
  journalctl -u strongswan-starter -n 20 --no-pager
}

show_detailed_status() {
  echo "[*] Детальный статус strongSwan:"
  ipsec statusall
}

while true; do
  echo
  print_status
  list_clients
  echo "===== Меню Atlas IKEv2 ====="
  echo "1) Запустить сервер"
  echo "2) Остановить сервер"
  echo "3) Перезапустить сервер"
  echo "4) Добавить клиента"
  echo "5) Удалить клиента"
  echo "6) Сменить пароль клиента"
  echo "7) Экспорт CA-сертификата"
  echo "8) Показать активные подключения"
  echo "9) Детальный статус (диагностика)"
  echo "0) Выход"
  echo "============================"
  printf "Выбор: "
  read x
  echo
  case $x in
    1) start_ikev2 ;;
    2) stop_ikev2 ;;
    3) restart_ikev2 ;;
    4) add_client ;;
    5) delete_client ;;
    6) change_password ;;
    7) export_ca_cert ;;
    8) show_connections ;;
    9) show_detailed_status ;;
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
echo
echo "⚠️  ВНИМАНИЕ: Этот сервер использует IKEv2 БЕЗ IPsec шифрования (null cipher)."
echo "    Подходит только для максимальной скорости или локальных сетей."
echo
echo "📱  Для подключения клиентов необходимо установить CA-сертификат."
echo "    Экспортируйте его через менеджер: atlas -> 7"
echo
echo "⚙ Менеджер клиентов: команда 'atlas'"
