#!/bin/bash

detect_installed_protocols() {
    local protocols=""
    [ -f /etc/atlastunnel/pptp.conf ] && protocols="$protocols pptp"
    [ -f /etc/atlastunnel/l2tp.conf ] && protocols="$protocols l2tp"
    [ -f /etc/atlastunnel/l2tp-ipsec.conf ] && protocols="$protocols l2tp-ipsec"
    [ -f /etc/atlastunnel/ikev2.conf ] && protocols="$protocols ikev2"
    [ -f /etc/atlastunnel/ikev2-ipsec.conf ] && protocols="$protocols ikev2-ipsec"
    [ -f /etc/atlastunnel/sstp.conf ] && protocols="$protocols sstp"
    [ -f /etc/atlastunnel/openvpn.conf ] && protocols="$protocols openvpn"
    echo "$protocols"
}

get_protocol_display_name() {
    local protocol="$1"
    case "$protocol" in
        pptp) echo "PPTP" ;;
        l2tp) echo "L2TP" ;;
        l2tp-ipsec) echo "L2TP/IPsec" ;;
        sstp) echo "SSTP" ;;
        ikev2) echo "IKEv2" ;;
        ikev2-ipsec) echo "IKEv2/IPsec" ;;
        openvpn) echo "OpenVPN" ;;
        *) echo "Unknown" ;;
    esac
}

get_service_name() {
    local protocol="$1"
    case "$protocol" in
        pptp) echo "pptpd" ;;
        l2tp|l2tp-ipsec) echo "xl2tpd" ;;
        sstp) echo "sstp-server" ;;
        ikev2|ikev2-ipsec) echo "strongswan-starter" ;;
        openvpn) echo "openvpn@server" ;;
        *) echo "unknown" ;;
    esac
}

get_chap_file() {
    local protocol="$1"
    case "$protocol" in
        pptp|l2tp|l2tp-ipsec|sstp) echo "/etc/ppp/chap-secrets" ;;
        ikev2|ikev2-ipsec) echo "/etc/ipsec.secrets" ;;
        openvpn) echo "/etc/openvpn/clients" ;;
        *) echo "" ;;
    esac
}

get_psk() {
    if [ -f "/etc/ipsec.secrets" ]; then
        grep -E "^\s*%any\s+%any\s*:\s*PSK" /etc/ipsec.secrets 2>/dev/null | \
            sed 's/.*PSK\s*"\([^"]*\)".*/\1/'
    fi
}

get_ca_cert_path() {
    if [ -f "/var/www/html/ca-cert.pem" ]; then
        echo "/var/www/html/ca-cert.pem"
    elif [ -f "/usr/share/atlastunnel/ca-cert.pem" ]; then
        echo "/usr/share/atlastunnel/ca-cert.pem"
    elif [ -f "/etc/ipsec.d/cacerts/ca-cert.pem" ]; then
        echo "/etc/ipsec.d/cacerts/ca-cert.pem"
    fi
}

print_protocol_status() {
    local protocol="$1"
    local display_name
    display_name=$(get_protocol_display_name "$protocol")
    local service_name
    service_name=$(get_service_name "$protocol")

    echo "[*] Статус $display_name сервера:"

    if systemctl is-active "$service_name" >/dev/null 2>&1; then
        echo "    $display_name: ✅ ЗАПУЩЕН"
    else
        echo "    $display_name: ❌ ОСТАНОВЛЕН"
    fi

    if [ "$protocol" = "l2tp-ipsec" ]; then
        if systemctl is-active strongswan-starter >/dev/null 2>&1; then
            echo "    IPsec:  ✅ ЗАПУЩЕН"
        else
            echo "    IPsec:  ❌ ОСТАНОВЛЕН"
        fi
    fi

    local server_ip
    server_ip=$(get_public_ip)
    echo "    IP сервера: $server_ip"

    if [ "$protocol" = "l2tp-ipsec" ]; then
        local psk
        psk=$(get_psk)
        if [ -n "$psk" ]; then
            echo "    PSK (ключ): $psk"
        fi
    fi

    if [ "$protocol" = "ikev2" ] || [ "$protocol" = "ikev2-ipsec" ]; then
        local ca_cert_path
        ca_cert_path=$(get_ca_cert_path)
        if [ -n "$ca_cert_path" ]; then
            echo "    CA-сертификат: $ca_cert_path"
            echo "    Установите CA-сертификат на клиент для подключения"
        fi
    fi
}

list_clients_for_protocol() {
    local protocol="$1"
    local chap_file
    chap_file=$(get_chap_file "$protocol")

    echo
    echo "[*] Список клиентов:"

    case "$protocol" in
        l2tp-ipsec)
            if [ ! -f "$chap_file" ] || ! grep -qvE '^\s*#|^\s*$' "$chap_file"; then
                echo "    Нет добавленных клиентов."
                return
            fi

            local psk
            psk=$(get_psk)
            if [ -z "$psk" ]; then
                psk="<не найден>"
            fi

            printf "\n  %-4s %-20s %-20s %-30s\n" "№" "ЛОГИН" "ПАРОЛЬ" "PSK"
            echo "  --------------------------------------------------------------------------------------"

            local i=1
            while IFS= read -r line; do
                local user pass
                user=$(echo "$line" | awk '{print $1}' | sed 's/"//g')
                pass=$(echo "$line" | awk '{print $3}' | sed 's/"//g')
                printf "  %-4s %-20s %-20s %-30s\n" "$i" "$user" "$pass" "$psk"
                i=$((i + 1))
            done < <(grep -vE '^\s*#|^\s*$' "$chap_file")
            echo
            ;;
        pptp|l2tp|sstp)
            if [ ! -f "$chap_file" ] || ! grep -qvE '^\s*#|^\s*$' "$chap_file"; then
                echo "    Нет добавленных клиентов."
                return
            fi

            printf "\n  %-4s %-20s %-20s\n" "№" "ЛОГИН" "ПАРОЛЬ"
            echo "  ---------------------------------------------------------"

            local i=1
            while IFS= read -r line; do
                local user pass
                user=$(echo "$line" | awk '{print $1}' | sed 's/"//g')
                pass=$(echo "$line" | awk '{print $3}' | sed 's/"//g')
                printf "  %-4s %-20s %-20s\n" "$i" "$user" "$pass"
                i=$((i + 1))
            done < <(grep -vE '^\s*#|^\s*$' "$chap_file")
            echo
            ;;
        ikev2|ikev2-ipsec)
            local users
            users=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$chap_file" 2>/dev/null || true)

            if [ -z "$users" ]; then
                echo "    Нет добавленных клиентов."
                return
            fi

            local ca_cert_path
            ca_cert_path=$(get_ca_cert_path)
            if [ -z "$ca_cert_path" ]; then
                ca_cert_path="<не найден>"
            fi

            printf "\n  %-4s %-20s %-20s %-40s\n" "№" "ЛОГИН" "ПАРОЛЬ" "CA-СЕРТИФИКАТ"
            echo "  ----------------------------------------------------------------------------------------------"

            local i=1
            echo "$users" | while IFS= read -r line; do
                local login pass
                login=$(echo "$line" | awk '{print $1}')
                pass=$(echo "$line" | awk -F'"' '{print $2}')
                printf "  %-4s %-20s %-20s %-40s\n" "$i" "$login" "$pass" "$ca_cert_path"
                i=$((i + 1))
            done
            echo
            ;;
        openvpn)
            echo "    Список клиентов OpenVPN пока не поддерживается"
            echo
            ;;
    esac
}

add_client_to_protocol() {
    local protocol="$1"
    local chap_file
    chap_file=$(get_chap_file "$protocol")

    echo "[*] Добавление клиента..."
    printf "  Введите логин: "
    read -r login

    if [ -z "$login" ] || [ ${#login} -lt 3 ]; then
        echo "  ❌ Логин должен содержать минимум 3 символа."
        return 1
    fi

    if ! echo "$login" | grep -qE '^[a-zA-Z0-9_-]+$'; then
        echo "  ❌ Логин может содержать только буквы, цифры, дефис и подчеркивание."
        return 1
    fi

    local password
    password=$(rand_pw)

    case "$protocol" in
        pptp)
            if grep -qE "^\"?${login}\"?[[:space:]]+pptpd[[:space:]]" "$chap_file"; then
                echo "  ❌ Клиент с таким логином уже существует."
                return 1
            fi
            echo "$login pptpd $password *" >> "$chap_file"
            ;;
        l2tp|l2tp-ipsec)
            if grep -qE "^\"${login}\"[[:space:]]+\*[[:space:]]" "$chap_file"; then
                echo "  ❌ Клиент с таким логином уже существует."
                return 1
            fi
            echo "\"$login\" * $password *" >> "$chap_file"
            ;;
        sstp)
            if grep -qE "^\"${login}\"[[:space:]]+sstp[[:space:]]" "$chap_file"; then
                echo "  ❌ Клиент с таким логином уже существует."
                return 1
            fi
            echo "\"$login\" sstp \"$password\" *" >> "$chap_file"
            ;;
        ikev2|ikev2-ipsec)
            if grep -qE "^${login}[[:space:]]+:[[:space:]]+EAP" "$chap_file"; then
                echo "  ❌ Клиент с таким логином уже существует."
                return 1
            fi
            echo "$login : EAP \"$password\"" >> "$chap_file"
            systemctl reload strongswan-starter >/dev/null 2>&1
            ;;
        openvpn)
            echo "  ❌ Добавление клиентов OpenVPN пока не поддерживается"
            return 1
            ;;
    esac

    echo "  ✅ Клиент добавлен."
    echo "  🔐 Логин: $login"
    echo "  🔐 Пароль: $password"
}

delete_client_from_protocol() {
    local protocol="$1"
    local chap_file
    chap_file=$(get_chap_file "$protocol")

    echo "[*] Удаление клиента..."
    printf "  Введите номер клиента для удаления: "
    read -r num

    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        echo "  ❌ Неверный формат номера."
        return 1
    fi

    local login
    case "$protocol" in
        pptp|l2tp|l2tp-ipsec|sstp)
            local i=1
            while IFS= read -r line; do
                if [ "$i" -eq "$num" ]; then
                    login=$(echo "$line" | awk '{print $1}' | sed 's/"//g')
                    break
                fi
                i=$((i + 1))
            done < <(grep -vE '^\s*#|^\s*$' "$chap_file")

            if [ -z "$login" ]; then
                echo "  ❌ Неверный номер клиента."
                return 1
            fi

            sed -i "/^\"*${login}\"*/d" "$chap_file"
            ;;
        ikev2|ikev2-ipsec)
            local i=1
            local users
            users=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$chap_file" | awk '{print $1}')

            for l in $users; do
                if [ "$i" -eq "$num" ]; then
                    login="$l"
                    break
                fi
                i=$((i + 1))
            done

            if [ -z "$login" ]; then
                echo "  ❌ Неверный номер клиента."
                return 1
            fi

            sed -i "/^${login} : EAP/d" "$chap_file"
            systemctl reload strongswan-starter >/dev/null 2>&1
            ;;
        openvpn)
            echo "  ❌ Удаление клиентов OpenVPN пока не поддерживается"
            return 1
            ;;
    esac

    echo "  ✅ Клиент \"$login\" удалён."
}

change_client_password() {
    local protocol="$1"
    local chap_file
    chap_file=$(get_chap_file "$protocol")

    echo "[*] Смена пароля клиента..."
    printf "  Введите номер клиента: "
    read -r num

    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        echo "  ❌ Неверный формат номера."
        return 1
    fi

    local login password
    password=$(rand_pw)

    case "$protocol" in
        pptp|l2tp|l2tp-ipsec|sstp)
            local i=1
            while IFS= read -r line; do
                if [ "$i" -eq "$num" ]; then
                    login=$(echo "$line" | awk '{print $1}' | sed 's/"//g')
                    break
                fi
                i=$((i + 1))
            done < <(grep -vE '^\s*#|^\s*$' "$chap_file")

            if [ -z "$login" ]; then
                echo "  ❌ Неверный номер клиента."
                return 1
            fi

            sed -i "s|^\"*${login}\"* .* .* \*|\"$login\" * $password *|" "$chap_file"
            ;;
        ikev2|ikev2-ipsec)
            local i=1
            local users
            users=$(grep -E '^\s*[^:]+\s*:\s*EAP' "$chap_file" | awk '{print $1}')

            for l in $users; do
                if [ "$i" -eq "$num" ]; then
                    login="$l"
                    break
                fi
                i=$((i + 1))
            done

            if [ -z "$login" ]; then
                echo "  ❌ Неверный номер клиента."
                return 1
            fi

            sed -i "s|^${login} : EAP \".*\"|${login} : EAP \"$password\"|" "$chap_file"
            systemctl reload strongswan-starter >/dev/null 2>&1
            ;;
        openvpn)
            echo "  ❌ Смена пароля OpenVPN клиентов пока не поддерживается"
            return 1
            ;;
    esac

    echo "  ✅ Новый пароль клиента \"$login\": $password"
}

start_protocol_service() {
    local protocol="$1"
    local service_name
    service_name=$(get_service_name "$protocol")

    echo "[*] Запуск $protocol..."

    if [ "$protocol" = "l2tp-ipsec" ]; then
        systemctl start strongswan-starter
        systemctl start xl2tpd
    else
        systemctl start "$service_name"
    fi

    echo "✅ Запущено."
}

stop_protocol_service() {
    local protocol="$1"
    local service_name
    service_name=$(get_service_name "$protocol")

    echo "[*] Остановка $protocol..."

    if [ "$protocol" = "l2tp-ipsec" ]; then
        systemctl stop xl2tpd
        systemctl stop strongswan-starter
    else
        systemctl stop "$service_name"
    fi

    echo "🛑 Остановлено."
}

restart_protocol_service() {
    local protocol="$1"
    local service_name
    service_name=$(get_service_name "$protocol")

    echo "[*] Перезапуск $protocol..."

    if [ "$protocol" = "l2tp-ipsec" ]; then
        systemctl restart strongswan-starter
        systemctl restart xl2tpd
    else
        systemctl restart "$service_name"
    fi

    echo "🔄 Перезапущено."
}

show_ca_cert_instructions() {
    echo ""
    echo "============================================="
    echo "  Инструкции по установке CA-сертификата"
    echo "============================================="
    echo ""
    echo "1. Скопируйте CA-сертификат с сервера на устройство:"

    local ca_cert_path
    ca_cert_path=$(get_ca_cert_path)

    if [ -n "$ca_cert_path" ]; then
        echo "   Путь на сервере: $ca_cert_path"
    fi

    echo ""
    echo "2. Установите сертификат на устройство:"
    echo ""
    echo "   Windows:"
    echo "   - Откройте файл ca-cert.pem"
    echo "   - Установить сертификат → Локальный компьютер"
    echo "   - Поместите сертификат в: Доверенные корневые центры сертификации"
    echo ""
    echo "   macOS/iOS:"
    echo "   - Откройте файл ca-cert.pem"
    echo "   - Добавьте в Связку ключей"
    echo "   - Настройки → Основные → Профили VPN → Доверять сертификату"
    echo ""
    echo "   Android:"
    echo "   - Настройки → Безопасность → Установить из хранилища"
    echo "   - Выберите файл ca-cert.pem"
    echo "   - Назначьте имя и используйте для VPN"
    echo ""
    echo "   Linux:"
    echo "   - sudo cp ca-cert.pem /usr/local/share/ca-certificates/vpn-ca.crt"
    echo "   - sudo update-ca-certificates"
    echo ""
    echo "3. Настройте VPN-подключение с параметрами сервера"
    echo ""
    echo "============================================="
}
