#!/bin/bash
set -e

readonly VERSION="4.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/lib/lib-utils.sh"
source "${SCRIPT_DIR}/lib/lib-system.sh"
source "${SCRIPT_DIR}/lib/lib-protocols.sh"
source "${SCRIPT_DIR}/lib/lib-manager.sh"

show_banner() {
    echo ""
    echo "============================================="
    echo "  AtlasTunnel v${VERSION} - Unified VPN"
    echo "============================================="
    echo ""
}

select_protocols() {
    echo "Выберите протоколы для установки (можно несколько):"
    echo ""
    echo "  1) PPTP           - Максимальная скорость"
    echo "  2) L2TP           - Без шифрования"
    echo "  3) L2TP/IPsec     - С шифрованием IPsec"
    echo "  4) IKEv2          - Без шифрования (null cipher)"
    echo "  5) IKEv2/IPsec    - С шифрованием IPsec"
    echo "  6) SSTP           - SSL-based (порт 443)"
    echo "  7) OpenVPN        - Универсальное решение"
    echo "  8) ВСЕ ПРОТОКОЛЫ  - Установить все (кроме IKEv2 - будет IKEv2/IPsec)"
    echo ""

    read -rp "Введите номера через пробел (например: 1 3 5): " choices

    SELECTED_PROTOCOLS=()
    for choice in $choices; do
        case "$choice" in
            1) SELECTED_PROTOCOLS+=("pptp") ;;
            2) SELECTED_PROTOCOLS+=("l2tp") ;;
            3) SELECTED_PROTOCOLS+=("l2tp-ipsec") ;;
            4) SELECTED_PROTOCOLS+=("ikev2") ;;
            5) SELECTED_PROTOCOLS+=("ikev2-ipsec") ;;
            6) SELECTED_PROTOCOLS+=("sstp") ;;
            7) SELECTED_PROTOCOLS+=("openvpn") ;;
            8) SELECTED_PROTOCOLS=("pptp" "l2tp" "l2tp-ipsec" "ikev2-ipsec" "sstp" "openvpn") ;;
            *) warn "Неверный выбор: $choice" ;;
        esac
    done

    [ ${#SELECTED_PROTOCOLS[@]} -eq 0 ] && die "Не выбраны протоколы для установки"

    if [[ " ${SELECTED_PROTOCOLS[*]} " =~ " ikev2 " ]] && [[ " ${SELECTED_PROTOCOLS[*]} " =~ " ikev2-ipsec " ]]; then
        echo ""
        echo "============================================="
        echo "  ОШИБКА: Несовместимые протоколы"
        echo "============================================="
        echo ""
        echo "IKEv2 и IKEv2/IPsec нельзя установить одновременно."
        echo ""
        echo "Причина:"
        echo "  - Оба используют один файл конфигурации /etc/ipsec.conf"
        echo "  - Одинаковые порты (UDP 500, 4500)"
        echo "  - Один демон strongSwan не может работать в двух режимах"
        echo ""
        echo "Выберите один из них:"
        echo "  - IKEv2 (без IPsec) - для максимальной скорости"
        echo "  - IKEv2/IPsec - для защищенного соединения"
        echo ""
        echo "============================================="
        echo ""
        select_protocols
        return
    fi

    log "Выбраны протоколы: ${SELECTED_PROTOCOLS[*]}"
}

install_selected_protocols() {
    local vpn_user="vpnuser"
    local vpn_pass vpn_psk

    vpn_pass=$(rand_pw)
    vpn_psk=$(rand_pw)

    local ikev2_installed=false
    local ikev2_ipsec_installed=false
    local ikev2_selected=false
    local ikev2_ipsec_selected=false

    [ -f "/etc/atlastunnel/ikev2.conf" ] && ikev2_installed=true
    [ -f "/etc/atlastunnel/ikev2-ipsec.conf" ] && ikev2_ipsec_installed=true

    [[ " ${SELECTED_PROTOCOLS[*]} " =~ " ikev2 " ]] && ikev2_selected=true
    [[ " ${SELECTED_PROTOCOLS[*]} " =~ " ikev2-ipsec " ]] && ikev2_ipsec_selected=true

    if ($ikev2_installed && $ikev2_ipsec_selected) || ($ikev2_ipsec_installed && $ikev2_selected); then
        echo ""
        echo "============================================="
        echo "  ВНИМАНИЕ: Конфликт протоколов"
        echo "============================================="
        echo ""

        if $ikev2_installed && $ikev2_ipsec_selected; then
            echo "Обнаружено: IKEv2 (без IPsec) уже установлен"
            echo "Попытка установить: IKEv2/IPsec"
        else
            echo "Обнаружено: IKEv2/IPsec уже установлен"
            echo "Попытка установить: IKEv2 (без IPsec)"
        fi

        echo ""
        echo "Эти протоколы несовместимы:"
        echo "  - Используют один файл /etc/ipsec.conf"
        echo "  - Одинаковые порты (UDP 500, 4500)"
        echo "  - Новый протокол ЗАМЕНИТ существующий"
        echo ""
        echo "Последствия замены:"
        echo "  - Текущая конфигурация будет перезаписана"
        echo "  - Пользователи IKEv2 будут сохранены"
        echo "  - Потребуется перенастройка клиентов"
        echo ""
        echo "============================================="
        echo ""

        read -rp "Введите YES для подтверждения замены: " confirmation

        if [ "$confirmation" != "YES" ]; then
            echo ""
            echo "Установка отменена."
            exit 1
        fi

        echo ""
        log "Подтверждена замена протокола IKEv2..."
    fi

    for protocol in "${SELECTED_PROTOCOLS[@]}"; do
        case "$protocol" in
            pptp) install_pptp "$vpn_user" "$vpn_pass" "$WAN_IFACE" ;;
            l2tp) install_l2tp "$vpn_user" "$vpn_pass" "$WAN_IFACE" ;;
            l2tp-ipsec) install_l2tp_ipsec "$vpn_user" "$vpn_pass" "$vpn_psk" "$WAN_IFACE" ;;
            ikev2) install_ikev2 "$vpn_user" "$vpn_pass" "$WAN_IFACE" ;;
            ikev2-ipsec) install_ikev2_ipsec "$vpn_user" "$vpn_pass" "$WAN_IFACE" ;;
            sstp) install_sstp "$vpn_user" "$vpn_pass" "$WAN_IFACE" ;;
            openvpn) install_openvpn "$vpn_user" "$vpn_pass" "$WAN_IFACE" ;;
        esac
    done

    cat > /etc/atlastunnel/credentials.conf <<EOF
VPN_USER=$vpn_user
VPN_PASS=$vpn_pass
VPN_PSK=$vpn_psk
EOF
    chmod 600 /etc/atlastunnel/credentials.conf
}

install_universal_manager() {
    log "Установка универсального менеджера..."

    mkdir -p /etc/atlastunnel/lib
    cp "${SCRIPT_DIR}/lib"/*.sh /etc/atlastunnel/lib/
    cp "${SCRIPT_DIR}/atlas-manager.sh" /usr/local/bin/atlas
    chmod +x /usr/local/bin/atlas

    ok "Менеджер установлен: команда 'atlas'"
}

show_summary() {
    local public_ip
    public_ip=$(get_public_ip)

    source /etc/atlastunnel/credentials.conf

    echo ""
    echo "============================================="
    echo "  Установка завершена!"
    echo "============================================="
    echo ""
    echo "IP сервера: $public_ip"
    echo "Логин по умолчанию: $VPN_USER"
    echo "Пароль: $VPN_PASS"

    if [[ " ${SELECTED_PROTOCOLS[*]} " =~ " l2tp-ipsec " ]]; then
        echo "PSK (для L2TP/IPsec): $VPN_PSK"
    fi

    if [[ " ${SELECTED_PROTOCOLS[*]} " =~ " ikev2 " ]] || [[ " ${SELECTED_PROTOCOLS[*]} " =~ " ikev2-ipsec " ]]; then
        local ca_cert_path
        if [ -f "/var/www/html/ca-cert.pem" ]; then
            ca_cert_path="/var/www/html/ca-cert.pem"
        elif [ -f "/usr/share/atlastunnel/ca-cert.pem" ]; then
            ca_cert_path="/usr/share/atlastunnel/ca-cert.pem"
        elif [ -f "/etc/ipsec.d/cacerts/ca-cert.pem" ]; then
            ca_cert_path="/etc/ipsec.d/cacerts/ca-cert.pem"
        fi

        if [ -n "$ca_cert_path" ]; then
            echo "CA-сертификат (для IKEv2/IKEv2-IPsec): $ca_cert_path"
            echo ""
            echo "ВАЖНО: Установите CA-сертификат на клиент перед подключением!"
            echo "Скопируйте файл $ca_cert_path на устройство клиента"
        fi
    fi

    echo ""
    echo "Установленные протоколы:"
    for protocol in "${SELECTED_PROTOCOLS[@]}"; do
        local display_name
        display_name=$(get_protocol_display_name "$protocol")
        echo "  - $display_name"
    done

    echo ""
    echo "Для управления используйте команду: atlas"
    echo "============================================="
}

main() {
    check_root
    check_distro

    show_banner

    existing_protocols=$(detect_installed_protocols)
    if [ -n "$existing_protocols" ]; then
        warn "Обнаружены уже установленные протоколы: $existing_protocols"
        echo "Вы можете добавить дополнительные протоколы или переустановить существующие"
        echo ""
    fi

    select_protocols

    if [ -z "$existing_protocols" ]; then
        install_base_packages
        configure_sysctl

        WAN_IFACE=$(detect_wan_interface)
        log "Обнаружен внешний интерфейс: $WAN_IFACE"

        mkdir -p /etc/atlastunnel
        echo "WAN_IFACE=$WAN_IFACE" > /etc/atlastunnel/network.conf
    else
        source /etc/atlastunnel/network.conf
    fi

    install_selected_protocols
    install_universal_manager

    netfilter-persistent save >/dev/null 2>&1

    show_summary
}

main "$@"
