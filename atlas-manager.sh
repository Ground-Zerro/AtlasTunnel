#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -d "/etc/atlastunnel" ]; then
    LIB_DIR="/etc/atlastunnel/lib"
else
    LIB_DIR="${SCRIPT_DIR}/lib"
fi

source "${LIB_DIR}/lib-utils.sh"
source "${LIB_DIR}/lib-manager.sh"

single_protocol_menu() {
    local protocol="$1"
    local display_name
    display_name=$(get_protocol_display_name "$protocol")

    while true; do
        echo ""
        print_protocol_status "$protocol"
        list_clients_for_protocol "$protocol"
        echo ""
        echo "===== Atlas $display_name Manager ====="
        echo "1) Запустить сервер"
        echo "2) Остановить сервер"
        echo "3) Перезапустить сервер"
        echo "4) Добавить клиента"
        echo "5) Удалить клиента"
        echo "6) Сменить пароль клиента"

        if [ "$protocol" = "ikev2" ] || [ "$protocol" = "ikev2-ipsec" ]; then
            echo "7) Показать инструкции по установке CA-сертификата"
        fi

        echo "0) Выход"
        echo "======================================="

        read -rp "Выбор: " choice

        case "$choice" in
            1) start_protocol_service "$protocol" ;;
            2) stop_protocol_service "$protocol" ;;
            3) restart_protocol_service "$protocol" ;;
            4) add_client_to_protocol "$protocol" ;;
            5) delete_client_from_protocol "$protocol" ;;
            6) change_client_password "$protocol" ;;
            7)
                if [ "$protocol" = "ikev2" ] || [ "$protocol" = "ikev2-ipsec" ]; then
                    show_ca_cert_instructions
                else
                    warn "Неверный выбор"
                fi
                ;;
            0) exit 0 ;;
            *) warn "Неверный выбор" ;;
        esac
    done
}

multi_protocol_menu() {
    while true; do
        local protocols
        protocols=$(detect_installed_protocols)
        local protocols_array=($protocols)

        echo ""
        echo "===== Atlas Multi-Protocol Manager ====="
        echo ""
        echo "Установленные протоколы:"

        local i=1
        for proto in "${protocols_array[@]}"; do
            local display_name
            display_name=$(get_protocol_display_name "$proto")
            local service_name
            service_name=$(get_service_name "$proto")

            local status="ОСТАНОВЛЕН"
            if systemctl is-active "$service_name" >/dev/null 2>&1; then
                status="ЗАПУЩЕН"
            fi

            echo "  $i) $display_name [$status]"
            ((i++))
        done

        echo ""
        echo "  A) Показать статус всех"
        echo "  S) Запустить все"
        echo "  T) Остановить все"
        echo "  R) Перезапустить все"
        echo "  0) Выход"
        echo "=========================================="

        read -rp "Выберите протокол или действие: " choice

        case "$choice" in
            [1-9])
                local idx=$((choice - 1))
                if [ $idx -lt ${#protocols_array[@]} ]; then
                    single_protocol_menu "${protocols_array[$idx]}"
                else
                    warn "Неверный выбор"
                fi
                ;;
            A|a) show_all_status "${protocols_array[@]}" ;;
            S|s) start_all_protocols "${protocols_array[@]}" ;;
            T|t) stop_all_protocols "${protocols_array[@]}" ;;
            R|r) restart_all_protocols "${protocols_array[@]}" ;;
            0) exit 0 ;;
            *) warn "Неверный выбор" ;;
        esac
    done
}

show_all_status() {
    local protocols=("$@")
    echo ""
    echo "===== Статус всех протоколов ====="
    for proto in "${protocols[@]}"; do
        print_protocol_status "$proto"
        echo ""
    done
}

start_all_protocols() {
    local protocols=("$@")
    for proto in "${protocols[@]}"; do
        start_protocol_service "$proto"
    done
}

stop_all_protocols() {
    local protocols=("$@")
    for proto in "${protocols[@]}"; do
        stop_protocol_service "$proto"
    done
}

restart_all_protocols() {
    local protocols=("$@")
    for proto in "${protocols[@]}"; do
        restart_protocol_service "$proto"
    done
}

main_menu() {
    local protocols
    protocols=$(detect_installed_protocols)

    [ -z "$protocols" ] && die "Протоколы VPN не установлены. Запустите atlastunnel.sh"

    local protocols_array=($protocols)
    local protocol_count=${#protocols_array[@]}

    if [ "$protocol_count" -eq 1 ]; then
        single_protocol_menu "${protocols_array[0]}"
    else
        multi_protocol_menu
    fi
}

main_menu
