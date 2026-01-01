#!/bin/bash

set -e

readonly GITHUB_REPO="Ground-Zerro/AtlasTunnel"
readonly GITHUB_BRANCH="main"
readonly GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"

readonly TEMP_DIR="/tmp/atlastunnel-install-$$"

log() { echo "[*] $*"; }
ok()  { echo "[✓] $*"; }
err() { echo "[✗] $*" >&2; }
die() { err "$*"; exit 1; }

check_root() {
    [ "$(id -u)" -eq 0 ] || die "Требуется root доступ. Запустите с sudo или от root."
}

check_distro() {
    local os_id
    os_id=$(lsb_release -is 2>/dev/null | tr '[:upper:]' '[:lower:]')
    [[ "$os_id" == "ubuntu" ]] || die "Поддерживается только Ubuntu"
}

download_file() {
    local url="$1"
    local dest="$2"

    if ! curl -fsSL "$url" -o "$dest"; then
        die "Не удалось загрузить $url"
    fi
}

main() {
    echo ""
    echo "============================================="
    echo "  AtlasTunnel Installer"
    echo "  Загрузка файлов с GitHub..."
    echo "============================================="
    echo ""

    check_root
    check_distro

    log "Создание временной директории..."
    mkdir -p "$TEMP_DIR/lib"
    cd "$TEMP_DIR"

    log "Загрузка главного скрипта..."
    download_file "${GITHUB_RAW_URL}/atlastunnel.sh" "atlastunnel.sh"

    log "Загрузка менеджера..."
    download_file "${GITHUB_RAW_URL}/atlas-manager.sh" "atlas-manager.sh"

    log "Загрузка библиотек..."
    download_file "${GITHUB_RAW_URL}/lib/lib-utils.sh" "lib/lib-utils.sh"
    download_file "${GITHUB_RAW_URL}/lib/lib-system.sh" "lib/lib-system.sh"
    download_file "${GITHUB_RAW_URL}/lib/lib-protocols.sh" "lib/lib-protocols.sh"
    download_file "${GITHUB_RAW_URL}/lib/lib-manager.sh" "lib/lib-manager.sh"

    ok "Все файлы загружены"

    log "Установка прав на выполнение..."
    chmod +x atlastunnel.sh atlas-manager.sh
    chmod +x lib/*.sh

    echo ""
    echo "============================================="
    echo "  Запуск установки AtlasTunnel..."
    echo "============================================="
    echo ""

    ./atlastunnel.sh

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo ""
        log "Очистка временных файлов..."
        cd /
        rm -rf "$TEMP_DIR"
        ok "Установка завершена успешно!"
    else
        err "Установка завершилась с ошибкой (код: $exit_code)"
        err "Временные файлы сохранены в: $TEMP_DIR"
        exit $exit_code
    fi
}

main "$@"
