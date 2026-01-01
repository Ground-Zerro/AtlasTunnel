#!/bin/bash

log() {
    echo "[*] $*"
}

ok() {
    echo "[✓] $*"
}

warn() {
    echo "[!] $*" >&2
}

err() {
    echo "[✗] $*" >&2
}

die() {
    err "$*"
    exit 1
}

rand_pw() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c8
}

get_public_ip() {
    curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || echo "недоступен"
}

get_ubuntu_version() {
    lsb_release -rs | cut -d'.' -f1,2
}

check_root() {
    [ "$(id -u)" -eq 0 ] || die "Требуется root доступ"
}

check_distro() {
    local os_id
    os_id=$(lsb_release -is 2>/dev/null | tr '[:upper:]' '[:lower:]')
    [[ "$os_id" == "ubuntu" ]] || die "Поддерживается только Ubuntu"
}
