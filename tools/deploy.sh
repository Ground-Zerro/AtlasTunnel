#!/bin/bash

set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CRATE="${ROOT}/atlas"
readonly DIST="${ROOT}/bin"

readonly ARCHES=(x86_64 aarch64)
readonly TRIPLE_x86_64="x86_64-unknown-linux-musl"
readonly TRIPLE_aarch64="aarch64-unknown-linux-musl"

log()  { echo "[*] $*"; }
ok()   { echo "[✓] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[✗] $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Сборка статических бинарников atlas и выкатка их на серверы.

  tools/deploy.sh --build-only              собрать в bin/ и выйти
  tools/deploy.sh root@host1 root@host2     собрать и выкатить
  tools/deploy.sh --skip-build root@host1   выкатить уже собранное

Архитектура сервера определяется по uname -m, нужный бинарник выбирается
автоматически. Собирать на самом сервере не требуется: musl-сборка статическая.
EOF
}

triple_for() {
    local arch="$1"
    local name="TRIPLE_${arch}"
    echo "${!name}"
}

asset_for() {
    echo "atlas-${1}-linux"
}

cargo_bin() {
    if command -v cargo >/dev/null 2>&1; then
        command -v cargo
    elif [ -x "$HOME/.cargo/bin/cargo" ]; then
        echo "$HOME/.cargo/bin/cargo"
    else
        die "не найден cargo — установите Rust 1.74+ (https://rustup.rs)"
    fi
}

# Кросс-компоновка aarch64 делается rust-lld из состава toolchain: отдельный
# кросс-линкер в системе не нужен, потому что в дереве зависимостей нет C-кода,
# а musl-libc Rust поставляет уже собранным.
linker_for() {
    local arch="$1"
    [ "$arch" = "aarch64" ] || return 0
    local lld
    lld=$(find "${RUSTUP_HOME:-$HOME/.rustup}/toolchains" -name rust-lld -type f 2>/dev/null | head -1)
    [ -n "$lld" ] || die "не найден rust-lld для сборки под aarch64"
    echo "$lld"
}

build() {
    local cargo arch triple asset lld
    cargo=$(cargo_bin)
    local rustup="${cargo%/cargo}/rustup"

    mkdir -p "$DIST"

    for arch in "${ARCHES[@]}"; do
        triple=$(triple_for "$arch")
        asset=$(asset_for "$arch")

        if [ -x "$rustup" ]; then
            "$rustup" target add "$triple" >/dev/null 2>&1 || true
        fi

        log "Сборка ${arch} (${triple})..."
        lld=$(linker_for "$arch")
        if [ -n "$lld" ]; then
            env "CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER=$lld" \
                "$cargo" build --release --manifest-path "${CRATE}/Cargo.toml" --target "$triple"
        else
            "$cargo" build --release --manifest-path "${CRATE}/Cargo.toml" --target "$triple"
        fi

        install -m 755 "${CRATE}/target/${triple}/release/atlas" "${DIST}/${asset}"
        ok "${asset} $(du -h "${DIST}/${asset}" | cut -f1)"
    done

    # Формат sha256sum совпадает с тем, что разбирает install.sh: он тянет
    # bin/ прямо из репозитория, релизы для этого не нужны.
    ( cd "$DIST" && sha256sum "$(asset_for x86_64)" "$(asset_for aarch64)" > SHA256SUMS )
    ok "контрольные суммы: ${DIST}/SHA256SUMS"
}

deploy() {
    local host="$1"
    local arch asset local_hash remote_hash remote_arch

    remote_arch=$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$host" 'uname -m' 2>/dev/null) \
        || { warn "${host}: нет доступа по SSH"; return 1; }

    case "$remote_arch" in
        x86_64)  arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) warn "${host}: неподдерживаемая архитектура ${remote_arch}"; return 1 ;;
    esac

    asset=$(asset_for "$arch")
    [ -f "${DIST}/${asset}" ] || { warn "${host}: не собран ${asset}"; return 1; }

    log "${host} (${remote_arch}): копирование ${asset}..."
    scp -q -o ConnectTimeout=15 -o BatchMode=yes "${DIST}/${asset}" "${host}:/tmp/atlas.new" \
        || { warn "${host}: не удалось скопировать файл"; return 1; }

    # Сверка на удалённой стороне: оборванная передача не должна пройти незамеченной.
    local_hash=$(sha256sum "${DIST}/${asset}" | cut -d' ' -f1)
    remote_hash=$(ssh -o BatchMode=yes "$host" 'sha256sum /tmp/atlas.new | cut -d" " -f1' 2>/dev/null || true)
    if [ "$local_hash" != "$remote_hash" ]; then
        ssh -o BatchMode=yes "$host" 'rm -f /tmp/atlas.new' 2>/dev/null || true
        warn "${host}: контрольная сумма не совпала"
        return 1
    fi

    # mv, а не install: переименование срабатывает даже когда старый бинарник запущен.
    ssh -o BatchMode=yes "$host" \
        'chmod 755 /tmp/atlas.new && mv -f /tmp/atlas.new /usr/local/bin/atlas' \
        || { warn "${host}: не удалось установить бинарник"; return 1; }

    ok "${host}: $(ssh -o BatchMode=yes "$host" '/usr/local/bin/atlas --version')"
    return 0
}

main() {
    local do_build=1 do_deploy=1
    local hosts=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --build-only) do_deploy=0 ;;
            --skip-build) do_build=0 ;;
            -h|--help) usage; return 0 ;;
            -*) die "неизвестный параметр: $1" ;;
            *) hosts+=("$1") ;;
        esac
        shift
    done

    if [ "$do_deploy" -eq 1 ] && [ ${#hosts[@]} -eq 0 ]; then
        usage
        die "не указан ни один сервер"
    fi

    if [ "$do_build" -eq 1 ]; then
        build
    fi

    [ "$do_deploy" -eq 1 ] || return 0

    local host failed=()
    for host in "${hosts[@]}"; do
        deploy "$host" || failed+=("$host")
    done

    echo
    if [ ${#failed[@]} -eq 0 ]; then
        ok "выкачено серверов: ${#hosts[@]}"
    else
        warn "с ошибками: ${failed[*]} (успешно: $(( ${#hosts[@]} - ${#failed[@]} )) из ${#hosts[@]})"
        return 1
    fi
}

main "$@"
