#!/bin/bash

set -euo pipefail

readonly REPO="Ground-Zerro/AtlasTunnel"
readonly BRANCH="${ATLAS_BRANCH:-main}"
readonly BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}/bin"
readonly BIN_PATH="/usr/local/bin/atlas"

log() { echo "[*] $*"; }
ok()  { echo "[✓] $*"; }
die() { echo "[✗] $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Требуется root доступ. Запустите через sudo."

case "$(uname -m)" in
    x86_64)        ASSET="atlas-x86_64-linux" ;;
    aarch64|arm64) ASSET="atlas-aarch64-linux" ;;
    *)             die "Неподдерживаемая архитектура: $(uname -m)" ;;
esac

command -v curl >/dev/null 2>&1 || die "Требуется curl"
command -v sha256sum >/dev/null 2>&1 || die "Требуется sha256sum"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

log "Загрузка ${ASSET} из ветки ${BRANCH}..."
curl -fsSL "${BASE}/${ASSET}" -o "${TMP}/atlas" \
    || die "Не удалось загрузить ${BASE}/${ASSET}"

# Контрольная сумма обязательна: бинарник ставится в систему с правами root.
log "Проверка контрольной суммы..."
curl -fsSL "${BASE}/SHA256SUMS" -o "${TMP}/SHA256SUMS" \
    || die "Не удалось загрузить SHA256SUMS"

EXPECTED=$(grep " ${ASSET}\$" "${TMP}/SHA256SUMS" | cut -d' ' -f1)
[ -n "$EXPECTED" ] || die "В SHA256SUMS нет записи для ${ASSET}"

ACTUAL=$(sha256sum "${TMP}/atlas" | cut -d' ' -f1)
[ "$EXPECTED" = "$ACTUAL" ] \
    || die "Контрольная сумма не совпала: ожидалось ${EXPECTED}, получено ${ACTUAL}"
ok "Контрольная сумма совпала"

# mv, а не install: переименование срабатывает даже когда старый atlas запущен.
chmod 755 "${TMP}/atlas"
mv -f "${TMP}/atlas" "$BIN_PATH"
ok "Установлено: ${BIN_PATH} ($("$BIN_PATH" --version))"

echo
if [ -e /dev/tty ]; then
    log "Запуск установки протоколов..."
    exec "$BIN_PATH" install
else
    echo "Терминал недоступен — запустите установку вручную:"
    echo "  atlas install                                     интерактивный выбор"
    echo "  atlas install --protocols pptp,l2tp-ipsec --yes   без интерфейса"
fi
