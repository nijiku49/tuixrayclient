#!/bin/sh
# Установка harley на Alpine Linux. Только POSIX sh (busybox ash).
# Запуск из каталога с бинарником:  sudo sh install.sh [путь/к/harley]
# Без доступа к GitHub: XRAY_ZIP=/путь/Xray-linux-64.zip sudo sh install.sh
set -eu

BIN_SRC="${1:-./harley}"
PREFIX="${PREFIX:-/usr/local}"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

say() { printf '%s\n' "$*"; }
die() { printf 'ошибка: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "запусти от root: sudo sh $0"
[ -f "$BIN_SRC" ] || die "не найден бинарник $BIN_SRC (собери: make build)"

say "→ harley → $PREFIX/bin/harley"
install -D -m 0755 "$BIN_SRC" "$PREFIX/bin/harley"

# xray-core: в репозиториях Alpine его нет — ставим официальный релиз
# (статический бинарник) через harley с проверкой SHA-256.
if command -v xray >/dev/null 2>&1; then
	say "→ xray уже установлен: $(xray version 2>/dev/null | head -n 1)"
elif [ -n "${XRAY_ZIP:-}" ]; then
	say "→ xray из архива $XRAY_ZIP"
	"$PREFIX/bin/harley" install-xray --from "$XRAY_ZIP" || die "не удалось установить xray из $XRAY_ZIP"
else
	say "→ скачиваю xray-core с GitHub (официальный релиз)"
	"$PREFIX/bin/harley" install-xray || say "  не удалось — скачай Xray-linux-*.zip и .dgst вручную и запусти: XRAY_ZIP=путь sh $0"
fi

if [ ! -c /dev/net/tun ]; then
	say "→ загружаю модуль tun"
	modprobe tun 2>/dev/null || say "  не удалось: modprobe tun (нужен только для режима TUN)"
fi
if [ -f /etc/modules ] && ! grep -qx 'tun' /etc/modules; then
	say "→ добавляю tun в /etc/modules"
	printf 'tun\n' >> /etc/modules
fi

if [ -d /etc/init.d ] && [ -f "$SCRIPT_DIR/openrc/harley" ]; then
	say "→ OpenRC: /etc/init.d/harley"
	install -m 0755 "$SCRIPT_DIR/openrc/harley" /etc/init.d/harley
	if [ ! -f /etc/conf.d/harley ]; then
		install -m 0644 "$SCRIPT_DIR/openrc/harley.confd" /etc/conf.d/harley
	fi
	say "  автоподключение при загрузке: rc-update add harley default"
fi

say "Готово. Запусти: harley  (для режима TUN и автозапуска — от root)"
