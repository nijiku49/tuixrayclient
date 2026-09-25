#!/bin/sh
# Установка harley на Alpine Linux. Только POSIX sh (busybox ash).
# Запуск из каталога с бинарником:  sudo sh install.sh [путь/к/harley]
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

if ! command -v xray >/dev/null 2>&1; then
	if command -v apk >/dev/null 2>&1; then
		say "→ xray не найден, ставлю: apk add xray"
		apk add xray || say "  не удалось установить xray — поставь вручную"
	else
		say "! xray не найден — установи xray-core"
	fi
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
