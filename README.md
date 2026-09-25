# harley

TUI VPN-клиент для Alpine Linux — аналог Happ, только в терминале.
Работает поверх [xray-core](https://github.com/XTLS/Xray-core): harley генерирует
конфиг, запускает и останавливает xray, показывает статус, скорость и логи.

**Вставил ссылку — всё работает.** Вставляешь подписку или ключ, harley сам определяет,
что это, импортирует серверы, пингует их, выбирает самый быстрый и подключается.

```
 ◆ harley  Серверы  │  Логи                                             ● подключено
────────────────────────────────────────────────────────────────────────────────────
 ▾ Мой VPN 4                  14.0 ГБ / 100 ГБ · до 01.01.2027 · обновлена 5 мин назад
  ● 🇩🇪 Germany Fast          VLESS·Reality         48 мс
    🇳🇱 Netherlands           Trojan                91 мс
    🇺🇸 USA                   VLESS                    ✕
    🇫🇮 Finland               Hy2                  120 мс
 ▾ Ключи 1
    my-server                 VMess                    —
────────────────────────────────────────────────────────────────────────────────────
 ● Подключено 🇩🇪 Germany Fast  VLESS·Reality   TUN harley0 (весь трафик) · всё через VPN
 ↑    12.4 КБ/с  ↓     1.2 МБ/с   трафик ↑ 3.1 МБ  ↓ 120.5 МБ   время 00:12:34
 📢 Новые серверы в Финляндии!
 Enter подключить  d откл  p пинг  f быстрейший  u обновить  a добавить  x удалить  / поиск …
```

## Возможности

- **Импорт чего угодно**: ссылка на подписку, один ключ, много ключей (построчно или
  base64-блобом), целиком xray JSON, sing-box JSON, Clash/mihomo YAML.
  Формат определяется по содержимому, а не по заголовкам.
- **Протоколы**: VLESS (Reality с `pbk`/`sid`/`spx`, TLS, `fp`, `sni`, `alpn`,
  `flow=xtls-rprx-vision`; транспорты tcp, ws, grpc, httpupgrade, xhttp/splithttp),
  VMess, Trojan, Shadowsocks (включая 2022), Hysteria2.
- **Подписки как в Happ**: User-Agent `Happ/…` (настраивается), `X-HWID`,
  заголовки `profile-title` (в т.ч. `base64:`), `subscription-userinfo`
  (трафик и дата окончания), `profile-update-interval` (автообновление),
  `support-url`, `announce`, `profile-web-page-url`. Те же поля понимаются
  в виде `#profile-title: …` в начале тела подписки.
- **Без сети — на сохранённой копии**: если подписка не отвечает, серверы остаются,
  а в заголовке группы видно «⚠ не обновилась».
- **Режимы**: Proxy (локальные SOCKS5 и HTTP) и TUN (весь трафик системы через
  встроенный tun xray).
- **Пинг** — реальная задержка через прокси (URL-тест через xray), а не только TCP.
- **Маршрутизация**: «всё через VPN», «RU напрямую» (`geoip:ru`, `geosite:category-ru`,
  `.ru`, `.su`, `.рф`), «свои правила». **DNS — через VPN, без утечек.**
- **CLI для скриптов и OpenRC**: `harley add/connect/disconnect/status/update`.
- Один статический бинарник (`CGO_ENABLED=0`), без зависимостей, amd64 и arm64.

## Установка на Alpine

```sh
# 1. xray-core
apk add xray

# 2. harley (из релиза или собранный: make release)
install -m 0755 harley-linux-amd64 /usr/local/bin/harley     # arm64: harley-linux-arm64

# 3. Для режима TUN — модуль tun (и чтобы грузился при старте)
modprobe tun
echo tun >> /etc/modules

# 4. Автоподключение при загрузке (OpenRC)
install -m 0755 openrc/harley /etc/init.d/harley
install -m 0644 openrc/harley.confd /etc/conf.d/harley
rc-update add harley default
```

Или одной командой из каталога релиза: `sudo sh install.sh ./harley-linux-amd64`
(ставит бинарник, xray, модуль tun и OpenRC-скрипт; POSIX sh, работает в busybox ash).

### Сборка из исходников

```sh
apk add go make git
make build          # ./harley для текущей платформы
make test           # юнит-тесты
make test-xray      # + проверка конфигов и сквозные тесты с настоящим xray
make release        # dist/harley-linux-amd64, dist/harley-linux-arm64, SHA256SUMS
```

### Geo-файлы (для «RU напрямую»)

Пресет «RU напрямую» использует `geoip.dat` и `geosite.dat`. harley ищет их в
`asset_dir` из настроек, `$XRAY_LOCATION_ASSET`, рядом с бинарником xray,
в `/usr/share/xray`, `/usr/local/share/xray`, `/usr/share/v2ray`.
Если их нет, скачай, например, из
[Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat/releases)
в `/usr/share/xray/`. Для «всё через VPN» они не нужны.

## Быстрый старт

```sh
harley          # открыть TUI
```

При первом запуске — пустой экран с одной подсказкой **«Вставь ссылку или ключ»**.
Вставь из буфера (Ctrl+Shift+V) — дальше всё само: импорт → пинг → самый быстрый
сервер → подключение. Автоподключение можно выключить в настройках (`s`).

Режим TUN (весь трафик системы) требует root или `CAP_NET_ADMIN`:

```sh
sudo harley     # или doas harley
```

От root данные хранятся в `/etc/harley/`, от обычного пользователя — в
`~/.config/harley/` (переопределяется `$HARLEY_HOME`). Для OpenRC настраивай
harley от root, чтобы служба видела те же серверы.

## Горячие клавиши

| Клавиша | Действие |
|---|---|
| **Вставка** (Ctrl+Shift+V) | добавить подписку или ключи — в любой момент, без лишних окон |
| ↑/↓, j/k, PgUp/PgDn, g/G | выбор сервера |
| Enter | подключиться; на заголовке подписки — свернуть/развернуть |
| d | отключиться |
| p | пинг всех серверов (URL-тест через xray) |
| f | пинг и подключение к самому быстрому |
| u | обновить подписки |
| a | добавить ссылку или ключ вручную |
| x | удалить сервер или подписку (с подтверждением) |
| / | поиск (Esc — сбросить) |
| m | режим Proxy ↔ TUN (если подключены — переподключится) |
| r | маршрутизация: всё через VPN → RU напрямую → свои правила |
| s | настройки |
| Tab, l | вкладка логов xray |
| ? | справка |
| q | выход (VPN остаётся подключённым; отключить — `d` или `harley disconnect`) |

## Командная строка

```sh
harley add 'https://panel.example.com/sub/abc123'        # подписка (+ автоподключение)
harley add 'vless://uuid@host:443?security=reality&…#NL' # ключ (кавычки нужны из-за &)
harley add --no-connect < keys.txt                        # много ключей из файла
xclip -o -sel clip | harley add                           # из буфера через stdin
harley list                                               # список с номерами
harley connect                                            # к последнему серверу
harley connect 3                                          # по номеру
harley connect нидерл                                     # по части имени
harley ping                                               # пинг всех
harley status                                             # код выхода: 0 — подключено, 3 — нет
harley update                                             # обновить все подписки
harley update --due                                       # только просроченные (для cron)
harley mode tun | proxy
harley routing all | ru | custom
harley logs -n 100
harley disconnect
```

Автообновление по таймеру работает, пока открыт TUI. Без TUI — через cron:

```sh
# crontab -e (от root, если служба OpenRC)
*/30 * * * * /usr/local/bin/harley update --due >/dev/null 2>&1
```

## Настройки

Файл `config.json` в каталоге данных (создаётся при первом запуске; основные
пункты меняются и из TUI, клавиша `s`):

```json
{
  "xray_path": "",                     // пусто — искать xray в PATH
  "asset_dir": "",                     // каталог geoip.dat/geosite.dat
  "mode": "proxy",                     // proxy | tun
  "listen": "127.0.0.1",
  "socks_port": 10808,
  "http_port": 10809,                  // 0 — не поднимать HTTP-прокси
  "tun_name": "harley0",
  "tun_mtu": 1500,
  "routing": "all",                    // all | ru-direct | custom
  "custom_rules": {
    "direct_domains": ["domain:example.ru", "geosite:category-gov-ru"],
    "direct_ips": ["geoip:ru", "203.0.113.0/24"],
    "proxy_domains": ["domain:youtube.com"],
    "proxy_ips": [],
    "block_domains": ["geosite:category-ads-all"],
    "block_ips": [],
    "default_direct": false            // true — всё остальное напрямую
  },
  "dns": ["1.1.1.1", "8.8.8.8"],       // DNS-серверы, запросы к ним идут через VPN
  "autoconnect": true,                 // после импорта: пинг → быстрейший → подключение
  "auto_update_hours": 12,             // если подписка не прислала profile-update-interval
  "user_agent": "Happ/3.8.1",
  "send_hwid": true,
  "ping_url": "https://www.gstatic.com/generate_204",
  "ping_timeout_sec": 5,
  "log_level": "warning"
}
```

(Комментарии в примере — для пояснения, в самом файле их быть не должно.)

## Как это устроено

- **Proxy**: xray слушает SOCKS5 и HTTP на `listen:порт`. Приложения настраиваются
  на прокси вручную (`export ALL_PROXY=socks5h://127.0.0.1:10808`).
- **TUN**: xray создаёт интерфейс `harley0`; harley назначает ему адрес и добавляет
  маршруты `0.0.0.0/1` и `128.0.0.0/1` (и `::/1`, `8000::/1`, если есть IPv6) —
  маршрут по умолчанию не трогается. Исходящие соединения xray к серверу и «напрямую»
  привязаны к физическому интерфейсу (`sockopt.interface`), поэтому петли нет.
  Адрес сервера разрешается заранее и кладётся в `dns.hosts`.
- **DNS без утечек**: в TUN запросы на порт 53 перехватываются и обрабатываются
  встроенным DNS xray, который ходит к `dns` только через VPN. Адреса DNS из
  `/etc/resolv.conf` (например, роутер 192.168.1.1) дополнительно заворачиваются
  в туннель маршрутом `/32` — иначе они ушли бы мимо по маршруту локальной сети.
- **Пинг**: отдельный временный xray, у каждого сервера свой SOCKS-вход; через каждый
  делается HTTP-запрос к `ping_url`. Без xray — запасной TCP-пинг.
- **Процесс**: xray запускается в отдельной сессии и переживает выход из TUI;
  PID — в `run/xray.pid` (от root — `/run/harley/`), лог — `run/xray.log`.

## Понятные ошибки

| Ситуация | Что покажет harley |
|---|---|
| xray не установлен | «xray не найден: установи его командой `apk add xray`…» |
| TUN без прав | «режим TUN требует root или CAP_NET_ADMIN: запусти `sudo harley`…» |
| нет /dev/net/tun | «выполни `modprobe tun` и добавь tun в /etc/modules» |
| порт занят | «порт 10808 уже занят другой программой — смени его в настройках…» |
| сервер недоступен | ✕ в колонке пинга; при подключении — ошибка из лога xray |
| подписка не отвечает | «подписка не отвечает: … — работаю на сохранённой копии» |
| 403 от панели | «доступ запрещён: проверь ссылку, срок подписки или лимит устройств (HWID)» |
| нет geo-файлов | «для «RU напрямую» нужны geoip.dat и geosite.dat…» |
| старый xray без Hysteria2/TUN | «эта версия xray не поддерживает … — обнови xray-core» |

## Ограничения

- Нужен свежий xray-core: Hysteria2 и встроенный TUN появились в версиях 2025–2026 года.
  Проверено с Xray 26.3.27.
- `allowInsecure` удалён из xray-core (с 2026-06); ключи с `insecure=1` без
  `pcs`/`pinSHA256` подключатся только к серверу с валидным сертификатом.
- Плагины Shadowsocks (obfs, v2ray-plugin) и транспорт h2 не поддерживаются xray.

## Разработка

```
cmd/harley/        CLI и точка входа
internal/parse/    ключи и форматы подписок, автоопределение вставки
internal/sub/      загрузка подписок, заголовки Happ
internal/xray/     генерация конфига, процесс, TUN-маршруты, пинг, статистика
internal/app/      сценарии: импорт, обновление, пинг, подключение
internal/store/    config.json, state.json, блокировки
internal/tui/      интерфейс на bubbletea
scripts/           OpenRC-скрипт и установщик (POSIX sh)
```

Чек-лист ручной проверки на реальных серверах — в [CHECKLIST.md](CHECKLIST.md).
