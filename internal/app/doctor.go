package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/store"
	"github.com/nijiku49/tuixrayclient/internal/xray"
)

// Check — одна проверка диагностики.
type Check struct {
	Name string
	OK   bool
	Warn bool // не ошибка, но стоит обратить внимание
	Info string
}

// Doctor проверяет по звеньям, почему может не работать интернет:
// xray, права, tun, маршруты, DNS, сам сервер (через SOCKS) и выход в сеть
// через туннель. Вывод удобно прислать разработчику.
func (a *App) Doctor(ctx context.Context) []Check {
	var cs []Check
	add := func(name string, ok bool, format string, args ...any) {
		cs = append(cs, Check{Name: name, OK: ok, Info: fmt.Sprintf(format, args...)})
	}
	warn := func(name, format string, args ...any) {
		cs = append(cs, Check{Name: name, OK: true, Warn: true, Info: fmt.Sprintf(format, args...)})
	}

	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	osRel, _ := os.ReadFile("/etc/alpine-release")
	add("система", true, "Linux %s, %s, Alpine %s, uid %d", strings.TrimSpace(string(kernel)), runtime.GOARCH,
		orDash(strings.TrimSpace(string(osRel))), os.Geteuid())

	settings, err := a.Store.LoadSettings()
	if err != nil {
		add("настройки", false, "%v", err)
		return cs
	}
	add("настройки", true, "режим %s, %s, IPv6 %s, данные %s", ModeLabel(settings.Mode), RoutingLabel(settings.Routing),
		onOff(settings.IPv6), a.Store.Dir)

	bin, err := xray.FindBinary(settings.XrayPath)
	if err != nil {
		add("xray", false, "%v", err)
	} else {
		v := xray.Version(bin)
		add("xray", v != "", "%s (%s)", orDash(v), bin)
	}

	st := a.GetStatus()
	switch {
	case st.Connected:
		s := st.Session
		add("подключение", true, "%s [%s], режим %s, %s", s.ServerName, s.Protocol, ModeLabel(s.Mode),
			FormatDuration(time.Since(s.Started)))
	case st.Crashed:
		add("подключение", false, "xray остановился: %s", st.Reason)
	default:
		add("подключение", false, "не подключено — сначала подключись, потом запусти doctor")
	}

	route, rerr := xray.DefaultRoute(settings.TunName)
	if rerr != nil {
		add("маршрут по умолчанию", false, "%v", rerr)
	} else {
		add("маршрут по умолчанию", true, "через %s, шлюз %s", route.Iface, route.Gateway)
	}

	resolv, _ := os.ReadFile("/etc/resolv.conf")
	dnsServers := xray.ResolvConfServers(string(resolv))
	var dnsList []string
	for _, ip := range dnsServers {
		dnsList = append(dnsList, ip.String())
	}
	add("/etc/resolv.conf", len(dnsServers) > 0, "nameserver: %s", orDash(strings.Join(dnsList, ", ")))

	sess := st.Session
	tunMode := sess != nil && sess.Mode == store.ModeTUN
	if tunMode {
		if err := xray.CheckTUN(); err != nil {
			add("права и /dev/net/tun", false, "%v", err)
		} else {
			add("права и /dev/net/tun", true, "есть")
		}
		iface, ierr := net.InterfaceByName(sess.TunName)
		if ierr != nil {
			add("интерфейс "+sess.TunName, false, "не найден: %v", ierr)
		} else {
			addrs, _ := iface.Addrs()
			up := iface.Flags&net.FlagUp != 0
			add("интерфейс "+sess.TunName, up, "up=%v, mtu %d, адреса %v", up, iface.MTU, addrs)
		}
		routes := xray.RoutesVia(sess.TunName)
		has := func(dst string) bool {
			for _, r := range routes {
				if r == dst {
					return true
				}
			}
			return false
		}
		add("маршруты в туннель", has("0.0.0.0/1") && has("128.0.0.0/1"), "%s", orDash(strings.Join(routes, ", ")))
		for _, ip := range dnsServers {
			if ip.To4() == nil || ip.IsLoopback() {
				if ip.IsLoopback() {
					warn("DNS "+ip.String(), "локальный резолвер (dnsmasq/unbound?): его upstream-запросы идут своим путём")
				}
				continue
			}
			if !has(ip.String() + "/32") {
				add("DNS "+ip.String()+" через туннель", false, "нет маршрута %s/32 через %s — возможна утечка DNS", ip, sess.TunName)
			}
		}
		if b, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter"); err == nil {
			v := strings.TrimSpace(string(b))
			ifv, _ := os.ReadFile("/proc/sys/net/ipv4/conf/" + sess.BindIface + "/rp_filter")
			iv := strings.TrimSpace(string(ifv))
			bad := v != "2" && (v == "1" || iv == "1")
			add("rp_filter", !bad, "all=%s, %s=%s (нужно 0 или 2; strict=1 отбрасывает ответы сервера)", v, sess.BindIface, orDash(iv))
		}
		if xray.HasIPv6Default() {
			if settings.IPv6 {
				warn("IPv6", "есть IPv6 и он включён — если у сервера нет IPv6, сайты по IPv6 не откроются (выключи ipv6 в config.json)")
			} else {
				add("IPv6", true, "есть в системе, завёрнут в туннель; приложениям отдаются только IPv4-адреса")
			}
		}
	}

	if st.Connected && sess.SocksPort > 0 {
		ms, err := probeVia(ctx, "socks5://"+net.JoinHostPort(loopbackOf(sess.Listen), strconv.Itoa(sess.SocksPort)), settings.PingURL)
		if err != nil {
			add("сервер (через SOCKS)", false, "%s недоступен через прокси: %v — проблема с самим сервером/ключом, а не с TUN", settings.PingURL, err)
		} else {
			add("сервер (через SOCKS)", true, "%s за %d мс", settings.PingURL, ms)
		}
	}
	if tunMode && st.Connected {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		start := time.Now()
		ips, err := net.DefaultResolver.LookupHost(rctx, "www.google.com")
		cancel()
		if err != nil {
			add("DNS через туннель", false, "www.google.com не разрешился: %v", err)
		} else {
			add("DNS через туннель", true, "www.google.com → %s за %d мс", ips[0], time.Since(start).Milliseconds())
		}
		ms, err := probeVia(ctx, "", settings.PingURL)
		if err != nil {
			add("HTTP через туннель", false, "%s: %v", settings.PingURL, err)
		} else {
			add("HTTP через туннель", true, "%s за %d мс", settings.PingURL, ms)
		}
	}

	var logErrs []string
	for _, l := range xray.TailFile(a.Store.LogPath(), 200) {
		low := strings.ToLower(l)
		if strings.Contains(low, "xray ") && strings.Contains(low, "started") {
			continue
		}
		if strings.Contains(low, "[error]") || strings.Contains(low, "[warning]") || strings.Contains(low, "failed") {
			logErrs = append(logErrs, l)
		}
	}
	if len(logErrs) > 8 {
		logErrs = logErrs[len(logErrs)-8:]
	}
	if len(logErrs) > 0 {
		warn("лог xray", "последние предупреждения/ошибки:\n    %s", strings.Join(logErrs, "\n    "))
	}
	return cs
}

func probeVia(ctx context.Context, proxy, target string) (int, error) {
	tr := &http.Transport{DisableKeepAlives: true, Proxy: nil}
	if proxy != "" {
		u, _ := url.Parse(proxy)
		tr.Proxy = http.ProxyURL(u)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return int(time.Since(start).Milliseconds()), nil
}

func loopbackOf(listen string) string {
	if listen == "" || listen == "0.0.0.0" || listen == "::" {
		return "127.0.0.1"
	}
	return listen
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "вкл"
	}
	return "выкл"
}
