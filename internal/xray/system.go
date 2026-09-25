package xray

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const capNetAdmin = 12

// CheckTUN проверяет, можно ли поднять TUN: права и /dev/net/tun.
func CheckTUN() error {
	if !hasNetAdmin() {
		return errors.New("режим TUN требует root или CAP_NET_ADMIN: запусти `sudo harley` (или `doas harley`), либо переключись в режим Proxy (клавиша m)")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return errors.New("нет /dev/net/tun: выполни `modprobe tun` и добавь tun в /etc/modules, чтобы модуль грузился при старте")
	}
	if _, err := ipBinary(); err != nil {
		return err
	}
	return nil
}

func hasNetAdmin() bool {
	if os.Geteuid() == 0 {
		return true
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && caps&(1<<capNetAdmin) != 0
		}
	}
	return false
}

func ipBinary() (string, error) {
	if p, err := exec.LookPath("ip"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/sbin/ip", "/bin/ip", "/usr/sbin/ip"} {
		if isExec(p) {
			return p, nil
		}
	}
	return "", errors.New("не найдена утилита ip (busybox или `apk add iproute2`)")
}

// Route — маршрут по умолчанию.
type Route struct {
	Iface   string
	Gateway net.IP
}

// DefaultRoute читает маршрут по умолчанию из /proc/net/route, пропуская
// указанный интерфейс (наш tun).
func DefaultRoute(skipIface string) (Route, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return Route{}, err
	}
	return parseProcRoute(string(b), skipIface)
}

func parseProcRoute(text, skipIface string) (Route, error) {
	best, bestMetric := Route{}, -1
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 || f[0] == skipIface {
			continue
		}
		// Iface Destination Gateway Flags RefCnt Use Metric Mask
		if f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if bestMetric >= 0 && metric >= bestMetric {
			continue
		}
		gw, _ := hex.DecodeString(f[2])
		if len(gw) == 4 {
			// Little-endian.
			gw = net.IPv4(gw[3], gw[2], gw[1], gw[0])
		}
		best, bestMetric = Route{Iface: f[0], Gateway: net.IP(gw)}, metric
	}
	if bestMetric < 0 {
		return Route{}, errors.New("нет маршрута по умолчанию — нет сети?")
	}
	return best, nil
}

// TunAddr — адрес, назначаемый интерфейсу tun.
const TunAddr = "172.19.0.1/30"

// ResolvConfServers — адреса DNS-серверов из resolv.conf.
func ResolvConfServers(text string) []net.IP {
	var out []net.IP
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			host, _, _ := strings.Cut(f[1], "%") // fe80::1%eth0
			if ip := net.ParseIP(host); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

// dnsLeakRoutes — маршруты к системным DNS через tun. Без них запросы к
// DNS роутера (192.168.x.x) ушли бы по более узкому маршруту локальной
// сети мимо туннеля — утечка DNS. В туннеле их перехватывает xray.
func dnsLeakRoutes(servers []net.IP) (v4, v6 []string) {
	for _, ip := range servers {
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String()+"/32")
		} else if !ip.IsLinkLocalUnicast() {
			v6 = append(v6, ip.String()+"/128")
		}
	}
	return v4, v6
}

// SetupTunRoutes ждёт появления интерфейса xray и направляет в него весь
// трафик. Маршрут по умолчанию не трогаем: 0/1 и 128/1 перекрывают его,
// а исходящие xray привязаны к физическому интерфейсу.
func SetupTunRoutes(tun string, wait time.Duration) error {
	ip, err := ipBinary()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	for {
		if _, err := os.Stat("/sys/class/net/" + tun); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("xray не создал интерфейс %s за %s — смотри логи", tun, wait)
		}
		time.Sleep(100 * time.Millisecond)
	}
	run := func(ignoreExists bool, args ...string) error {
		out, err := exec.Command(ip, args...).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if ignoreExists && (strings.Contains(msg, "File exists") || strings.Contains(msg, "exists")) {
				return nil
			}
			return fmt.Errorf("ip %s: %s", strings.Join(args, " "), msg)
		}
		return nil
	}
	if err := run(true, "addr", "add", TunAddr, "dev", tun); err != nil {
		return err
	}
	if err := run(false, "link", "set", tun, "up"); err != nil {
		return err
	}
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run(true, "route", "add", dst, "dev", tun); err != nil {
			return err
		}
	}
	resolv, _ := os.ReadFile("/etc/resolv.conf")
	dns4, dns6 := dnsLeakRoutes(ResolvConfServers(string(resolv)))
	for _, dst := range dns4 {
		if err := run(true, "route", "add", dst, "dev", tun); err != nil {
			return fmt.Errorf("не удалось завернуть DNS %s в туннель: %w", dst, err)
		}
	}
	for _, dst := range dns6 {
		_ = run(true, "-6", "route", "add", dst, "dev", tun)
	}
	// IPv6: если он есть в системе, тоже заворачиваем — иначе утечка.
	if hasIPv6Default() {
		for _, dst := range []string{"::/1", "8000::/1"} {
			if err := run(true, "-6", "route", "add", dst, "dev", tun); err != nil {
				return fmt.Errorf("не удалось завернуть IPv6 в туннель (%v); отключи IPv6 или установи iproute2", err)
			}
		}
	}
	return nil
}

// TeardownTunRoutes удаляет маршруты (при остановке xray интерфейс исчезает
// вместе с ними, но подчищаем на случай зависшего процесса).
func TeardownTunRoutes(tun string) {
	ip, err := ipBinary()
	if err != nil {
		return
	}
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_ = exec.Command(ip, "route", "del", dst, "dev", tun).Run()
	}
	for _, dst := range []string{"::/1", "8000::/1"} {
		_ = exec.Command(ip, "-6", "route", "del", dst, "dev", tun).Run()
	}
}

func hasIPv6Default() bool {
	b, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		// dst dst_len src src_len nexthop metric refcnt use flags iface
		if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			return true
		}
	}
	return false
}

// ResolveServer заранее разрешает домен сервера (до поднятия TUN).
func ResolveServer(host string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return nil, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("не удалось разрешить адрес сервера %s: %w", host, err)
	}
	return addrs, nil
}

// FreePorts выделяет n свободных TCP-портов на 127.0.0.1.
func FreePorts(n int) ([]int, error) {
	var (
		ports     []int
		listeners []net.Listener
	)
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// PortFree — свободен ли порт на адресе.
func PortFree(addr string, port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	l.Close()
	return true
}
