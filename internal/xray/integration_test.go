package xray

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/parse"
	"github.com/nijiku49/tuixrayclient/internal/store"
)

func xrayBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		bin, _ = exec.LookPath("xray")
	}
	if bin == "" {
		t.Skip("xray не найден (задай XRAY_BIN)")
	}
	return bin
}

// startTestServer поднимает локальный xray-сервер VLESS без шифрования,
// который любые соединения перенаправляет на target (httptest-сервер).
func startTestServer(t *testing.T, bin, target string) int {
	t.Helper()
	ports, _ := FreePorts(1)
	cfg := fmt.Sprintf(`{
	  "log": {"loglevel": "error"},
	  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
	    "settings": {"clients": [{"id": "5783a3e7-e373-51cd-8642-c83782b807c5"}], "decryption": "none"}}],
	  "outbounds": [{"protocol": "freedom", "settings": {"redirect": "%s"}}]
	}`, ports[0], target)
	p := filepath.Join(t.TempDir(), "server.json")
	os.WriteFile(p, []byte(cfg), 0o600)
	cmd := exec.Command(bin, "run", "-c", p)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if err := waitListen(ports[0], 5*time.Second, nil); err != nil {
		t.Fatal("тестовый сервер не поднялся")
	}
	return ports[0]
}

func TestIntegrationPingAndConnect(t *testing.T) {
	bin := xrayBin(t)
	var hits int
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(strings.Repeat("x", 100_000)))
	}))
	defer web.Close()
	target := strings.TrimPrefix(web.URL, "http://")
	srvPort := startTestServer(t, bin, target)

	good, err := parse.ParseLink(fmt.Sprintf("vless://5783a3e7-e373-51cd-8642-c83782b807c5@127.0.0.1:%d?security=none#good", srvPort))
	if err != nil {
		t.Fatal(err)
	}
	deadPorts, _ := FreePorts(1)
	dead, _ := parse.ParseLink(fmt.Sprintf("vless://5783a3e7-e373-51cd-8642-c83782b807c5@127.0.0.1:%d?security=none#dead", deadPorts[0]))
	wrong, _ := parse.ParseLink(fmt.Sprintf("trojan://nope@127.0.0.1:%d?security=none#wrong-proto", srvPort))

	// --- URL-тест ---
	// Адрес из TEST-NET: сервер всё равно перенаправит на httptest.
	res := URLTest(context.Background(), []*model.Server{good, dead, wrong}, PingOptions{
		Bin: bin, URL: "http://203.0.113.1/generate_204", Timeout: 3 * time.Second, WorkDir: t.TempDir(),
	})
	if res[0].Err != nil || res[0].Ms <= 0 {
		t.Fatalf("живой сервер: %+v", res[0])
	}
	if res[1].Err == nil {
		t.Fatalf("мёртвый сервер должен давать ошибку: %+v", res[1])
	}
	if res[2].Err == nil {
		t.Fatalf("неверный протокол должен давать ошибку: %+v", res[2])
	}

	// --- Подключение в режиме proxy ---
	dir := t.TempDir()
	ports, _ := FreePorts(3)
	o := OptionsFromSettings(store.Defaults())
	o.SocksPort, o.HTTPPort, o.MetricsPort = ports[0], ports[1], ports[2]
	cfg, err := Build(good, o)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proc{Bin: bin, Config: filepath.Join(dir, "xray.json"), PidFile: filepath.Join(dir, "xray.pid"), LogFile: filepath.Join(dir, "xray.log")}
	os.WriteFile(p.Config, cfg, 0o600)
	pid, err := p.Start(300 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if got, ok := p.Running(); !ok || got != pid {
		t.Fatalf("Running: %d %v", got, ok)
	}
	if err := waitListen(o.SocksPort, 5*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	for _, proxy := range []string{"socks5://127.0.0.1:" + strconv.Itoa(o.SocksPort), "http://127.0.0.1:" + strconv.Itoa(o.HTTPPort)} {
		pu, _ := url.Parse(proxy)
		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
		resp, err := c.Get("http://203.0.113.1/")
		if err != nil {
			t.Fatalf("через %s: %v", proxy, err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != 100_000 {
			t.Fatalf("через %s получили %d байт", proxy, n)
		}
	}
	tr, err := QueryTraffic(context.Background(), o.MetricsPort)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Down < 100_000 {
		t.Fatalf("статистика трафика: %+v", tr)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Running(); ok {
		t.Fatal("xray не остановлен")
	}

	// --- Порт занят: понятная ошибка ---
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	o.SocksPort = l.Addr().(*net.TCPAddr).Port
	cfg, _ = Build(good, o)
	os.WriteFile(p.Config, cfg, 0o600)
	if _, err := p.Start(time.Second); err == nil || !strings.Contains(err.Error(), "порт") {
		p.Stop()
		t.Fatalf("ожидалась ошибка «порт занят»: %v", err)
	}
}

func TestParseProcRoute(t *testing.T) {
	text := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"harley0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	r, err := parseProcRoute(text, "harley0")
	if err != nil || r.Iface != "eth0" || r.Gateway.String() != "10.0.0.1" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := parseProcRoute("Iface\n", ""); err == nil {
		t.Fatal("нет маршрута — ошибка")
	}
}

func TestDNSLeakRoutes(t *testing.T) {
	servers := ResolvConfServers("# comment\nnameserver 192.168.1.1\nnameserver 127.0.0.53\nnameserver 2001:4860:4860::8888\nnameserver fe80::1%eth0\nsearch lan\n")
	if len(servers) != 4 {
		t.Fatalf("%v", servers)
	}
	v4, v6 := dnsLeakRoutes(servers)
	if len(v4) != 1 || v4[0] != "192.168.1.1/32" {
		t.Fatalf("v4: %v", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:4860:4860::8888/128" {
		t.Fatalf("v6: %v", v6)
	}
}

func TestExplainLog(t *testing.T) {
	cases := map[string]string{
		"listen tcp 127.0.0.1:10808: bind: address already in use":           "порт",
		"failed to open /dev/net/tun: no such file or directory":             "modprobe tun",
		"tun: operation not permitted":                                       "root",
		"failed to load geoip.dat: open geoip.dat: no such file":             "geoip.dat",
		"infra/conf: failed to build outbound > unknown config id: hysteria": "Hysteria2",
	}
	for log, want := range cases {
		if got := ExplainLog([]string{log}); !strings.Contains(got, want) {
			t.Errorf("%q → %q (ждали %q)", log, got, want)
		}
	}
}

func TestParseMetrics(t *testing.T) {
	tr, err := ParseMetrics([]byte(`{"cmdline":["xray"],"stats":{"inbound":{},"outbound":{"proxy":{"uplink":10,"downlink":20},"direct":{"uplink":5,"downlink":5}},"user":{}}}`))
	if err != nil || tr.Up != 10 || tr.Down != 20 {
		t.Fatalf("%+v %v", tr, err)
	}
}
