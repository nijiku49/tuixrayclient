package xray

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/parse"
	"github.com/nijiku49/tuixrayclient/internal/store"
)

var testLinks = map[string]string{
	"vless-reality": "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@203.0.113.10:443?type=tcp&security=reality&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&spx=%2F&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision#R",
	"vless-ws-tls":  "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@example.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=firefox#ws",
	"vless-grpc":    "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@example.com:443?type=grpc&security=tls&serviceName=svc&mode=multi#g",
	"vless-hu":      "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@example.com:80?type=httpupgrade&path=%2Fup&host=h.example.com#hu",
	"vless-xhttp":   "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@example.com:443?type=xhttp&security=reality&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab&path=%2Fx&mode=auto&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#xh",
	"vless-tcphttp": "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@example.com:80?type=tcp&headerType=http&host=bing.com&path=%2F#th",
	"vmess-ws":      "vmess://eyJ2IjoiMiIsInBzIjoidm0iLCJhZGQiOiJ2bS5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInBhdGgiOiIvdm0iLCJ0bHMiOiJ0bHMiLCJzbmkiOiJ2bS5leGFtcGxlLmNvbSJ9",
	"trojan":        "trojan://secret@tr.example.com:443?sni=tr.example.com&fp=chrome#t",
	"ss":            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:8388#ss",
	"ss2022":        "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@ss.example.com:8388#ss22",
	"hy2":           "hy2://letmein@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=gawr#hy",
	"hy2-hop":       "hy2://letmein@hy.example.com:20000-30000?sni=hy.example.com&upmbps=50&downmbps=200#hop",
	"tls-pin":       "trojan://secret@tr.example.com:443?sni=tr.example.com&allowInsecure=1&pcs=" + strings.Repeat("ab", 32) + "#pin",
}

func server(t *testing.T, key string) *model.Server {
	t.Helper()
	s, err := parse.ParseLink(testLinks[key])
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return s
}

type cfgT struct {
	DNS struct {
		Servers []string            `json:"servers"`
		Tag     string              `json:"tag"`
		Hosts   map[string][]string `json:"hosts"`
	} `json:"dns"`
	Inbounds []struct {
		Tag      string         `json:"tag"`
		Protocol string         `json:"protocol"`
		Port     int            `json:"port"`
		Listen   string         `json:"listen"`
		Settings map[string]any `json:"settings"`
	} `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
	Routing   struct {
		DomainStrategy string           `json:"domainStrategy"`
		Rules          []map[string]any `json:"rules"`
	} `json:"routing"`
	Metrics map[string]any `json:"metrics"`
}

func decode(t *testing.T, b []byte) cfgT {
	t.Helper()
	var c cfgT
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func baseOpts() Options {
	o := OptionsFromSettings(store.Defaults())
	o.MetricsPort = 10813
	return o
}

func TestBuildProxyMode(t *testing.T) {
	b, err := Build(server(t, "vless-reality"), baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	c := decode(t, b)
	if len(c.Inbounds) != 2 || c.Inbounds[0].Protocol != "socks" || c.Inbounds[0].Port != 10808 ||
		c.Inbounds[1].Protocol != "http" || c.Inbounds[1].Port != 10809 || c.Inbounds[0].Listen != "127.0.0.1" {
		t.Fatalf("inbounds: %+v", c.Inbounds)
	}
	if c.Outbounds[0]["tag"] != TagProxy {
		t.Fatal("первый outbound должен быть proxy (он же по умолчанию)")
	}
	ss := c.Outbounds[0]["streamSettings"].(map[string]any)
	rs := ss["realitySettings"].(map[string]any)
	if ss["security"] != "reality" || rs["publicKey"] != "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw" ||
		rs["shortId"] != "6ba85179e30d4fc2" || rs["serverName"] != "www.microsoft.com" || rs["fingerprint"] != "chrome" || rs["spiderX"] != "/" {
		t.Fatalf("reality: %v", rs)
	}
	user := c.Outbounds[0]["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["flow"] != "xtls-rprx-vision" || user["encryption"] != "none" {
		t.Fatalf("user: %v", user)
	}
	// DNS идёт через VPN.
	if c.DNS.Tag != TagDNSIn || !hasRule(c, "inboundTag", TagDNSIn, TagProxy) {
		t.Fatal("DNS должен идти через proxy")
	}
	if c.Metrics["listen"] != "127.0.0.1:10813" {
		t.Fatalf("metrics: %v", c.Metrics)
	}
	for _, r := range c.Routing.Rules {
		if r["outboundTag"] == TagDNSOut {
			t.Fatal("в режиме proxy нет dns-out")
		}
	}
}

func TestBuildTUN(t *testing.T) {
	o := baseOpts()
	o.Mode = store.ModeTUN
	o.BindInterface = "eth0"
	o.ServerHosts = map[string][]string{"example.com": {"203.0.113.5"}}
	b, err := Build(server(t, "vless-ws-tls"), o)
	if err != nil {
		t.Fatal(err)
	}
	c := decode(t, b)
	if c.Inbounds[0].Protocol != "tun" || c.Inbounds[0].Settings["name"] != "harley0" || c.Inbounds[0].Settings["MTU"] != float64(1500) {
		t.Fatalf("tun inbound: %+v", c.Inbounds[0])
	}
	so := c.Outbounds[0]["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if so["interface"] != "eth0" || so["domainStrategy"] != "UseIPv4" {
		t.Fatalf("sockopt proxy: %v", so)
	}
	direct := findOutbound(c, TagDirect)
	if direct["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["interface"] != "eth0" {
		t.Fatal("direct должен быть привязан к физическому интерфейсу")
	}
	if findOutbound(c, TagDNSOut) == nil || !hasRule(c, "inboundTag", TagTun, TagDNSOut) {
		t.Fatal("DNS из TUN должен перехватываться")
	}
	// Правило перехвата DNS — раньше правила «локальные сети напрямую»,
	// иначе запросы к DNS роутера (192.168.x.x) утекут мимо VPN.
	if c.Routing.Rules[0]["outboundTag"] != TagDNSOut {
		t.Fatal("перехват DNS должен быть первым правилом")
	}
	if c.DNS.Hosts["example.com"][0] != "203.0.113.5" {
		t.Fatalf("hosts: %v", c.DNS.Hosts)
	}
}

func TestBuildRouting(t *testing.T) {
	o := baseOpts()
	b, _ := Build(server(t, "trojan"), o)
	c := decode(t, b)
	if c.Routing.DomainStrategy != "AsIs" || NeedsGeoFiles(o) {
		t.Fatal("«всё через VPN» не должно требовать geo-файлов")
	}
	for _, r := range c.Routing.Rules {
		if strings.Contains(mustJSON(r), "geoip:") || strings.Contains(mustJSON(r), "geosite:") {
			t.Fatalf("лишнее geo-правило: %v", r)
		}
	}

	o.Routing = store.RouteRUDirect
	b, _ = Build(server(t, "trojan"), o)
	c = decode(t, b)
	if !hasRule(c, "domain", "geosite:category-ru", TagDirect) || !hasRule(c, "ip", "geoip:ru", TagDirect) {
		t.Fatalf("RU напрямую: %v", c.Routing.Rules)
	}
	if c.Routing.DomainStrategy != "IPIfNonMatch" || !NeedsGeoFiles(o) {
		t.Fatal("для geoip нужен IPIfNonMatch и geo-файлы")
	}

	o.Routing = store.RouteCustom
	o.Custom = store.CustomRules{
		DirectDomains: []string{"domain:example.org"},
		ProxyIPs:      []string{"8.8.8.8/32"},
		BlockDomains:  []string{"domain:ads.example"},
		DefaultDirect: true,
	}
	b, _ = Build(server(t, "trojan"), o)
	c = decode(t, b)
	if !hasRule(c, "domain", "domain:example.org", TagDirect) || !hasRule(c, "ip", "8.8.8.8/32", TagProxy) ||
		!hasRule(c, "domain", "domain:ads.example", TagBlock) {
		t.Fatalf("свои правила: %v", c.Routing.Rules)
	}
	last := c.Routing.Rules[len(c.Routing.Rules)-1]
	if last["outboundTag"] != TagDirect || last["network"] != "tcp,udp" {
		t.Fatal("DefaultDirect: последнее правило — всё напрямую")
	}
	if NeedsGeoFiles(o) {
		t.Fatal("свои правила без geo:* не требуют geo-файлов")
	}
}

func TestOutboundsPerProtocol(t *testing.T) {
	check := func(key string, fn func(ob map[string]any, ss map[string]any)) {
		t.Helper()
		outs, err := Outbounds(server(t, key), "x", "", "")
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		b, _ := json.Marshal(outs[0])
		var ob map[string]any
		_ = json.Unmarshal(b, &ob)
		fn(ob, ob["streamSettings"].(map[string]any))
	}
	check("vless-ws-tls", func(ob, ss map[string]any) {
		ws := ss["wsSettings"].(map[string]any)
		tls := ss["tlsSettings"].(map[string]any)
		if ss["network"] != "ws" || ws["path"] != "/ws" || ws["host"] != "cdn.example.com" ||
			tls["serverName"] != "cdn.example.com" || tls["fingerprint"] != "firefox" || len(tls["alpn"].([]any)) != 2 {
			t.Fatalf("ws: %v", ss)
		}
	})
	check("vless-grpc", func(ob, ss map[string]any) {
		g := ss["grpcSettings"].(map[string]any)
		if g["serviceName"] != "svc" || g["multiMode"] != true {
			t.Fatalf("grpc: %v", g)
		}
	})
	check("vless-hu", func(ob, ss map[string]any) {
		if ss["httpupgradeSettings"].(map[string]any)["path"] != "/up" || ss["security"] != "none" {
			t.Fatalf("httpupgrade: %v", ss)
		}
	})
	check("vless-xhttp", func(ob, ss map[string]any) {
		x := ss["xhttpSettings"].(map[string]any)
		if ss["network"] != "xhttp" || x["mode"] != "auto" || x["extra"].(map[string]any)["xPaddingBytes"] != "100-1000" {
			t.Fatalf("xhttp: %v", x)
		}
	})
	check("vless-tcphttp", func(ob, ss map[string]any) {
		h := ss["tcpSettings"].(map[string]any)["header"].(map[string]any)
		if h["type"] != "http" {
			t.Fatalf("tcp http: %v", h)
		}
	})
	check("vmess-ws", func(ob, ss map[string]any) {
		u := ob["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
		if ob["protocol"] != "vmess" || u["security"] != "auto" || ss["security"] != "tls" {
			t.Fatalf("vmess: %v", ob)
		}
	})
	check("trojan", func(ob, ss map[string]any) {
		srv := ob["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		if srv["password"] != "secret" || ss["security"] != "tls" {
			t.Fatalf("trojan: %v", ob)
		}
	})
	check("ss2022", func(ob, ss map[string]any) {
		srv := ob["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
		if srv["method"] != "2022-blake3-aes-128-gcm" || srv["password"] != "MTIzNDU2Nzg5MDEyMzQ1Ng==" {
			t.Fatalf("ss2022: %v", srv)
		}
	})
	check("hy2", func(ob, ss map[string]any) {
		st := ob["settings"].(map[string]any)
		if ob["protocol"] != "hysteria" || st["version"] != float64(2) || ss["network"] != "hysteria" {
			t.Fatalf("hy2: %v", ob)
		}
		if ss["hysteriaSettings"].(map[string]any)["auth"] != "letmein" {
			t.Fatal("hy2 auth")
		}
		udp := ss["finalmask"].(map[string]any)["udp"].([]any)[0].(map[string]any)
		if udp["type"] != "salamander" || udp["settings"].(map[string]any)["password"] != "gawr" {
			t.Fatalf("salamander: %v", udp)
		}
		if ss["tlsSettings"].(map[string]any)["alpn"].([]any)[0] != "h3" {
			t.Fatal("hy2 alpn h3")
		}
	})
	check("hy2-hop", func(ob, ss map[string]any) {
		qp := ss["finalmask"].(map[string]any)["quicParams"].(map[string]any)
		if qp["brutalUp"] != "50 mbps" || qp["brutalDown"] != "200 mbps" || qp["udpHop"].(map[string]any)["ports"] != "20000-30000" {
			t.Fatalf("quicParams: %v", qp)
		}
	})
	check("tls-pin", func(ob, ss map[string]any) {
		tls := ss["tlsSettings"].(map[string]any)
		if _, ok := tls["allowInsecure"]; ok {
			t.Fatal("allowInsecure удалён из xray и не должен попадать в конфиг")
		}
		if tls["pinnedPeerCertSha256"] != strings.Repeat("ab", 32) {
			t.Fatal("pcs")
		}
	})
}

func TestRawOutbounds(t *testing.T) {
	body, err := os.ReadFile("../parse/testdata/xray_array.json")
	if err != nil {
		t.Fatal(err)
	}
	r := parse.ParseBody(body)
	de := r.Servers[0]
	outs, err := Outbounds(de, "proxy", "p-", "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 2 || outs[0]["tag"] != "proxy" || outs[1]["tag"] != "p-fragment" {
		t.Fatalf("теги: %v / %v", outs[0]["tag"], outs[1]["tag"])
	}
	so := outs[0]["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if so["dialerProxy"] != "p-fragment" {
		t.Fatalf("dialerProxy не переименован: %v", so)
	}
	if _, ok := so["interface"]; ok {
		t.Fatal("outbound с dialerProxy не должен привязываться к интерфейсу")
	}
	if outs[1]["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["interface"] != "eth0" {
		t.Fatal("конец цепочки должен быть привязан к интерфейсу")
	}
	// Исходный Raw не должен меняться.
	if !strings.Contains(string(de.Raw), `"dialerProxy": "fragment"`) {
		t.Fatal("Raw изменён")
	}
}

func TestBuildPing(t *testing.T) {
	servers := []*model.Server{server(t, "vless-reality"), server(t, "trojan"), {Protocol: "bogus"}}
	b, errs := BuildPing(servers, []int{20001, 20002, 20003}, "")
	if errs[0] != nil || errs[1] != nil || errs[2] == nil {
		t.Fatalf("errs: %v", errs)
	}
	c := decode(t, b)
	if len(c.Inbounds) != 2 || c.Inbounds[1].Port != 20002 {
		t.Fatalf("inbounds: %+v", c.Inbounds)
	}
	if !hasRule(c, "inboundTag", "in1", "t1") {
		t.Fatal("маршрут in1 → t1")
	}
	if c.Outbounds[0]["protocol"] != "blackhole" {
		t.Fatal("по умолчанию — blackhole, чтобы тест не шёл напрямую")
	}
}

// TestXrayAccepts прогоняет все сгенерированные конфиги через настоящий
// `xray run -test`, если бинарник доступен (XRAY_BIN или xray в PATH).
func TestXrayAccepts(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		bin, _ = exec.LookPath("xray")
	}
	if bin == "" {
		t.Skip("xray не найден (задай XRAY_BIN)")
	}
	dir := t.TempDir()
	run := func(name string, cfg []byte) {
		t.Helper()
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, cfg, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "run", "-test", "-c", p).CombinedOutput()
		if err != nil {
			t.Errorf("%s: xray отверг конфиг: %v\n%s", name, err, out)
		}
	}
	for key := range testLinks {
		for _, mode := range []string{store.ModeProxy, store.ModeTUN} {
			o := baseOpts()
			o.Mode = mode
			if mode == store.ModeTUN {
				o.BindInterface = "lo"
				o.ServerHosts = map[string][]string{"example.com": {"203.0.113.1"}}
			}
			b, err := Build(server(t, key), o)
			if err != nil {
				t.Fatal(err)
			}
			run(key+"-"+mode, b)
		}
	}
	body, _ := os.ReadFile("../parse/testdata/xray_array.json")
	for i, s := range parse.ParseBody(body).Servers {
		b, err := Build(s, baseOpts())
		if err != nil {
			t.Fatal(err)
		}
		run("raw"+string(rune('0'+i)), b)
	}
	var all []*model.Server
	var ports []int
	for key := range testLinks {
		all = append(all, server(t, key))
		ports = append(ports, 30000+len(ports))
	}
	b, _ := BuildPing(all, ports, "")
	run("ping", b)
}

func hasRule(c cfgT, field, value, out string) bool {
	for _, r := range c.Routing.Rules {
		if r["outboundTag"] != out {
			continue
		}
		if list, ok := r[field].([]any); ok {
			for _, v := range list {
				if v == value {
					return true
				}
			}
		}
	}
	return false
}

func findOutbound(c cfgT, tag string) map[string]any {
	for _, o := range c.Outbounds {
		if o["tag"] == tag {
			return o
		}
	}
	return nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
