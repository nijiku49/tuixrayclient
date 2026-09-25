// Package xray генерирует конфиги xray-core и управляет его процессом.
package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/store"
)

// Теги.
const (
	TagProxy  = "proxy"
	TagDirect = "direct"
	TagBlock  = "block"
	TagDNSOut = "dns-out"
	TagDNSIn  = "dns-internal"
	TagTun    = "tun-in"
	TagSocks  = "socks-in"
	TagHTTP   = "http-in"
)

// Options — всё, что нужно для генерации конфига подключения.
type Options struct {
	Mode        string
	Listen      string
	SocksPort   int
	HTTPPort    int // 0 — не поднимать HTTP-прокси
	MetricsPort int // 0 — без статистики
	TunName     string
	TunMTU      int
	// BindInterface — физический интерфейс, через который в режиме TUN
	// уходит трафик к серверу и direct (иначе он зациклится в tun).
	BindInterface string
	// ServerHosts — заранее разрешённые адреса серверов (домен → IP) для
	// dns.hosts: в режиме TUN системный DNS уже идёт через туннель.
	ServerHosts map[string][]string
	Routing     string
	Custom      store.CustomRules
	DNS         []string
	LogLevel    string
}

// OptionsFromSettings — Options из настроек пользователя.
func OptionsFromSettings(st store.Settings) Options {
	return Options{
		Mode:      st.Mode,
		Listen:    st.ListenAddr,
		SocksPort: st.SocksPort,
		HTTPPort:  st.HTTPPort,
		TunName:   st.TunName,
		TunMTU:    st.TunMTU,
		Routing:   st.Routing,
		Custom:    st.Custom,
		DNS:       st.DNS,
		LogLevel:  st.LogLevel,
	}
}

type obj = map[string]any

// privateCIDRs — локальные сети всегда напрямую (без geoip.dat).
var privateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32",
	"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
}

// RU-пресет.
var (
	ruDirectDomains = []string{"geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai"}
	ruDirectIPs     = []string{"geoip:ru"}
)

// NeedsGeoFiles — нужны ли geoip.dat/geosite.dat для выбранной маршрутизации.
func NeedsGeoFiles(o Options) bool {
	switch o.Routing {
	case store.RouteRUDirect:
		return true
	case store.RouteCustom:
		c := o.Custom
		for _, list := range [][]string{c.DirectDomains, c.DirectIPs, c.ProxyDomains, c.ProxyIPs, c.BlockDomains, c.BlockIPs} {
			for _, v := range list {
				if strings.HasPrefix(v, "geosite:") || strings.HasPrefix(v, "geoip:") || strings.HasPrefix(v, "ext:") {
					return true
				}
			}
		}
	}
	return false
}

// Build генерирует конфиг xray для подключения к серверу.
func Build(s *model.Server, o Options) ([]byte, error) {
	outs, err := Outbounds(s, TagProxy, "", o.BindInterface)
	if err != nil {
		return nil, err
	}
	if o.Mode == store.ModeTUN {
		// Адрес сервера разрешаем через hosts, а не через системный DNS.
		setSockopt(outs[0], "domainStrategy", "UseIP")
	}

	sniff := obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	listen := o.Listen
	if listen == "" {
		listen = "127.0.0.1"
	}
	var inbounds []any
	if o.Mode == store.ModeTUN {
		inbounds = append(inbounds, obj{
			"tag": TagTun, "protocol": "tun",
			"settings": obj{"name": o.TunName, "MTU": o.TunMTU},
			"sniffing": sniff,
		})
	}
	if o.SocksPort > 0 {
		inbounds = append(inbounds, obj{
			"tag": TagSocks, "listen": listen, "port": o.SocksPort, "protocol": "socks",
			"settings": obj{"auth": "noauth", "udp": true},
			"sniffing": sniff,
		})
	}
	if o.HTTPPort > 0 {
		inbounds = append(inbounds, obj{
			"tag": TagHTTP, "listen": listen, "port": o.HTTPPort, "protocol": "http",
			"sniffing": sniff,
		})
	}
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("не задан ни один вход: включи TUN или укажи порт SOCKS/HTTP")
	}

	direct := obj{"tag": TagDirect, "protocol": "freedom", "settings": obj{"domainStrategy": "UseIP"}}
	block := obj{"tag": TagBlock, "protocol": "blackhole"}
	outbounds := []any{outs[0]}
	for _, d := range outs[1:] {
		outbounds = append(outbounds, d)
	}
	outbounds = append(outbounds, direct, block)
	if o.Mode == store.ModeTUN {
		outbounds = append(outbounds, obj{"tag": TagDNSOut, "protocol": "dns"})
		if o.BindInterface != "" {
			setSockopt(direct, "interface", o.BindInterface)
		}
	}

	rules, strategy := routingRules(o)

	dnsServers := o.DNS
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1", "8.8.8.8"}
	}
	dns := obj{"servers": dnsServers, "tag": TagDNSIn, "queryStrategy": "UseIP"}
	if len(o.ServerHosts) > 0 {
		dns["hosts"] = o.ServerHosts
	}

	level := o.LogLevel
	if level == "" {
		level = "warning"
	}
	cfg := obj{
		"log":       obj{"loglevel": level, "access": "none", "dnsLog": false},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   obj{"domainStrategy": strategy, "rules": rules},
	}
	if o.MetricsPort > 0 {
		cfg["stats"] = obj{}
		cfg["metrics"] = obj{"tag": "metrics", "listen": net.JoinHostPort("127.0.0.1", strconv.Itoa(o.MetricsPort))}
		cfg["policy"] = obj{"system": obj{
			"statsOutboundUplink": true, "statsOutboundDownlink": true,
		}}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func routingRules(o Options) ([]any, string) {
	var rules []any
	strategy := "AsIs"
	if o.Mode == store.ModeTUN {
		// DNS-запросы системы перехватываем и отдаём встроенному DNS xray.
		rules = append(rules, obj{"inboundTag": []string{TagTun}, "port": "53", "outboundTag": TagDNSOut})
	}
	// Запросы встроенного DNS — только через VPN (без утечек).
	rules = append(rules, obj{"inboundTag": []string{TagDNSIn}, "outboundTag": TagProxy})
	rules = append(rules, obj{"ip": privateCIDRs, "outboundTag": TagDirect})
	rules = append(rules, obj{"domain": []string{"domain:localhost"}, "outboundTag": TagDirect})

	add := func(field string, values []string, out string) {
		if len(values) > 0 {
			rules = append(rules, obj{field: values, "outboundTag": out})
			if field == "ip" {
				strategy = "IPIfNonMatch"
			}
		}
	}
	switch o.Routing {
	case store.RouteRUDirect:
		add("domain", ruDirectDomains, TagDirect)
		add("ip", ruDirectIPs, TagDirect)
	case store.RouteCustom:
		c := o.Custom
		add("domain", c.BlockDomains, TagBlock)
		add("ip", c.BlockIPs, TagBlock)
		add("domain", c.ProxyDomains, TagProxy)
		add("ip", c.ProxyIPs, TagProxy)
		add("domain", c.DirectDomains, TagDirect)
		add("ip", c.DirectIPs, TagDirect)
		if c.DefaultDirect {
			rules = append(rules, obj{"network": "tcp,udp", "outboundTag": TagDirect})
		}
	}
	return rules, strategy
}

// Outbounds строит outbound сервера с тегом tag. Вспомогательные outbound
// (dialerProxy-цепочки из xray-подписок) получают теги с префиксом
// depPrefix и идут следом.
func Outbounds(s *model.Server, tag, depPrefix, bindIface string) ([]obj, error) {
	if len(s.Raw) > 0 {
		return rawOutbounds(s, tag, depPrefix, bindIface)
	}
	ob, err := buildOutbound(s)
	if err != nil {
		return nil, err
	}
	ob["tag"] = tag
	if bindIface != "" {
		setSockopt(ob, "interface", bindIface)
	}
	return []obj{ob}, nil
}

func buildOutbound(s *model.Server) (obj, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	ob := obj{}
	switch s.Protocol {
	case model.VLESS:
		enc := s.Encryption
		if enc == "" {
			enc = "none"
		}
		user := obj{"id": s.UUID, "encryption": enc, "level": 0}
		if s.Flow != "" {
			user["flow"] = s.Flow
		}
		ob["protocol"] = "vless"
		ob["settings"] = obj{"vnext": []any{obj{"address": s.Address, "port": s.Port, "users": []any{user}}}}
	case model.VMess:
		sec := s.Encryption
		if sec == "" {
			sec = "auto"
		}
		ob["protocol"] = "vmess"
		ob["settings"] = obj{"vnext": []any{obj{"address": s.Address, "port": s.Port,
			"users": []any{obj{"id": s.UUID, "alterId": s.AlterID, "security": sec, "level": 0}}}}}
	case model.Trojan:
		ob["protocol"] = "trojan"
		ob["settings"] = obj{"servers": []any{obj{"address": s.Address, "port": s.Port, "password": s.Password}}}
	case model.Shadowsocks:
		method := s.Method
		if method == "chacha20-poly1305" {
			method = "chacha20-ietf-poly1305"
		}
		ob["protocol"] = "shadowsocks"
		ob["settings"] = obj{"servers": []any{obj{"address": s.Address, "port": s.Port,
			"method": method, "password": s.Password, "uot": true}}}
	case model.Hysteria2:
		ob["protocol"] = "hysteria"
		ob["settings"] = obj{"version": 2, "address": s.Address, "port": s.Port}
	default:
		return nil, fmt.Errorf("неподдерживаемый протокол %q", s.Protocol)
	}
	ss, err := streamSettings(s)
	if err != nil {
		return nil, err
	}
	ob["streamSettings"] = ss
	return ob, nil
}

func streamSettings(s *model.Server) (obj, error) {
	network := s.Network
	if network == "" {
		network = "tcp"
	}
	ss := obj{"network": network}
	switch network {
	case "tcp":
		if s.HeaderType == "http" {
			req := obj{}
			if s.Path != "" {
				req["path"] = splitList(s.Path)
			}
			if s.Host != "" {
				req["headers"] = obj{"Host": splitList(s.Host)}
			}
			ss["tcpSettings"] = obj{"header": obj{"type": "http", "request": req}}
		}
	case "ws":
		ss["wsSettings"] = nonEmpty(obj{"path": s.Path, "host": s.Host})
	case "httpupgrade":
		ss["httpupgradeSettings"] = nonEmpty(obj{"path": s.Path, "host": s.Host})
	case "grpc":
		g := nonEmpty(obj{"serviceName": s.ServiceName, "authority": s.Authority})
		if s.GRPCMulti {
			g["multiMode"] = true
		}
		ss["grpcSettings"] = g
	case "xhttp":
		x := nonEmpty(obj{"path": s.Path, "host": s.Host, "mode": s.XHTTPMode})
		if len(s.XHTTPExtra) > 0 {
			x["extra"] = json.RawMessage(s.XHTTPExtra)
		}
		ss["xhttpSettings"] = x
	case "kcp":
	case "hysteria":
		ss["hysteriaSettings"] = obj{"version": 2, "auth": s.Password}
		var fm obj
		if s.Obfs == "salamander" {
			fm = obj{"udp": []any{obj{"type": "salamander", "settings": obj{"password": s.ObfsPassword}}}}
		}
		qp := obj{}
		if s.UpMbps > 0 {
			qp["brutalUp"] = fmt.Sprintf("%d mbps", s.UpMbps)
		}
		if s.DownMbps > 0 {
			qp["brutalDown"] = fmt.Sprintf("%d mbps", s.DownMbps)
		}
		if s.HopPorts != "" {
			qp["udpHop"] = obj{"ports": s.HopPorts}
		}
		if len(qp) > 0 {
			if fm == nil {
				fm = obj{}
			}
			fm["quicParams"] = qp
		}
		if fm != nil {
			ss["finalmask"] = fm
		}
	default:
		return nil, fmt.Errorf("неподдерживаемый транспорт %q", network)
	}

	sec := s.Security
	if sec == "" {
		sec = "none"
	}
	ss["security"] = sec
	switch sec {
	case "tls":
		t := nonEmpty(obj{"serverName": s.SNI, "fingerprint": s.Fingerprint,
			"pinnedPeerCertSha256": s.PinSHA256, "verifyPeerCertByName": s.VerifyName})
		alpn := s.ALPN
		if s.Protocol == model.Hysteria2 && len(alpn) == 0 {
			alpn = []string{"h3"}
		}
		if len(alpn) > 0 {
			t["alpn"] = alpn
		}
		// allowInsecure удалён из xray-core (2026-06): его наличие ломает
		// запуск. Если сервер требует «insecure» без pin — подключение
		// упадёт с ошибкой сертификата, и это видно в логах.
		ss["tlsSettings"] = t
	case "reality":
		fp := s.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		ss["realitySettings"] = nonEmpty(obj{"serverName": s.SNI, "fingerprint": fp,
			"publicKey": s.PublicKey, "shortId": s.ShortID, "spiderX": s.SpiderX})
	case "none":
	default:
		return nil, fmt.Errorf("неизвестный security %q", sec)
	}
	return ss, nil
}

// rawOutbounds — outbound из xray-JSON подписки «как есть», с новым тегом.
func rawOutbounds(s *model.Server, tag, depPrefix, bindIface string) ([]obj, error) {
	var main obj
	if err := json.Unmarshal(s.Raw, &main); err != nil {
		return nil, fmt.Errorf("повреждённый outbound: %w", err)
	}
	var deps []obj
	if len(s.RawDeps) > 0 {
		if err := json.Unmarshal(s.RawDeps, &deps); err != nil {
			return nil, fmt.Errorf("повреждённая цепочка outbound: %w", err)
		}
	}
	rename := map[string]string{}
	for _, d := range deps {
		if t, _ := d["tag"].(string); t != "" {
			rename[t] = depPrefix + t
		}
	}
	all := append([]obj{main}, deps...)
	for i, ob := range all {
		if i == 0 {
			ob["tag"] = tag
		} else if t, _ := ob["tag"].(string); t != "" {
			ob["tag"] = rename[t]
		}
		stripInsecure(ob)
		if ss, ok := ob["streamSettings"].(obj); ok {
			if so, ok := ss["sockopt"].(obj); ok {
				if dp, _ := so["dialerProxy"].(string); dp != "" && rename[dp] != "" {
					so["dialerProxy"] = rename[dp]
				}
			}
		}
		if ps, ok := ob["proxySettings"].(obj); ok {
			if t, _ := ps["tag"].(string); rename[t] != "" {
				ps["tag"] = rename[t]
			}
		}
		// Привязка к интерфейсу нужна только тем, кто сам ходит в сеть:
		// последнему в цепочке (без dialerProxy).
		if bindIface != "" && !hasDialer(ob) {
			setSockopt(ob, "interface", bindIface)
		}
	}
	return all, nil
}

func hasDialer(ob obj) bool {
	if ss, ok := ob["streamSettings"].(obj); ok {
		if so, ok := ss["sockopt"].(obj); ok {
			if dp, _ := so["dialerProxy"].(string); dp != "" {
				return true
			}
		}
	}
	if _, ok := ob["proxySettings"].(obj); ok {
		return true
	}
	return false
}

func stripInsecure(ob obj) {
	if ss, ok := ob["streamSettings"].(obj); ok {
		if t, ok := ss["tlsSettings"].(obj); ok {
			delete(t, "allowInsecure")
		}
	}
}

func setSockopt(ob obj, key string, val any) {
	ss, ok := ob["streamSettings"].(obj)
	if !ok {
		ss = obj{}
		ob["streamSettings"] = ss
	}
	so, ok := ss["sockopt"].(obj)
	if !ok {
		so = obj{}
		ss["sockopt"] = so
	}
	so[key] = val
}

func nonEmpty(m obj) obj {
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
	return m
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// BuildPing — конфиг для URL-теста: у каждого сервера свой SOCKS-вход на
// 127.0.0.1:ports[i], трафик с которого идёт только в его outbound.
// bindIface — физический интерфейс, если сейчас активен TUN (иначе тест
// пошёл бы через текущий туннель).
func BuildPing(servers []*model.Server, ports []int, bindIface string) ([]byte, []error) {
	errs := make([]error, len(servers))
	var (
		inbounds, outbounds, rules []any
	)
	for i, s := range servers {
		tag := "t" + strconv.Itoa(i)
		outs, err := Outbounds(s, tag, tag+"-", bindIface)
		if err != nil {
			errs[i] = err
			continue
		}
		for _, o := range outs {
			outbounds = append(outbounds, o)
		}
		inTag := "in" + strconv.Itoa(i)
		inbounds = append(inbounds, obj{
			"tag": inTag, "listen": "127.0.0.1", "port": ports[i], "protocol": "socks",
			"settings": obj{"auth": "noauth", "udp": false},
		})
		rules = append(rules, obj{"inboundTag": []string{inTag}, "outboundTag": tag})
	}
	if len(inbounds) == 0 {
		return nil, errs
	}
	outbounds = append(outbounds, obj{"tag": TagBlock, "protocol": "blackhole"})
	cfg := obj{
		"log":       obj{"loglevel": "error", "access": "none"},
		"inbounds":  inbounds,
		"outbounds": append([]any{obj{"tag": "default-block", "protocol": "blackhole"}}, outbounds...),
		"routing":   obj{"rules": rules},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		for i := range errs {
			if errs[i] == nil {
				errs[i] = err
			}
		}
		return nil, errs
	}
	return b, errs
}
