package parse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

// Clash / mihomo YAML: proxies: [{name, type, server, port, …}].

type clashConfig struct {
	Proxies []map[string]any `yaml:"proxies"`
}

var clashProxiesRe = regexp.MustCompile(`(?m)^proxies:\s*$|^proxies:\s*\[`)

func looksLikeClash(b []byte) bool {
	return clashProxiesRe.Match(b)
}

func parseClash(b []byte) ([]*model.Server, []string, error) {
	var c clashConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, nil, errf("Clash YAML: %v", err)
	}
	var (
		out  []*model.Server
		errs []string
	)
	for _, p := range c.Proxies {
		s, err := clashProxy(clashMap(p))
		if err != nil {
			errs = append(errs, fmt.Sprintf("Clash: %s: %v", clashMap(p).str("name"), err))
			continue
		}
		if s == nil {
			continue
		}
		if srv, err := finish(s); err == nil {
			out = append(out, srv)
		} else {
			errs = append(errs, "Clash: "+s.Name+": "+err.Error())
		}
	}
	return out, errs, nil
}

type clashMap map[string]any

func (m clashMap) str(k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func (m clashMap) int(k string) int {
	n, _ := strconv.Atoi(strings.Fields(m.str(k) + " 0")[0])
	return n
}

func (m clashMap) bool(k string) bool {
	if b, ok := m[k].(bool); ok {
		return b
	}
	return truthy(m.str(k))
}

func (m clashMap) sub(k string) clashMap {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return clashMap{}
}

func (m clashMap) list(k string) []string {
	switch v := m[k].(type) {
	case []any:
		var out []string
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case string:
		return splitList(v)
	}
	return nil
}

func clashProxy(p clashMap) (*model.Server, error) {
	s := &model.Server{Name: p.str("name"), Address: p.str("server"), Port: p.int("port")}
	switch strings.ToLower(p.str("type")) {
	case "vless":
		s.Protocol, s.UUID, s.Flow, s.Encryption = model.VLESS, p.str("uuid"), p.str("flow"), "none"
		if e := p.str("encryption"); e != "" {
			s.Encryption = e
		}
	case "vmess":
		s.Protocol, s.UUID, s.AlterID = model.VMess, p.str("uuid"), p.int("alterId")
		s.Encryption = p.str("cipher")
		if s.Encryption == "" {
			s.Encryption = "auto"
		}
	case "trojan":
		s.Protocol, s.Password = model.Trojan, p.str("password")
	case "ss":
		if p.str("plugin") != "" {
			return nil, errf("плагины ss не поддерживаются xray")
		}
		s.Protocol, s.Method, s.Password = model.Shadowsocks, strings.ToLower(p.str("cipher")), p.str("password")
	case "hysteria2", "hy2":
		s.Protocol, s.Password, s.Network, s.Security = model.Hysteria2, p.str("password"), "hysteria", "tls"
		if s.Password == "" {
			s.Password = p.str("auth")
		}
		s.Obfs, s.ObfsPassword = strings.ToLower(p.str("obfs")), p.str("obfs-password")
		s.HopPorts = p.str("ports")
		s.UpMbps, s.DownMbps = atoiMbps(p.str("up")), atoiMbps(p.str("down"))
		s.SNI, s.AllowInsecure, s.ALPN = p.str("sni"), p.bool("skip-cert-verify"), p.list("alpn")
		s.Fingerprint = p.str("client-fingerprint")
		return s, nil
	default:
		return nil, nil // http, socks5, wireguard, … — не наши
	}

	// Транспорт.
	netw, err := normNetwork(p.str("network"))
	if err != nil {
		return nil, err
	}
	s.Network = netw
	switch netw {
	case "ws":
		o := p.sub("ws-opts")
		s.Path = o.str("path")
		s.Host = o.sub("headers").str("Host")
	case "grpc":
		s.ServiceName = p.sub("grpc-opts").str("grpc-service-name")
	case "httpupgrade":
		o := p.sub("http-upgrade-opts")
		s.Path, s.Host = o.str("path"), o.str("host")
	case "xhttp":
		o := p.sub("xhttp-opts")
		s.Path, s.Host, s.XHTTPMode = o.str("path"), o.str("host"), o.str("mode")
	}

	// TLS / Reality.
	s.Security = "none"
	if p.bool("tls") || s.Protocol == model.Trojan {
		s.Security = "tls"
	}
	s.SNI = p.str("servername")
	if s.SNI == "" {
		s.SNI = p.str("sni")
	}
	s.AllowInsecure = p.bool("skip-cert-verify")
	s.Fingerprint = p.str("client-fingerprint")
	s.ALPN = p.list("alpn")
	if r := p.sub("reality-opts"); len(r) > 0 {
		s.Security = "reality"
		s.PublicKey, s.ShortID = r.str("public-key"), r.str("short-id")
	}
	return s, nil
}
