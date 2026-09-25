// Package parse разбирает ключи (vless://, vmess://, …) и подписки любых
// распространённых форматов в []*model.Server.
package parse

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }

// Schemes — поддерживаемые схемы ключей.
var Schemes = []string{"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}

// IsKey — строка похожа на ключ поддерживаемого протокола.
func IsKey(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, sc := range Schemes {
		if strings.HasPrefix(s, sc+"://") {
			return true
		}
	}
	return false
}

// ParseLink разбирает один ключ.
func ParseLink(link string) (*model.Server, error) {
	link = strings.TrimSpace(link)
	lower := strings.ToLower(link)
	var (
		s   *model.Server
		err error
	)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		s, err = parseVLESS(link)
	case strings.HasPrefix(lower, "vmess://"):
		s, err = parseVMess(link)
	case strings.HasPrefix(lower, "trojan://"):
		s, err = parseTrojan(link)
	case strings.HasPrefix(lower, "ss://"):
		s, err = parseSS(link)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		s, err = parseHy2(link)
	default:
		scheme := link
		if i := strings.Index(link, "://"); i >= 0 {
			scheme = link[:i]
		} else if len(scheme) > 20 {
			scheme = scheme[:20] + "…"
		}
		return nil, errf("неизвестный тип ключа %q (поддерживаются vless, vmess, trojan, ss, hy2)", scheme)
	}
	if err != nil {
		return nil, err
	}
	s.Link = link
	return finish(s)
}

func finish(s *model.Server) (*model.Server, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Protocol, err)
	}
	if s.Name == "" {
		s.Name = s.Endpoint()
	}
	s.ID = s.ComputeID()
	return s, nil
}

// normNetwork приводит название транспорта к виду harley.
func normNetwork(n string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "", "tcp", "raw":
		return "tcp", nil
	case "ws", "websocket":
		return "ws", nil
	case "grpc", "gun":
		return "grpc", nil
	case "httpupgrade":
		return "httpupgrade", nil
	case "xhttp", "splithttp":
		return "xhttp", nil
	case "kcp", "mkcp":
		return "kcp", nil
	case "h2", "http", "h3":
		return "", errf("транспорт %q удалён из xray-core — попроси у провайдера ключ с xhttp", n)
	case "quic":
		return "", errf("транспорт quic удалён из xray-core")
	}
	return "", errf("неизвестный транспорт %q", n)
}

// applyStreamQuery заполняет транспорт и TLS/Reality из параметров ссылки
// (общий формат для vless, trojan и ss с транспортами).
func applyStreamQuery(s *model.Server, q url.Values) error {
	net, err := normNetwork(first(q, "type", "network", "net"))
	if err != nil {
		return err
	}
	s.Network = net
	s.HeaderType = first(q, "headerType")
	s.Host = first(q, "host")
	s.Path = first(q, "path")
	s.ServiceName = first(q, "serviceName", "servicename")
	s.Authority = first(q, "authority")
	mode := first(q, "mode")
	switch net {
	case "grpc":
		s.GRPCMulti = strings.EqualFold(mode, "multi")
		if s.ServiceName == "" && s.Path != "" {
			s.ServiceName = strings.TrimPrefix(s.Path, "/")
			s.Path = ""
		}
	case "xhttp":
		s.XHTTPMode = mode
		if extra := first(q, "extra"); extra != "" {
			if !json.Valid([]byte(extra)) {
				return errf("xhttp: параметр extra — не JSON")
			}
			s.XHTTPExtra = json.RawMessage(extra)
		}
	}
	sec := strings.ToLower(first(q, "security"))
	switch sec {
	case "", "none":
		sec = "none"
	case "tls", "xtls":
		sec = "tls"
	case "reality":
	default:
		return errf("неизвестный security=%q", sec)
	}
	s.Security = sec
	s.SNI = first(q, "sni", "peer", "serverName")
	s.Fingerprint = first(q, "fp", "fingerprint")
	s.ALPN = splitList(first(q, "alpn"))
	s.AllowInsecure = truthy(first(q, "allowInsecure", "insecure", "allow_insecure"))
	s.PinSHA256 = first(q, "pcs", "pinSHA256")
	s.VerifyName = first(q, "vcn")
	s.PublicKey = first(q, "pbk", "publicKey")
	s.ShortID = first(q, "sid", "shortId")
	s.SpiderX = first(q, "spx", "spiderX")
	return nil
}

// vless://uuid@host:port?type=...&security=...#name
func parseVLESS(link string) (*model.Server, error) {
	u, err := splitURI(link)
	if err != nil {
		return nil, err
	}
	s := &model.Server{Protocol: model.VLESS, Name: u.Fragment, Address: u.Host, UUID: u.User}
	if s.Port, err = atoiPort(u.Port); err != nil {
		return nil, err
	}
	if err := applyStreamQuery(s, u.Query); err != nil {
		return nil, err
	}
	s.Flow = first(u.Query, "flow")
	s.Encryption = first(u.Query, "encryption")
	if s.Encryption == "" {
		s.Encryption = "none"
	}
	return s, nil
}

// vmessJSON — формат v2rayN: vmess://base64(json).
type vmessJSON struct {
	PS   string      `json:"ps"`
	Add  string      `json:"add"`
	Port flexString  `json:"port"`
	ID   string      `json:"id"`
	Aid  flexString  `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	SNI  string      `json:"sni"`
	ALPN string      `json:"alpn"`
	FP   string      `json:"fp"`
	Ins  flexString  `json:"allowInsecure"`
	Mode string      `json:"mode"`
	Xtra interface{} `json:"extra"`
}

// flexString принимает и число, и строку.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		*f = ""
		return nil
	}
	*f = flexString(n.String())
	return nil
}

func parseVMess(link string) (*model.Server, error) {
	body := strings.TrimSpace(link[len("vmess://"):])
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	if strings.Contains(body, "@") {
		// URI-форма vmess://uuid@host:port?… ('@' не бывает в base64).
		return parseVMessURI(link)
	}
	raw, ok := DecodeBase64(body)
	if !ok {
		return nil, errf("vmess: не удалось декодировать base64")
	}
	var v vmessJSON
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errf("vmess: неверный JSON: %v", err)
	}
	s := &model.Server{
		Protocol:    model.VMess,
		Name:        v.PS,
		Address:     strings.TrimSpace(v.Add),
		UUID:        strings.TrimSpace(v.ID),
		Encryption:  v.Scy,
		Host:        v.Host,
		Path:        v.Path,
		SNI:         v.SNI,
		Fingerprint: v.FP,
		ALPN:        splitList(v.ALPN),
	}
	var err error
	if s.Port, err = atoiPort(string(v.Port)); err != nil {
		return nil, err
	}
	s.AlterID, _ = strconv.Atoi(string(v.Aid))
	if s.Encryption == "" {
		s.Encryption = "auto"
	}
	if s.Network, err = normNetwork(v.Net); err != nil {
		return nil, err
	}
	switch s.Network {
	case "tcp":
		s.HeaderType = v.Type
	case "grpc":
		s.ServiceName = v.Path
		s.Path = ""
		s.GRPCMulti = v.Type == "multi" || v.Mode == "multi"
	case "xhttp":
		s.XHTTPMode = v.Type
		if v.Mode != "" {
			s.XHTTPMode = v.Mode
		}
		if v.Xtra != nil {
			if b, err := json.Marshal(v.Xtra); err == nil && string(b) != `""` {
				s.XHTTPExtra = b
			}
		}
	}
	switch strings.ToLower(v.TLS) {
	case "tls":
		s.Security = "tls"
	case "reality":
		return nil, errf("vmess: Reality не поддерживается протоколом VMess")
	default:
		s.Security = "none"
	}
	s.AllowInsecure = truthy(string(v.Ins))
	return s, nil
}

func parseVMessURI(link string) (*model.Server, error) {
	u, err := splitURI(link)
	if err != nil {
		return nil, err
	}
	s := &model.Server{Protocol: model.VMess, Name: u.Fragment, Address: u.Host, UUID: u.User}
	if s.Port, err = atoiPort(u.Port); err != nil {
		return nil, err
	}
	if err := applyStreamQuery(s, u.Query); err != nil {
		return nil, err
	}
	s.Encryption = first(u.Query, "encryption", "scy")
	if s.Encryption == "" {
		s.Encryption = "auto"
	}
	s.AlterID, _ = strconv.Atoi(first(u.Query, "aid", "alterId"))
	return s, nil
}

// trojan://password@host:port?security=tls&sni=...#name
func parseTrojan(link string) (*model.Server, error) {
	u, err := splitURI(link)
	if err != nil {
		return nil, err
	}
	s := &model.Server{Protocol: model.Trojan, Name: u.Fragment, Address: u.Host, Password: u.User}
	if s.Port, err = atoiPort(u.Port); err != nil {
		return nil, err
	}
	if first(u.Query, "security") == "" {
		u.Query.Set("security", "tls") // trojan по умолчанию поверх TLS
	}
	if err := applyStreamQuery(s, u.Query); err != nil {
		return nil, err
	}
	s.Flow = first(u.Query, "flow")
	return s, nil
}

// ss://base64(method:password)@host:port#name (SIP002),
// ss://method:password@host:port#name (2022, без base64),
// ss://base64(method:password@host:port)#name (старый формат).
func parseSS(link string) (*model.Server, error) {
	body := link[len("ss://"):]
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name = unescape(body[i+1:])
		body = body[:i]
	}
	if !strings.Contains(body, "@") {
		// Старый формат: всё закодировано целиком.
		q := ""
		if i := strings.IndexByte(body, '?'); i >= 0 {
			body, q = body[:i], body[i:]
		}
		dec, ok := DecodeBase64(strings.TrimSuffix(body, "/"))
		if !ok {
			return nil, errf("ss: не удалось декодировать base64")
		}
		body = string(dec) + q
	}
	u, err := splitURI("ss://" + body)
	if err != nil {
		return nil, err
	}
	s := &model.Server{Protocol: model.Shadowsocks, Name: name, Address: u.Host}
	if s.Port, err = atoiPort(u.Port); err != nil {
		return nil, err
	}
	userinfo := u.User
	if !strings.Contains(userinfo, ":") {
		if dec, ok := DecodeBase64(u.RawUser); ok {
			userinfo = string(dec)
		}
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	if !ok {
		return nil, errf("ss: не удалось разобрать метод и пароль")
	}
	s.Method = strings.ToLower(method)
	s.Password = pass
	if !knownSSMethod(s.Method) {
		return nil, errf("ss: метод %q не поддерживается xray", method)
	}
	if p := first(u.Query, "plugin"); p != "" {
		return nil, errf("ss: плагины (%s) не поддерживаются xray", strings.SplitN(p, ";", 2)[0])
	}
	if err := applyStreamQuery(s, u.Query); err != nil {
		return nil, err
	}
	return s, nil
}

func knownSSMethod(m string) bool {
	switch m {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
		"xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	}
	return false
}

// hysteria2://auth@host:port[,ports]/?sni=&obfs=salamander&obfs-password=&insecure=1#name
func parseHy2(link string) (*model.Server, error) {
	u, err := splitURI(link)
	if err != nil {
		return nil, err
	}
	s := &model.Server{Protocol: model.Hysteria2, Name: u.Fragment, Address: u.Host, Password: u.User}
	portSpec := u.Port
	if portSpec == "" {
		portSpec = "443"
	}
	if strings.ContainsAny(portSpec, ",-") {
		// Мультипорт: первый порт — основной, весь список — для port hopping.
		s.HopPorts = portSpec
		firstPort := strings.FieldsFunc(portSpec, func(r rune) bool { return r == ',' || r == '-' })
		if len(firstPort) == 0 {
			return nil, errf("hy2: неверный порт %q", portSpec)
		}
		portSpec = firstPort[0]
	}
	if s.Port, err = atoiPort(portSpec); err != nil {
		return nil, err
	}
	if mp := first(u.Query, "mport"); mp != "" && s.HopPorts == "" {
		s.HopPorts = mp
	}
	s.Network = "hysteria"
	s.Security = "tls"
	s.SNI = first(u.Query, "sni", "peer")
	s.AllowInsecure = truthy(first(u.Query, "insecure", "allowInsecure"))
	s.PinSHA256 = first(u.Query, "pinSHA256")
	s.ALPN = splitList(first(u.Query, "alpn"))
	s.Fingerprint = first(u.Query, "fp")
	s.Obfs = strings.ToLower(first(u.Query, "obfs"))
	s.ObfsPassword = first(u.Query, "obfs-password", "obfs_password", "obfsPassword")
	if s.Obfs != "" && s.Obfs != "salamander" {
		return nil, errf("hy2: обфускация %q не поддерживается (только salamander)", s.Obfs)
	}
	s.UpMbps = atoiMbps(first(u.Query, "upmbps", "up"))
	s.DownMbps = atoiMbps(first(u.Query, "downmbps", "down"))
	return s, nil
}

func atoiMbps(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "mbps"), " ")
	n, _ := strconv.Atoi(s)
	return n
}
