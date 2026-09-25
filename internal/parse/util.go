package parse

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// DecodeBase64 терпимо декодирует base64: std/url, с паддингом и без,
// с переводами строк внутри.
func DecodeBase64(s string) ([]byte, bool) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	// Паддинг может быть неполным.
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil {
			return b, true
		}
	}
	return nil, false
}

// uri — результат ручного разбора scheme://userinfo@host:port/path?query#fragment.
// Стандартный url.Parse не годится: в ключах встречаются порты-диапазоны
// (hy2), нестандартные символы в паролях и именах.
type uri struct {
	Scheme   string
	User     string // уже раскодированный
	RawUser  string
	Host     string
	Port     string
	Path     string
	Query    url.Values
	Fragment string
}

func splitURI(s string) (*uri, error) {
	u := &uri{}
	i := strings.Index(s, "://")
	if i < 0 {
		return nil, errf("не похоже на ссылку: нет «://»")
	}
	u.Scheme = strings.ToLower(s[:i])
	rest := s[i+3:]
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		u.Fragment = unescape(rest[j+1:])
		rest = rest[:j]
	}
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		q, _ := url.ParseQuery(rest[j+1:])
		if q == nil {
			q = url.Values{}
		}
		u.Query = q
		rest = rest[:j]
	} else {
		u.Query = url.Values{}
	}
	if j := strings.LastIndexByte(rest, '@'); j >= 0 {
		u.RawUser = rest[:j]
		u.User = unescape(u.RawUser)
		rest = rest[j+1:]
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		u.Path = rest[j:]
		rest = rest[:j]
	}
	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, err
	}
	u.Host, u.Port = host, port
	return u, nil
}

func splitHostPort(hp string) (string, string, error) {
	if hp == "" {
		return "", "", errf("нет адреса сервера")
	}
	if strings.HasPrefix(hp, "[") {
		end := strings.IndexByte(hp, ']')
		if end < 0 {
			return "", "", errf("неверный IPv6-адрес %q", hp)
		}
		host := hp[1:end]
		rest := hp[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return host, "", nil
		}
		return host, rest[1:], nil
	}
	i := strings.LastIndexByte(hp, ':')
	if i < 0 {
		return hp, "", nil
	}
	return hp[:i], hp[i+1:], nil
}

func unescape(s string) string {
	if r, err := url.PathUnescape(s); err == nil {
		return r
	}
	return s
}

func atoiPort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p <= 0 || p > 65535 {
		return 0, errf("неверный порт %q", s)
	}
	return p, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// first возвращает первое непустое значение из query по списку ключей.
func first(q map[string][]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := q[k]; ok && len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}
