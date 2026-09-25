package parse

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

// Форматы тела подписки.
const (
	FormatBase64  = "base64"
	FormatPlain   = "plain"
	FormatXray    = "xray-json"
	FormatSingBox = "sing-box"
	FormatClash   = "clash"
)

// Result — результат разбора подписки или вставленного текста.
type Result struct {
	Servers []*model.Server
	// Errors — строки, которые не удалось разобрать (импорт остальных продолжается).
	Errors []string
	Format string
	// Meta — метаданные из комментариев в теле (#profile-title: …),
	// ключи в нижнем регистре.
	Meta map[string]string
}

// ParseBody определяет формат тела подписки по содержимому и разбирает его.
func ParseBody(body []byte) Result {
	return parseBody(body, 0)
}

func parseBody(body []byte, depth int) Result {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimSpace(body)
	res := Result{Meta: map[string]string{}}
	if len(trimmed) == 0 {
		res.Errors = append(res.Errors, "пустой ответ")
		return res
	}
	switch {
	case trimmed[0] == '{' || trimmed[0] == '[':
		var (
			servers []*model.Server
			errs    []string
			err     error
		)
		if looksLikeXrayJSON(trimmed) {
			res.Format = FormatXray
			servers, errs, err = parseXrayJSON(trimmed)
		} else if looksLikeSingBox(trimmed) {
			res.Format = FormatSingBox
			servers, errs, err = parseSingBox(trimmed)
		} else {
			res.Errors = append(res.Errors, "JSON не похож ни на xray, ни на sing-box конфиг")
			return res
		}
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
		res.Servers, res.Errors = servers, append(res.Errors, errs...)
		return res
	case looksLikeClash(trimmed):
		res.Format = FormatClash
		servers, errs, err := parseClash(trimmed)
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
		res.Servers, res.Errors = servers, append(res.Errors, errs...)
		return res
	case bytes.Contains(trimmed, []byte("://")):
		res.Format = FormatPlain
		res.Servers, res.Errors, res.Meta = parseLines(string(trimmed))
		return res
	}
	if depth == 0 {
		if dec, ok := DecodeBase64(string(trimmed)); ok {
			r := parseBody(dec, depth+1)
			if r.Format == FormatPlain {
				r.Format = FormatBase64
			}
			return r
		}
	}
	res.Errors = append(res.Errors, "не удалось распознать формат (ожидались ключи, base64, xray/sing-box JSON или Clash YAML)")
	return res
}

var keyStartRe = regexp.MustCompile(`(?i)(vless|vmess|trojan|ss|hysteria2|hy2|https?)://`)

// SplitKeys разрезает текст на отдельные ключи: построчно и по пробелам
// перед схемой (терминал при вставке может склеить строки через пробел).
// Пробелы внутри имени ключа («#My Server») разрез не вызывают, если
// за ними не идёт новая схема.
func SplitKeys(text string) []string {
	text = strings.ReplaceAll(text, "\r", "\n")
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		starts := []int{0}
		for _, m := range keyStartRe.FindAllStringIndex(line, -1) {
			if m[0] > 0 && (line[m[0]-1] == ' ' || line[m[0]-1] == '\t') {
				starts = append(starts, m[0])
			}
		}
		for i, st := range starts {
			end := len(line)
			if i+1 < len(starts) {
				end = starts[i+1]
			}
			if piece := strings.TrimSpace(line[st:end]); piece != "" {
				out = append(out, piece)
			}
		}
	}
	return out
}

func parseLines(text string) ([]*model.Server, []string, map[string]string) {
	var (
		servers []*model.Server
		errs    []string
	)
	meta := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			if k, v, ok := strings.Cut(strings.TrimLeft(line, "#/ "), ":"); ok {
				k = strings.ToLower(strings.TrimSpace(k))
				if isMetaKey(k) {
					meta[k] = strings.TrimSpace(v)
				}
			}
			continue
		}
		for _, key := range SplitKeys(line) {
			if !strings.Contains(key, "://") {
				continue
			}
			s, err := ParseLink(key)
			if err != nil {
				errs = append(errs, shorten(key)+": "+err.Error())
				continue
			}
			servers = append(servers, s)
		}
	}
	return servers, errs, meta
}

func isMetaKey(k string) bool {
	switch k {
	case "profile-title", "subscription-userinfo", "profile-update-interval",
		"support-url", "announce", "profile-web-page-url":
		return true
	}
	return false
}

func shorten(s string) string {
	if i := strings.Index(s, "://"); i >= 0 && len(s) > i+3+12 {
		return s[:i+3+12] + "…"
	}
	return s
}

// Input — результат автоопределения вставленного пользователем текста.
type Input struct {
	SubURLs []string
	Result
}

// DetectInput разбирает всё, что пользователь вставил: ссылки на подписки,
// один или много ключей, base64-блоб, JSON или YAML целиком.
func DetectInput(text string) Input {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\uFEFF"))
	var in Input
	if text == "" {
		return in
	}
	// Цельный JSON/YAML/base64 — сразу как тело подписки.
	if text[0] == '{' || text[0] == '[' || looksLikeClash([]byte(text)) {
		in.Result = ParseBody([]byte(text))
		return in
	}
	var rest []string
	for _, piece := range SplitKeys(text) {
		lower := strings.ToLower(piece)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			in.SubURLs = append(in.SubURLs, piece)
			continue
		}
		rest = append(rest, piece)
	}
	if len(rest) > 0 {
		in.Result = ParseBody([]byte(strings.Join(rest, "\n")))
	}
	if len(in.SubURLs) == 0 && len(in.Servers) == 0 && len(in.Errors) == 0 {
		in.Errors = append(in.Errors, "не найдено ни ссылок, ни ключей")
	}
	return in
}
