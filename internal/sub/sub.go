// Package sub загружает подписки так же, как это делает Happ: с «правильным»
// User-Agent, HWID-заголовками и разбором метаданных профиля.
package sub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/parse"
)

// DefaultUserAgent — UA, на который панели (Remnawave, Marzban, 3x-ui)
// отдают подписку в формате для Happ.
const DefaultUserAgent = "Happ/3.8.1"

// MaxBody — ограничение размера ответа подписки.
const MaxBody = 16 << 20

// Meta — метаданные профиля из заголовков ответа или комментариев в теле.
type Meta struct {
	Title         string
	Info          model.UserInfo
	IntervalHours int
	SupportURL    string
	WebPage       string
	Announce      string
}

// Options — параметры запроса.
type Options struct {
	UserAgent string
	HWID      string // пусто — не отправлять
	Timeout   time.Duration
	Client    *http.Client // для тестов; по умолчанию — свой
}

// Result — загруженная и разобранная подписка.
type Result struct {
	parse.Result
	Meta Meta
	Body []byte
}

// Fetch загружает подписку и разбирает её по содержимому.
func Fetch(ctx context.Context, rawURL string, opt Options) (*Result, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("неверная ссылка на подписку: %q", rawURL)
	}
	if opt.Timeout == 0 {
		opt.Timeout = 20 * time.Second
	}
	if opt.UserAgent == "" {
		opt.UserAgent = DefaultUserAgent
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{Timeout: opt.Timeout}
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opt.UserAgent)
	req.Header.Set("Accept", "*/*")
	if opt.HWID != "" {
		req.Header.Set("X-HWID", opt.HWID)
		req.Header.Set("X-Device-OS", "Linux")
		req.Header.Set("X-Ver-OS", kernelRelease())
		req.Header.Set("X-Device-Model", "harley")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, friendlyNetErr(u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		hint := ""
		switch resp.StatusCode {
		case 401, 403:
			hint = " — доступ запрещён: проверь ссылку, срок подписки или лимит устройств (HWID)"
		case 404:
			hint = " — подписка не найдена: ссылка устарела или с опечаткой"
		}
		return nil, fmt.Errorf("подписка ответила HTTP %d%s", resp.StatusCode, hint)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("подписка оборвала ответ: %v", err)
	}
	pr := parse.ParseBody(body)
	res := &Result{Result: pr, Body: body, Meta: ParseMeta(resp.Header, pr.Meta)}
	if len(res.Servers) == 0 {
		msg := "подписка не содержит поддерживаемых серверов"
		if len(pr.Errors) > 0 {
			msg += ": " + pr.Errors[0]
		}
		return res, errors.New(msg)
	}
	return res, nil
}

// ParseMeta объединяет метаданные из заголовков и из тела (заголовки важнее).
func ParseMeta(h http.Header, body map[string]string) Meta {
	get := func(k string) string {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			return v
		}
		return strings.TrimSpace(body[strings.ToLower(k)])
	}
	m := Meta{
		Title:      DecodeValue(get("profile-title")),
		SupportURL: get("support-url"),
		WebPage:    get("profile-web-page-url"),
		Announce:   DecodeValue(get("announce")),
	}
	if m.Title == "" {
		m.Title = filenameFromDisposition(h.Get("Content-Disposition"))
	}
	m.Info = ParseUserInfo(get("subscription-userinfo"))
	if n, err := strconv.Atoi(strings.TrimSpace(get("profile-update-interval"))); err == nil && n > 0 {
		m.IntervalHours = n
	}
	return m
}

// DecodeValue раскодирует значения вида «base64:…» (так Happ-панели
// передают не-ASCII в заголовках).
func DecodeValue(v string) string {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, "base64:"); ok {
		if b, ok := parse.DecodeBase64(rest); ok {
			return strings.TrimSpace(string(b))
		}
	}
	return v
}

// ParseUserInfo разбирает «upload=1; download=2; total=3; expire=4».
func ParseUserInfo(v string) model.UserInfo {
	var ui model.UserInfo
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' }) {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			ui.Upload = int64(n)
		case "download":
			ui.Download = int64(n)
		case "total":
			ui.Total = int64(n)
		case "expire":
			ui.Expire = int64(n)
		}
	}
	return ui
}

func filenameFromDisposition(v string) string {
	if v == "" {
		return ""
	}
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"`)
		switch strings.ToLower(k) {
		case "filename*":
			if i := strings.Index(val, "''"); i >= 0 {
				val = val[i+2:]
			}
			if d, err := url.PathUnescape(val); err == nil {
				return d
			}
		case "filename":
			return val
		}
	}
	return ""
}

func friendlyNetErr(host string, err error) error {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return fmt.Errorf("подписка не отвечает: не удалось найти %s (нет сети или DNS)", host)
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return fmt.Errorf("подписка не отвечает: %s не ответил вовремя", host)
	case strings.Contains(err.Error(), "connection refused"):
		return fmt.Errorf("подписка не отвечает: %s отклонил соединение", host)
	case strings.Contains(err.Error(), "certificate"):
		return fmt.Errorf("подписка: ошибка TLS-сертификата %s: %v", host, err)
	}
	return fmt.Errorf("подписка не отвечает: %v", err)
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "linux"
	}
	return strings.TrimSpace(string(b))
}
