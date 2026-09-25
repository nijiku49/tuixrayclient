package sub

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testKey = "vless://u1@a.example.com:443?security=reality&pbk=K&sid=01&sni=www.google.com#A"

func TestParseUserInfo(t *testing.T) {
	ui := ParseUserInfo("upload=455727941; download=6174315083; total=1073741824000; expire=1671815872")
	if ui.Upload != 455727941 || ui.Download != 6174315083 || ui.Total != 1073741824000 || ui.Expire != 1671815872 {
		t.Fatalf("%+v", ui)
	}
	if ui.Used() != 455727941+6174315083 {
		t.Fatal("Used")
	}
	// Без пробелов, с float и мусором.
	ui = ParseUserInfo("upload=1;download=2.0;total=0;expire=;junk")
	if ui.Upload != 1 || ui.Download != 2 || ui.Total != 0 || ui.Expire != 0 {
		t.Fatalf("%+v", ui)
	}
	if !ParseUserInfo("").Empty() {
		t.Fatal("пустой заголовок")
	}
}

func TestDecodeValue(t *testing.T) {
	enc := "base64:" + base64.StdEncoding.EncodeToString([]byte("Мой VPN 🚀"))
	if got := DecodeValue(enc); got != "Мой VPN 🚀" {
		t.Fatalf("%q", got)
	}
	if got := DecodeValue("Plain Title"); got != "Plain Title" {
		t.Fatalf("%q", got)
	}
	if got := DecodeValue("base64:!!!"); got != "base64:!!!" {
		t.Fatalf("битый base64 оставляем как есть: %q", got)
	}
}

func TestParseMeta(t *testing.T) {
	h := http.Header{}
	h.Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Remna")))
	h.Set("Subscription-Userinfo", "upload=10; download=20; total=100; expire=2000000000")
	h.Set("Profile-Update-Interval", "12")
	h.Set("Support-Url", "https://t.me/support")
	h.Set("Announce", "base64:"+base64.StdEncoding.EncodeToString([]byte("Плановые работы в субботу")))
	h.Set("Profile-Web-Page-Url", "https://panel.example.com")
	m := ParseMeta(h, map[string]string{"profile-title": "из тела"})
	if m.Title != "Remna" || m.Info.Total != 100 || m.IntervalHours != 12 || m.SupportURL != "https://t.me/support" ||
		m.Announce != "Плановые работы в субботу" || m.WebPage != "https://panel.example.com" {
		t.Fatalf("%+v", m)
	}
	// Метаданные только в теле.
	m = ParseMeta(http.Header{}, map[string]string{"profile-title": "Body Title", "profile-update-interval": "3",
		"subscription-userinfo": "upload=1; download=1; total=5"})
	if m.Title != "Body Title" || m.IntervalHours != 3 || m.Info.Total != 5 {
		t.Fatalf("%+v", m)
	}
	// Имя из Content-Disposition.
	h = http.Header{}
	h.Set("Content-Disposition", `attachment; filename*=UTF-8''%D0%9C%D0%BE%D0%B9`)
	if m = ParseMeta(h, nil); m.Title != "Мой" {
		t.Fatalf("%+v", m)
	}
}

func TestFetch(t *testing.T) {
	var gotUA, gotHWID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotHWID = r.UserAgent(), r.Header.Get("X-HWID")
		switch r.URL.Path {
		case "/ok":
			// Панель отдаёт разные форматы в зависимости от UA.
			if !strings.HasPrefix(r.UserAgent(), "Happ/") {
				w.Write([]byte("<html>use a proper client</html>"))
				return
			}
			w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Тест")))
			w.Header().Set("subscription-userinfo", "upload=1; download=2; total=3; expire=4")
			w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(testKey + "\n" + testKey + "2"))))
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		case "/empty":
			w.Write([]byte("nothing here"))
		}
	}))
	defer srv.Close()

	r, err := Fetch(context.Background(), srv.URL+"/ok", Options{HWID: "hw-1"})
	if err != nil {
		t.Fatal(err)
	}
	if gotUA != DefaultUserAgent || gotHWID != "hw-1" {
		t.Fatalf("UA %q HWID %q", gotUA, gotHWID)
	}
	if r.Meta.Title != "Тест" || r.Meta.Info.Total != 3 || len(r.Servers) != 2 || r.Format != "base64" {
		t.Fatalf("%+v %d %s", r.Meta, len(r.Servers), r.Format)
	}

	// Настраиваемый UA.
	if _, err := Fetch(context.Background(), srv.URL+"/ok", Options{UserAgent: "curl/8"}); err == nil {
		t.Fatal("с чужим UA панель не отдаёт ключи — должна быть ошибка")
	}
	if gotUA != "curl/8" {
		t.Fatalf("UA не применился: %q", gotUA)
	}

	if _, err := Fetch(context.Background(), srv.URL+"/forbidden", Options{}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("ожидалась ошибка 403: %v", err)
	}
	if _, err := Fetch(context.Background(), srv.URL+"/empty", Options{}); err == nil {
		t.Fatal("пустая подписка — ошибка")
	}
	if _, err := Fetch(context.Background(), "ftp://x", Options{}); err == nil {
		t.Fatal("неверная схема")
	}
	// Недоступный сервер.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	_, err = Fetch(context.Background(), deadURL, Options{Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "не отвечает") {
		t.Fatalf("ожидалась понятная ошибка «не отвечает»: %v", err)
	}
}
