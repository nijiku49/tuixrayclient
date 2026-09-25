package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/store"
	"github.com/nijiku49/tuixrayclient/internal/xray"
)

const (
	k1 = "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?security=reality&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=01&sni=www.google.com#Alpha"
	k2 = "trojan://pw@b.example.com:443?sni=b.example.com#Beta"
	k3 = "hy2://pw@c.example.com:443?sni=c.example.com#Gamma"
)

func newApp(t *testing.T) *App {
	t.Helper()
	a, err := NewAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Без xray в тестах пинг/подключение не трогаем, если не просили.
	s, _ := a.Settings()
	s.XrayPath = "/nonexistent/xray"
	a.SaveSettings(s)
	return a
}

func TestImportKeys(t *testing.T) {
	a := newApp(t)
	rep, err := a.Import(context.Background(), k1+"\n"+k2+"\nvless://broken")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 2 || len(rep.Errors) != 1 || len(rep.ServerIDs) != 2 {
		t.Fatalf("%+v", rep)
	}
	// Повторный импорт — без дублей.
	rep, _ = a.Import(context.Background(), k1)
	if rep.Added != 0 || rep.Existing != 1 {
		t.Fatalf("дубль: %+v", rep)
	}
	st, _ := a.State()
	if len(st.Servers) != 2 || st.Servers[0].SubID != model.ManualSubID {
		t.Fatalf("серверы: %d", len(st.Servers))
	}
	if _, err := a.Import(context.Background(), "просто текст"); err == nil {
		t.Fatal("мусор — ошибка")
	}
}

type fakePanel struct {
	srv   *httptest.Server
	body  atomic.Value
	down  atomic.Bool
	calls atomic.Int32
}

func newPanel(t *testing.T) *fakePanel {
	p := &fakePanel{}
	p.body.Store(base64.StdEncoding.EncodeToString([]byte(k1 + "\n" + k2)))
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		if p.down.Load() {
			// Имитируем обрыв соединения.
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Моя подписка")))
		w.Header().Set("subscription-userinfo", "upload=100; download=200; total=1000; expire=2000000000")
		w.Header().Set("profile-update-interval", "6")
		w.Header().Set("announce", "Привет!")
		w.Write([]byte(p.body.Load().(string)))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func TestImportSubscriptionAndOfflineFallback(t *testing.T) {
	a := newApp(t)
	p := newPanel(t)
	rep, err := a.Import(context.Background(), p.srv.URL+"/sub/token")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 2 || len(rep.SubsAdded) != 1 || rep.SubsAdded[0] != "Моя подписка" || len(rep.Announce) != 1 {
		t.Fatalf("%+v", rep)
	}
	st, _ := a.State()
	sb := st.Subscriptions[0]
	if sb.Name != "Моя подписка" || sb.Info.Total != 1000 || sb.Interval != 6 || sb.Updated.IsZero() {
		t.Fatalf("метаданные: %+v", sb)
	}
	if _, err := os.Stat(a.Store.CachePath(sb.ID)); err != nil {
		t.Fatal("копия подписки не сохранена")
	}

	// Пинг сохраняется при обновлении.
	a.Store.Update(func(st *store.State) error { st.Servers[0].Ping = 42; return nil })
	p.body.Store(k1 + "\n" + k3)
	if _, err := a.UpdateSub(context.Background(), sb.ID); err != nil {
		t.Fatal(err)
	}
	st, _ = a.State()
	if len(st.Servers) != 2 || st.Servers[0].Ping != 42 || st.Servers[1].Name != "Gamma" {
		t.Fatalf("после обновления: %v", st.Servers)
	}

	// Панель недоступна — серверы остаются.
	p.down.Store(true)
	_, err = a.UpdateSub(context.Background(), sb.ID)
	if err == nil || !strings.Contains(err.Error(), "сохранённой копии") {
		t.Fatalf("ожидалась ошибка с работой на копии: %v", err)
	}
	st, _ = a.State()
	if len(st.Servers) != 2 || st.Subscriptions[0].LastErr == "" {
		t.Fatal("серверы должны остаться, ошибка — записаться")
	}

	// Даже если серверы потерялись (например, удалены вручную), восстановим из кэша.
	a.Store.Update(func(st *store.State) error { st.Servers = nil; return nil })
	if _, err := a.UpdateSub(context.Background(), sb.ID); err == nil {
		t.Fatal("ошибка сети должна вернуться")
	}
	st, _ = a.State()
	if len(st.Servers) != 2 {
		t.Fatalf("восстановление из кэша: %d", len(st.Servers))
	}

	// Удаление подписки удаляет её серверы и кэш.
	if err := a.Delete(sb.ID); err != nil {
		t.Fatal(err)
	}
	st, _ = a.State()
	if len(st.Subscriptions) != 0 || len(st.Servers) != 0 {
		t.Fatal("подписка не удалена")
	}
	if _, err := os.Stat(a.Store.CachePath(sb.ID)); err == nil {
		t.Fatal("кэш не удалён")
	}
}

func TestImportUnreachableSubscription(t *testing.T) {
	a := newApp(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL + "/sub"
	dead.Close()
	_, err := a.Import(context.Background(), u)
	if err == nil || !strings.Contains(err.Error(), "не отвечает") {
		t.Fatalf("ожидалась ошибка «подписка не отвечает»: %v", err)
	}
	st, _ := a.State()
	if len(st.Subscriptions) != 1 || st.Subscriptions[0].LastErr == "" {
		t.Fatal("подписка должна остаться (обновить позже клавишей u)")
	}
}

func TestSubDue(t *testing.T) {
	a := newApp(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return now }
	s := store.Defaults()
	if !a.SubDue(&model.Subscription{Updated: now.Add(-13 * time.Hour)}, s) {
		t.Fatal("12ч по умолчанию истекли")
	}
	if a.SubDue(&model.Subscription{Updated: now.Add(-2 * time.Hour), Interval: 3}, s) {
		t.Fatal("интервал подписки 3ч не истёк")
	}
	if !a.SubDue(&model.Subscription{Updated: now.Add(-4 * time.Hour), Interval: 3}, s) {
		t.Fatal("интервал подписки 3ч истёк")
	}
	s.AutoUpdateHours = 0
	if a.SubDue(&model.Subscription{}, s) {
		t.Fatal("автообновление выключено")
	}
}

func TestFindServerAndFastest(t *testing.T) {
	st := &store.State{Servers: []*model.Server{
		{ID: "a", Name: "🇩🇪 Германия 1", Ping: 120},
		{ID: "b", Name: "🇩🇪 Германия 2", Ping: 80},
		{ID: "c", Name: "Финляндия", Ping: -1},
	}}
	for q, want := range map[string]string{"a": "a", "2": "b", "финл": "c", "🇩🇪 Германия 1": "a"} {
		s, err := FindServer(st, q)
		if err != nil || s.ID != want {
			t.Errorf("%q → %v %v", q, s, err)
		}
	}
	if _, err := FindServer(st, "Германия"); err == nil || !strings.Contains(err.Error(), "несколько") {
		t.Fatalf("неоднозначный запрос: %v", err)
	}
	if _, err := FindServer(st, "Марс"); err == nil {
		t.Fatal("не найден")
	}
	if Fastest(st, nil).ID != "b" || Fastest(st, []string{"a", "c"}).ID != "a" || Fastest(st, []string{"c"}) != nil {
		t.Fatal("Fastest")
	}
}

func TestConnectErrors(t *testing.T) {
	a := newApp(t)
	if _, err := a.Connect(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "пуст") {
		t.Fatalf("пустой список: %v", err)
	}
	a.Import(context.Background(), k1)
	if _, err := a.Connect(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "install-xray") {
		t.Fatalf("нет xray: %v", err)
	}
	if st := a.GetStatus(); st.Connected || st.Session != nil {
		t.Fatal("не подключены")
	}
	// Пинг без xray — TCP-фолбэк, без паники.
	rep, err := a.Ping(context.Background(), nil)
	if err != nil || !rep.TCPOnly || len(rep.Results) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
}

// TestAutoConnectIntegration — сценарий «вставил — работает» с настоящим
// xray: подписка → пинг → самый быстрый → подключение → статус → отключение.
func TestAutoConnectIntegration(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		bin, _ = exec.LookPath("xray")
	}
	if bin == "" {
		t.Skip("xray не найден (задай XRAY_BIN)")
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer web.Close()
	ports, _ := xray.FreePorts(4)
	srvCfg := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless",
	  "settings":{"clients":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5"}],"decryption":"none"}}],
	  "outbounds":[{"protocol":"freedom","settings":{"redirect":"%s"}}]}`, ports[0], strings.TrimPrefix(web.URL, "http://"))
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "srv.json"), []byte(srvCfg), 0o600)
	srv := exec.Command(bin, "run", "-c", filepath.Join(dir, "srv.json"))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()
	time.Sleep(500 * time.Millisecond)

	good := fmt.Sprintf("vless://5783a3e7-e373-51cd-8642-c83782b807c5@127.0.0.1:%d?security=none#Рабочий", ports[0])
	dead := fmt.Sprintf("vless://5783a3e7-e373-51cd-8642-c83782b807c5@127.0.0.1:%d?security=none#Мёртвый", ports[3])
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(dead + "\n" + good))))
	}))
	defer panel.Close()

	a, _ := NewAt(t.TempDir())
	s, _ := a.Settings()
	s.XrayPath = bin
	s.SocksPort, s.HTTPPort = ports[1], ports[2]
	s.PingURL = "http://203.0.113.1/generate_204"
	s.PingTimeout = 3
	a.SaveSettings(s)

	rep, err := a.Import(context.Background(), panel.URL+"/sub")
	if err != nil {
		t.Fatal(err)
	}
	sess, best, err := a.AutoConnect(context.Background(), rep.ServerIDs)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Disconnect()
	if best.Name != "Рабочий" || sess.ServerName != "Рабочий" {
		t.Fatalf("выбран %q", best.Name)
	}
	st := a.GetStatus()
	if !st.Connected || st.Session.SocksPort != ports[1] {
		t.Fatalf("статус: %+v", st)
	}
	if _, err := xray.QueryTraffic(context.Background(), st.Session.MetricsPort); err != nil {
		t.Fatalf("статистика недоступна: %v", err)
	}
	state, _ := a.State()
	if state.LastServerID != best.ID {
		t.Fatal("последний сервер не запомнен")
	}
	// Повторный connect без аргумента — к последнему серверу (сценарий OpenRC).
	if _, err := a.Connect(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := a.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if a.GetStatus().Connected {
		t.Fatal("не отключились")
	}
}

func TestEnsureXrayDownloads(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "xray", Method: zip.Deflate}
	h.SetMode(0o755)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte("#!/bin/sh\necho 'Xray 26.9.9 test'\n"))
	zw.Close()
	archive := buf.Bytes()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.HasSuffix(r.URL.Path, ".dgst") {
			fmt.Fprintf(w, "SHA2-256= %x\n", sha256.Sum256(archive))
			return
		}
		w.Write(archive)
	}))
	defer srv.Close()

	a, _ := NewAt(t.TempDir())
	s, _ := a.Settings()
	s.XrayReleases = srv.URL
	a.SaveSettings(s)
	for _, p := range []string{"/usr/local/bin/xray", "/usr/bin/xray"} {
		if _, err := os.Stat(p); err == nil {
			t.Skip("в системе уже есть xray: " + p)
		}
	}
	dir := t.TempDir()
	a.XrayLayout = xray.InstallLayout{BinDir: dir, AssetDir: dir}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	if !a.WillInstallXray() {
		t.Fatal("xray нет — должен скачаться")
	}
	bin, err := a.EnsureXray(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if bin != filepath.Join(dir, "xray") || a.WillInstallXray() {
		t.Fatalf("установлен в %s", bin)
	}
	// Повторно не качаем.
	hits = 0
	s, _ = a.Settings()
	if b2, err := a.EnsureXray(context.Background(), s); err != nil || b2 != bin || hits != 0 {
		t.Fatalf("повторная загрузка: %v %s %d", err, b2, hits)
	}
	// Выключенная автоустановка — понятная ошибка без скачивания.
	s = store.Defaults()
	s.AutoInstallXray = false
	os.Remove(bin)
	if _, err := a.EnsureXray(context.Background(), s); err == nil || !strings.Contains(err.Error(), "install-xray") || hits != 0 {
		t.Fatalf("%v, запросов %d", err, hits)
	}
}
