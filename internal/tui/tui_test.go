package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/nijiku49/tuixrayclient/internal/app"
)

const (
	k1 = "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?security=none#Alpha"
	k2 = "trojan://pw@b.example.com:443?sni=b.example.com#Beta"
)

func testModel(t *testing.T) *Model {
	t.Helper()
	a, err := app.NewAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, _ := a.Settings()
	s.AutoConnect = false
	s.XrayPath = "/nonexistent/xray"
	a.SaveSettings(s)
	m := newModel(a, "test")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return m
}

// run выполняет команду и скармливает результат модели (без горутин bubbletea).
func run(m *Model, cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			run(m, c)
		}
		return nil
	}
	_, next := m.Update(msg)
	return next
}

func paste(text string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text), Paste: true}
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestEmptyScreenAndPaste(t *testing.T) {
	m := testModel(t)
	if m.mode != mAdd || !strings.Contains(m.View(), "Вставь ссылку или ключ") {
		t.Fatal("первый запуск: подсказка «Вставь ссылку или ключ» и поле ввода")
	}
	// Вставка без Enter сразу запускает импорт.
	_, cmd := m.Update(paste(k1 + "\n" + k2))
	if cmd == nil || m.busy == "" {
		t.Fatal("вставка должна сразу запускать импорт")
	}
	next := run(m, cmd)
	if len(m.state.Servers) != 2 || m.mode != mNormal {
		t.Fatalf("после импорта: серверов %d, режим %v", len(m.state.Servers), m.mode)
	}
	if next == nil {
		t.Fatal("после импорта должен запуститься пинг")
	}
	if !m.pinging[m.state.Servers[0].ID] {
		t.Fatal("серверы помечены как пингующиеся")
	}
	v := m.View()
	for _, want := range []string{"Ключи", "Alpha", "Beta", "VLESS", "Trojan"} {
		if !strings.Contains(v, want) {
			t.Errorf("в списке нет %q", want)
		}
	}
	// Пинг без xray — TCP-фолбэк, модель не падает.
	run(m, next)
	if m.busy != "" || !strings.Contains(m.msg, "Пинг") {
		t.Fatalf("после пинга: busy=%q msg=%q", m.busy, m.msg)
	}
}

func TestPasteInNormalModeAndErrors(t *testing.T) {
	m := testModel(t)
	run(m, func() tea.Msg { _, c := m.Update(paste(k1)); return c() })
	if m.mode != mNormal {
		t.Fatal("режим")
	}
	m.busy = "" // пинг после импорта в тесте не запускаем
	// Вставка в обычном режиме — тоже импорт.
	_, cmd := m.Update(paste(k2))
	run(m, cmd)
	if len(m.state.Servers) != 2 {
		t.Fatalf("серверов %d", len(m.state.Servers))
	}
	m.busy = ""
	// Мусор — понятная ошибка, список не трогаем.
	_, cmd = m.Update(paste("hello world"))
	run(m, cmd)
	if m.msgKind != kErr || !strings.Contains(m.msg, "распознать") {
		t.Fatalf("ошибка: %q", m.msg)
	}
	// Подключение без xray — понятная ошибка.
	m.busy = ""
	m.cursor = 1
	_, cmd = m.Update(key("enter"))
	run(m, cmd)
	if m.msgKind != kErr || !strings.Contains(m.msg, "apk add xray") {
		t.Fatalf("нет xray: %q", m.msg)
	}
}

func TestSearchAndDelete(t *testing.T) {
	m := testModel(t)
	_, cmd := m.Update(paste(k1 + "\n" + k2))
	run(m, cmd)
	m.busy = ""
	m.Update(key("/"))
	for _, r := range "bet" {
		m.Update(key(string(r)))
	}
	if len(m.rows) != 2 || m.rows[1].server.Name != "Beta" {
		t.Fatalf("поиск: %d строк", len(m.rows))
	}
	m.Update(key("enter"))
	m.Update(key("x"))
	if m.mode != mConfirm || !strings.Contains(m.confirmTxt, "Beta") {
		t.Fatalf("подтверждение: %q", m.confirmTxt)
	}
	m.Update(key("y"))
	if len(m.state.Servers) != 1 || m.state.Servers[0].Name != "Alpha" {
		t.Fatal("Beta не удалён")
	}
	m.Update(key("esc"))
	if m.search != "" || len(m.rows) != 2 {
		t.Fatal("Esc сбрасывает поиск")
	}
}

func TestModeAndRoutingKeys(t *testing.T) {
	m := testModel(t)
	_, cmd := m.Update(paste(k1))
	run(m, cmd)
	m.busy = ""
	m.Update(key("m"))
	m.Update(key("r"))
	s, _ := m.app.Settings()
	if s.Mode != "tun" || s.Routing != "ru-direct" {
		t.Fatalf("настройки: %s %s", s.Mode, s.Routing)
	}
	if v := m.View(); !strings.Contains(v, "TUN") || !strings.Contains(v, "RU напрямую") {
		t.Fatal("статус-панель должна показывать режим и маршрутизацию")
	}
}
