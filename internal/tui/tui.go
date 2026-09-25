// Package tui — терминальный интерфейс harley на bubbletea.
package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/nijiku49/tuixrayclient/internal/app"
	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/store"
	"github.com/nijiku49/tuixrayclient/internal/xray"
)

type mode int

const (
	mNormal mode = iota
	mAdd
	mSearch
	mHelp
	mConfirm
	mSettings
	mEdit
)

type tab int

const (
	tabServers tab = iota
	tabLogs
)

type msgKind int

const (
	kInfo msgKind = iota
	kOK
	kErr
)

// row — строка списка: заголовок группы или сервер.
type row struct {
	header    bool
	groupID   string
	groupName string
	sub       *model.Subscription
	count     int
	server    *model.Server
}

// Model — состояние TUI.
type Model struct {
	app     *app.App
	version string
	ctx     context.Context

	width, height int
	tab           tab
	mode          mode

	state    *store.State
	settings store.Settings
	rows     []row
	cursor   int
	offset   int
	collapse map[string]bool
	search   string

	status   app.Status
	traffic  xray.Traffic
	prevTr   xray.Traffic
	prevAt   time.Time
	upSpeed  float64
	dnSpeed  float64
	haveTr   bool
	ticks    int
	crashMsg string

	busy     string
	spinner  spinner.Model
	pinging  map[string]bool
	msg      string
	msgKind  msgKind
	msgAt    time.Time
	announce string

	input      textinput.Model
	confirmID  string
	confirmTxt string

	setCursor int
	editKey   string

	logs      viewport.Model
	logFollow bool
}

// Run запускает TUI.
func Run(a *app.App, version string) error {
	m := newModel(a, version)
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func newModel(a *app.App, version string) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = sTitle
	in := textinput.New()
	in.Prompt = "› "
	in.PromptStyle = sKey
	in.Placeholder = "https://… или vless://…"
	in.CharLimit = 1 << 20
	m := &Model{
		app: a, version: version, ctx: context.Background(),
		collapse: map[string]bool{}, pinging: map[string]bool{},
		spinner: sp, input: in, logs: viewport.New(80, 20), logFollow: true,
		width: 100, height: 30,
	}
	m.reload()
	for _, sb := range m.state.Subscriptions {
		if sb.Announce != "" {
			m.announce = sb.Announce
		}
	}
	if m.empty() {
		m.mode = mAdd
		m.input.Focus()
	}
	return m
}

func (m *Model) empty() bool {
	return m.state == nil || (len(m.state.Servers) == 0 && len(m.state.Subscriptions) == 0)
}

// reload перечитывает состояние с диска (его меняют и фоновые операции,
// и CLI в соседнем терминале).
func (m *Model) reload() {
	if st, err := m.app.State(); err == nil {
		m.state = st
	} else {
		m.state = &store.State{}
		m.setMsg(kErr, err.Error())
	}
	if s, err := m.app.Settings(); err == nil {
		m.settings = s
	} else {
		m.setMsg(kErr, err.Error())
	}
	m.status = m.app.GetStatus()
	m.rebuild()
}

// rebuild пересобирает строки списка, стараясь сохранить позицию курсора.
func (m *Model) rebuild() {
	var keepID string
	if m.cursor < len(m.rows) {
		r := m.rows[m.cursor]
		if r.header {
			keepID = "g:" + r.groupID
		} else {
			keepID = r.server.ID
		}
	}
	m.rows = m.rows[:0]
	q := strings.ToLower(strings.TrimSpace(m.search))
	addGroup := func(id, name string, sb *model.Subscription) {
		var servers []*model.Server
		for _, s := range m.state.Servers {
			if s.SubID != id {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(s.Name), q) && !strings.Contains(strings.ToLower(s.ProtoLabel()), q) {
				continue
			}
			servers = append(servers, s)
		}
		if q != "" && len(servers) == 0 {
			return
		}
		if sb == nil && len(servers) == 0 {
			return
		}
		m.rows = append(m.rows, row{header: true, groupID: id, groupName: name, sub: sb, count: len(servers)})
		if m.collapse[id] && q == "" {
			return
		}
		for _, s := range servers {
			m.rows = append(m.rows, row{groupID: id, server: s})
		}
	}
	for _, sb := range m.state.Subscriptions {
		addGroup(sb.ID, sb.Name, sb)
	}
	addGroup(model.ManualSubID, "Ключи", nil)

	m.cursor = 0
	if keepID == "" && m.status.Session != nil {
		keepID = m.status.Session.ServerID
	}
	found := false
	for i, r := range m.rows {
		if (r.header && keepID == "g:"+r.groupID) || (!r.header && r.server.ID == keepID) {
			m.cursor, found = i, true
			break
		}
	}
	if !found {
		// Первый сервер, а не заголовок.
		for i, r := range m.rows {
			if !r.header {
				m.cursor = i
				break
			}
		}
	}
}

func (m *Model) setMsg(k msgKind, s string) {
	m.msgKind, m.msg, m.msgAt = k, s, time.Now()
}

// ─── Сообщения фоновых операций ──────────────────────────────────────────

type (
	tickMsg    time.Time
	importMsg  struct {
		rep app.ImportReport
		err error
	}
	pingMsg struct {
		rep app.PingReport
		err error
	}
	connectMsg struct {
		sess *app.Session
		srv  *model.Server
		err  error
		auto bool
	}
	disconnectMsg struct{ err error }
	updateMsg     struct {
		updated []string
		errs    []error
		auto    bool
	}
	statusMsg struct {
		st      app.Status
		traffic *xray.Traffic
	}
	logsMsg []string
)

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tick(), m.spinner.Tick, textinput.Blink, m.statusCmd()}
	if m.status.Crashed {
		m.setMsg(kErr, "xray остановился: "+m.status.Reason)
	}
	if c := m.dueUpdateCmd(); c != nil {
		cmds = append(cmds, c)
	}
	return tea.Batch(cmds...)
}

func (m *Model) statusCmd() tea.Cmd {
	a := m.app
	return func() tea.Msg {
		st := a.GetStatus()
		var tr *xray.Traffic
		if st.Connected && st.Session.MetricsPort > 0 {
			if t, err := xray.QueryTraffic(context.Background(), st.Session.MetricsPort); err == nil {
				tr = &t
			}
		}
		return statusMsg{st: st, traffic: tr}
	}
}

func (m *Model) logsCmd() tea.Cmd {
	path := m.app.Store.LogPath()
	return func() tea.Msg { return logsMsg(xray.TailFile(path, 500)) }
}

func (m *Model) importCmd(text string) tea.Cmd {
	m.busy = "Импортирую…"
	a, ctx := m.app, m.ctx
	return func() tea.Msg {
		rep, err := a.Import(ctx, text)
		return importMsg{rep, err}
	}
}

func (m *Model) pingCmd(ids []string) tea.Cmd {
	m.markPinging(ids)
	m.busy = "Пингую серверы (URL-тест)…"
	a, ctx := m.app, m.ctx
	return func() tea.Msg {
		rep, err := a.Ping(ctx, ids)
		return pingMsg{rep, err}
	}
}

func (m *Model) markPinging(ids []string) {
	m.pinging = map[string]bool{}
	if len(ids) == 0 {
		for _, s := range m.state.Servers {
			m.pinging[s.ID] = true
		}
		return
	}
	for _, id := range ids {
		m.pinging[id] = true
	}
}

func (m *Model) connectCmd(id string) tea.Cmd {
	name := id
	if s := m.state.ServerByID(id); s != nil {
		name = s.Name
	}
	m.busy = "Подключаюсь к " + name + "…"
	a, ctx := m.app, m.ctx
	return func() tea.Msg {
		sess, err := a.Connect(ctx, id)
		var srv *model.Server
		if sess != nil {
			srv = &model.Server{ID: sess.ServerID, Name: sess.ServerName}
		}
		return connectMsg{sess: sess, srv: srv, err: err}
	}
}

func (m *Model) autoConnectCmd(ids []string) tea.Cmd {
	m.markPinging(ids)
	m.busy = "Пингую и выбираю самый быстрый сервер…"
	a, ctx := m.app, m.ctx
	return func() tea.Msg {
		sess, srv, err := a.AutoConnect(ctx, ids)
		return connectMsg{sess: sess, srv: srv, err: err, auto: true}
	}
}

func (m *Model) disconnectCmd() tea.Cmd {
	m.busy = "Отключаюсь…"
	a := m.app
	return func() tea.Msg { return disconnectMsg{a.Disconnect()} }
}

func (m *Model) updateCmd(auto bool) tea.Cmd {
	if !auto {
		m.busy = "Обновляю подписки…"
	}
	a, ctx := m.app, m.ctx
	return func() tea.Msg {
		up, errs := a.UpdateAll(ctx, auto)
		return updateMsg{up, errs, auto}
	}
}

func (m *Model) dueUpdateCmd() tea.Cmd {
	if m.busy != "" || m.state == nil {
		return nil
	}
	for _, sb := range m.state.Subscriptions {
		if m.app.SubDue(sb, m.settings) {
			return m.updateCmd(true)
		}
	}
	return nil
}

// ─── Update ──────────────────────────────────────────────────────────────

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.input.Width = max(20, min(msg.Width-24, 60))
		m.logs.Width = msg.Width
		m.logs.Height = max(3, m.bodyHeight())
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tickMsg:
		m.ticks++
		cmds := []tea.Cmd{tick(), m.statusCmd()}
		if m.tab == tabLogs {
			cmds = append(cmds, m.logsCmd())
		}
		if m.ticks%60 == 0 {
			if c := m.dueUpdateCmd(); c != nil {
				cmds = append(cmds, c)
			}
		}
		if m.msg != "" && m.msgKind != kErr && time.Since(m.msgAt) > 8*time.Second {
			m.msg = ""
		}
		return m, tea.Batch(cmds...)

	case statusMsg:
		wasConnected := m.status.Connected
		m.status = msg.st
		if msg.traffic != nil {
			now := time.Now()
			if m.haveTr && !m.prevAt.IsZero() {
				dt := now.Sub(m.prevAt).Seconds()
				if dt > 0 {
					m.upSpeed = float64(msg.traffic.Up-m.prevTr.Up) / dt
					m.dnSpeed = float64(msg.traffic.Down-m.prevTr.Down) / dt
				}
			}
			m.prevTr, m.prevAt, m.haveTr = *msg.traffic, now, true
			m.traffic = *msg.traffic
		} else if !msg.st.Connected {
			m.haveTr, m.upSpeed, m.dnSpeed, m.traffic = false, 0, 0, xray.Traffic{}
		}
		if wasConnected && msg.st.Crashed && m.busy == "" {
			m.setMsg(kErr, "xray остановился: "+msg.st.Reason)
		}
		return m, nil

	case logsMsg:
		atBottom := m.logs.AtBottom()
		m.logs.SetContent(strings.Join(colorLog(msg), "\n"))
		if atBottom || m.logFollow {
			m.logs.GotoBottom()
			m.logFollow = false
		}
		return m, nil

	case importMsg:
		m.busy = ""
		m.reload()
		if m.mode == mAdd && !m.empty() {
			m.mode = mNormal
			m.input.Blur()
		}
		for _, a := range msg.rep.Announce {
			m.announce = a
		}
		if msg.err != nil {
			m.setMsg(kErr, msg.err.Error())
			if m.empty() {
				m.mode = mAdd
				m.input.Focus()
			}
			return m, nil
		}
		m.setMsg(kOK, "✓ "+msg.rep.Summary())
		if len(msg.rep.Errors) > 0 {
			m.setMsg(kErr, "✓ "+msg.rep.Summary()+" — "+msg.rep.Errors[0])
		}
		m.focusServer(msg.rep.ServerIDs)
		if m.settings.AutoConnect && len(msg.rep.ServerIDs) > 0 {
			return m, m.autoConnectCmd(msg.rep.ServerIDs)
		}
		if len(msg.rep.ServerIDs) > 0 {
			return m, m.pingCmd(msg.rep.ServerIDs)
		}
		return m, nil

	case pingMsg:
		m.busy = ""
		m.pinging = map[string]bool{}
		m.reload()
		if msg.err != nil {
			m.setMsg(kErr, msg.err.Error())
			return m, nil
		}
		ok, bad := 0, 0
		for _, r := range msg.rep.Results {
			if r.Err == nil {
				ok++
			} else {
				bad++
			}
		}
		txt := fmt.Sprintf("Пинг: отвечают %d, недоступны %d", ok, bad)
		if msg.rep.TCPOnly {
			txt += " (xray не найден — только TCP-пинг)"
		}
		m.setMsg(kInfo, txt)
		return m, nil

	case connectMsg:
		m.busy = ""
		m.pinging = map[string]bool{}
		m.haveTr = false
		m.reload()
		if msg.err != nil {
			m.setMsg(kErr, msg.err.Error())
			return m, nil
		}
		txt := "✓ Подключено: " + msg.sess.ServerName
		if msg.auto && msg.srv != nil && msg.srv.Ping > 0 {
			txt += fmt.Sprintf(" — самый быстрый, %d мс", msg.srv.Ping)
		}
		m.setMsg(kOK, txt)
		m.focusServer([]string{msg.sess.ServerID})
		return m, m.statusCmd()

	case disconnectMsg:
		m.busy = ""
		m.reload()
		if msg.err != nil {
			m.setMsg(kErr, msg.err.Error())
		} else {
			m.setMsg(kInfo, "Отключено")
		}
		return m, nil

	case updateMsg:
		m.busy = ""
		m.reload()
		switch {
		case len(msg.errs) > 0:
			m.setMsg(kErr, msg.errs[0].Error())
		case len(msg.updated) > 0:
			m.setMsg(kOK, "✓ Обновлено: "+strings.Join(msg.updated, ", "))
		case !msg.auto:
			m.setMsg(kInfo, "Подписок нет — добавь ссылку (a)")
		}
		for _, sb := range m.state.Subscriptions {
			if sb.Announce != "" {
				m.announce = sb.Announce
			}
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) focusServer(ids []string) {
	if len(ids) == 0 {
		return
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	for i, r := range m.rows {
		if !r.header && want[r.server.ID] {
			m.cursor = i
			return
		}
	}
}

func (m *Model) busyGuard() bool {
	if m.busy != "" {
		m.setMsg(kInfo, "Подожди: "+strings.TrimSuffix(m.busy, "…"))
		return true
	}
	return false
}

func (m *Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}
	switch m.mode {
	case mAdd:
		return m.keyAdd(k)
	case mSearch:
		return m.keySearch(k)
	case mHelp:
		m.mode = mNormal
		return m, nil
	case mConfirm:
		return m.keyConfirm(k)
	case mSettings:
		return m.keySettings(k)
	case mEdit:
		return m.keyEdit(k)
	}

	// Вставка в обычном режиме — сразу импорт, без лишних вопросов.
	if k.Paste {
		if m.busyGuard() {
			return m, nil
		}
		return m, m.importCmd(string(k.Runes))
	}

	if m.tab == tabLogs {
		switch k.String() {
		case "tab", "l", "esc":
			m.tab = tabServers
			return m, nil
		case "q":
			return m, tea.Quit
		case "G", "end":
			m.logs.GotoBottom()
			return m, nil
		case "g", "home":
			m.logs.GotoTop()
			return m, nil
		}
		var cmd tea.Cmd
		m.logs, cmd = m.logs.Update(k)
		return m, cmd
	}

	switch k.String() {
	case "q":
		return m, tea.Quit
	case "esc":
		if m.search != "" {
			m.search = ""
			m.rebuild()
		}
		m.announce = ""
		m.msg = ""
	case "tab", "l":
		m.tab = tabLogs
		m.logFollow = true
		return m, m.logsCmd()
	case "?", "h", "f1":
		m.mode = mHelp
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup", "ctrl+b":
		m.move(-max(1, m.bodyHeight()-2))
	case "pgdown", "ctrl+f":
		m.move(max(1, m.bodyHeight()-2))
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = max(0, len(m.rows)-1)
	case "enter", " ":
		if len(m.rows) == 0 {
			return m, nil
		}
		r := m.rows[m.cursor]
		if r.header {
			m.collapse[r.groupID] = !m.collapse[r.groupID]
			m.rebuild()
			return m, nil
		}
		if m.busyGuard() {
			return m, nil
		}
		return m, m.connectCmd(r.server.ID)
	case "d":
		if m.busyGuard() {
			return m, nil
		}
		if !m.status.Connected && m.status.Session == nil {
			m.setMsg(kInfo, "И так не подключено")
			return m, nil
		}
		return m, m.disconnectCmd()
	case "p":
		if m.busyGuard() {
			return m, nil
		}
		if len(m.state.Servers) == 0 {
			m.setMsg(kInfo, "Нет серверов — добавь ссылку (a)")
			return m, nil
		}
		return m, m.pingCmd(nil)
	case "f":
		if m.busyGuard() {
			return m, nil
		}
		if len(m.state.Servers) == 0 {
			return m, nil
		}
		return m, m.autoConnectCmd(nil)
	case "u":
		if m.busyGuard() {
			return m, nil
		}
		return m, m.updateCmd(false)
	case "a", "i", "ctrl+v":
		m.mode = mAdd
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	case "/":
		m.mode = mSearch
		m.input.SetValue(m.search)
		m.input.Placeholder = "поиск по имени"
		m.input.Focus()
		return m, textinput.Blink
	case "x", "delete":
		if len(m.rows) == 0 {
			return m, nil
		}
		r := m.rows[m.cursor]
		m.mode = mConfirm
		if r.header {
			if r.sub == nil {
				m.mode = mNormal
				m.setMsg(kInfo, "Ключи удаляются по одному")
				return m, nil
			}
			m.confirmID = r.groupID
			m.confirmTxt = fmt.Sprintf("Удалить подписку «%s» и её %d серверов?", r.groupName, r.count)
		} else {
			m.confirmID = r.server.ID
			m.confirmTxt = fmt.Sprintf("Удалить сервер «%s»?", r.server.Name)
		}
	case "s":
		m.mode = mSettings
	case "m":
		if m.busyGuard() {
			return m, nil
		}
		if m.settings.Mode == store.ModeTUN {
			m.settings.Mode = store.ModeProxy
		} else {
			m.settings.Mode = store.ModeTUN
		}
		return m, m.saveSettingsAndApply("Режим: " + app.ModeLabel(m.settings.Mode))
	case "r":
		if m.busyGuard() {
			return m, nil
		}
		switch m.settings.Routing {
		case store.RouteAll:
			m.settings.Routing = store.RouteRUDirect
		case store.RouteRUDirect:
			m.settings.Routing = store.RouteCustom
		default:
			m.settings.Routing = store.RouteAll
		}
		return m, m.saveSettingsAndApply("Маршрутизация: " + app.RoutingLabel(m.settings.Routing))
	}
	m.clampCursor()
	return m, nil
}

// saveSettingsAndApply сохраняет настройки и, если подключены,
// переподключается, чтобы изменения вступили в силу.
func (m *Model) saveSettingsAndApply(what string) tea.Cmd {
	if err := m.app.SaveSettings(m.settings); err != nil {
		m.setMsg(kErr, err.Error())
		return nil
	}
	if m.status.Connected && m.status.Session != nil {
		m.setMsg(kInfo, what+" — переподключаюсь")
		return m.connectCmd(m.status.Session.ServerID)
	}
	m.setMsg(kInfo, what)
	return nil
}

func (m *Model) move(d int) {
	m.cursor += d
	m.clampCursor()
}

func (m *Model) clampCursor() {
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m *Model) keyAdd(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.Paste {
		// Вставили — сразу импортируем, Enter не нужен.
		text := m.input.Value() + string(k.Runes)
		m.input.SetValue("")
		if !m.empty() {
			m.mode = mNormal
			m.input.Blur()
		}
		if m.busyGuard() {
			return m, nil
		}
		return m, m.importCmd(text)
	}
	switch k.String() {
	case "esc":
		if m.empty() {
			m.input.SetValue("")
			return m, nil
		}
		m.mode = mNormal
		m.input.Blur()
		return m, nil
	case "enter":
		text := strings.TrimSpace(m.input.Value())
		if text == "" {
			return m, nil
		}
		m.input.SetValue("")
		if !m.empty() {
			m.mode = mNormal
			m.input.Blur()
		}
		if m.busyGuard() {
			return m, nil
		}
		return m, m.importCmd(text)
	case "ctrl+q":
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(k)
	return m, cmd
}

func (m *Model) keySearch(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.search = ""
		m.mode = mNormal
		m.input.Blur()
		m.input.Placeholder = "https://… или vless://…"
		m.rebuild()
		return m, nil
	case "enter", "down", "up":
		m.mode = mNormal
		m.input.Blur()
		m.input.Placeholder = "https://… или vless://…"
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(k)
	m.search = m.input.Value()
	m.rebuild()
	return m, cmd
}

func (m *Model) keyConfirm(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.mode = mNormal
	switch k.String() {
	case "y", "Y", "д", "Д", "enter":
		if err := m.app.Delete(m.confirmID); err != nil {
			m.setMsg(kErr, err.Error())
		} else {
			m.setMsg(kInfo, "Удалено")
		}
		m.reload()
		m.clampCursor()
	default:
		m.setMsg(kInfo, "Отменено")
	}
	return m, nil
}

// ─── Настройки ───────────────────────────────────────────────────────────

type setting struct {
	key   string
	label string
	value func(s store.Settings) string
	kind  string // toggle, cycle, text, int
}

var settingsList = []setting{
	{"mode", "Режим подключения", func(s store.Settings) string { return app.ModeLabel(s.Mode) }, "cycle"},
	{"routing", "Маршрутизация", func(s store.Settings) string { return app.RoutingLabel(s.Routing) }, "cycle"},
	{"autoconnect", "Автоподключение после импорта", func(s store.Settings) string { return onOff(s.AutoConnect) }, "toggle"},
	{"socks", "SOCKS5-порт", func(s store.Settings) string { return strconv.Itoa(s.SocksPort) }, "int"},
	{"http", "HTTP-порт (0 — выключен)", func(s store.Settings) string { return strconv.Itoa(s.HTTPPort) }, "int"},
	{"listen", "Адрес прокси", func(s store.Settings) string { return s.ListenAddr }, "text"},
	{"dns", "DNS через VPN", func(s store.Settings) string { return strings.Join(s.DNS, ", ") }, "text"},
	{"autoupdate", "Автообновление подписок, ч", func(s store.Settings) string { return strconv.Itoa(s.AutoUpdateHours) }, "int"},
	{"ua", "User-Agent подписок", func(s store.Settings) string { return s.UserAgent }, "text"},
	{"hwid", "Отправлять HWID", func(s store.Settings) string { return onOff(s.SendHWID) }, "toggle"},
	{"pingurl", "URL для пинга", func(s store.Settings) string { return s.PingURL }, "text"},
	{"xray", "Путь к xray", func(s store.Settings) string {
		if s.XrayPath == "" {
			return "авто (PATH)"
		}
		return s.XrayPath
	}, "text"},
}

func onOff(b bool) string {
	if b {
		return "вкл"
	}
	return "выкл"
}

func (m *Model) keySettings(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc", "s", "q":
		m.mode = mNormal
	case "up", "k":
		m.setCursor = max(0, m.setCursor-1)
	case "down", "j":
		m.setCursor = min(len(settingsList)-1, m.setCursor+1)
	case "enter", " ":
		it := settingsList[m.setCursor]
		switch it.kind {
		case "toggle", "cycle":
			switch it.key {
			case "mode":
				if m.settings.Mode == store.ModeTUN {
					m.settings.Mode = store.ModeProxy
				} else {
					m.settings.Mode = store.ModeTUN
				}
			case "routing":
				switch m.settings.Routing {
				case store.RouteAll:
					m.settings.Routing = store.RouteRUDirect
				case store.RouteRUDirect:
					m.settings.Routing = store.RouteCustom
				default:
					m.settings.Routing = store.RouteAll
				}
			case "autoconnect":
				m.settings.AutoConnect = !m.settings.AutoConnect
			case "hwid":
				m.settings.SendHWID = !m.settings.SendHWID
			}
			if err := m.app.SaveSettings(m.settings); err != nil {
				m.setMsg(kErr, err.Error())
			} else {
				m.setMsg(kInfo, it.label+": "+it.value(m.settings))
			}
		default:
			m.mode = mEdit
			m.editKey = it.key
			v := it.value(m.settings)
			if it.key == "xray" && m.settings.XrayPath == "" {
				v = ""
			}
			m.input.SetValue(v)
			m.input.Placeholder = ""
			m.input.CursorEnd()
			m.input.Focus()
			return m, textinput.Blink
		}
	}
	return m, nil
}

func (m *Model) keyEdit(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.mode = mSettings
		m.input.Blur()
		m.input.Placeholder = "https://… или vless://…"
		return m, nil
	case "enter":
		v := strings.TrimSpace(m.input.Value())
		s := m.settings
		num := func() (int, bool) {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				m.setMsg(kErr, "нужно число от 0 до 65535")
				return 0, false
			}
			return n, true
		}
		switch m.editKey {
		case "socks":
			n, ok := num()
			if !ok || n == 0 {
				if ok {
					m.setMsg(kErr, "SOCKS-порт нужен (он же используется для проверки)")
				}
				return m, nil
			}
			s.SocksPort = n
		case "http":
			n, ok := num()
			if !ok {
				return m, nil
			}
			s.HTTPPort = n
		case "autoupdate":
			n, ok := num()
			if !ok {
				return m, nil
			}
			s.AutoUpdateHours = n
		case "listen":
			s.ListenAddr = v
		case "dns":
			var list []string
			for _, d := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				list = append(list, d)
			}
			s.DNS = list
		case "ua":
			s.UserAgent = v
		case "pingurl":
			s.PingURL = v
		case "xray":
			s.XrayPath = v
		}
		if err := m.app.SaveSettings(s); err != nil {
			m.setMsg(kErr, err.Error())
			return m, nil
		}
		m.settings, _ = m.app.Settings()
		m.mode = mSettings
		m.input.Blur()
		m.input.Placeholder = "https://… или vless://…"
		m.setMsg(kOK, "Сохранено — применится при следующем подключении")
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(k)
	return m, cmd
}
