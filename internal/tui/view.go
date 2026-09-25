package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/nijiku49/tuixrayclient/internal/app"
	"github.com/nijiku49/tuixrayclient/internal/store"
)

const footerLines = 5 // линия, 2 строки статуса, сообщение, подсказки

func (m *Model) bodyHeight() int {
	return max(3, m.height-2-footerLines)
}

func (m *Model) View() string {
	if m.width < 30 || m.height < 10 {
		return "Окно слишком маленькое для harley"
	}
	var b strings.Builder
	b.WriteString(m.viewHeader())
	b.WriteString("\n")
	b.WriteString(sRule.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	var body string
	switch {
	case m.mode == mHelp:
		body = m.viewHelp()
	case m.mode == mSettings || m.mode == mEdit:
		body = m.viewSettings()
	case m.tab == tabLogs:
		m.logs.Width, m.logs.Height = m.width, m.bodyHeight()
		body = m.logs.View()
	case m.empty():
		body = m.viewEmpty()
	default:
		body = m.viewList()
	}
	b.WriteString(fitHeight(body, m.bodyHeight()))
	b.WriteString("\n")
	b.WriteString(m.viewFooter())
	return b.String()
}

func fitHeight(s string, h int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (m *Model) viewHeader() string {
	tabs := []string{"Серверы", "Логи"}
	var parts []string
	for i, t := range tabs {
		if tab(i) == m.tab {
			parts = append(parts, sTabOn.Render(t))
		} else {
			parts = append(parts, sTabOff.Render(t))
		}
	}
	left := " " + sTitle.Render("◆ harley") + "  " + strings.Join(parts, sDim.Render("  │  "))
	var right string
	switch {
	case m.busy != "":
		right = m.spinner.View() + " " + sText.Render(m.busy)
	case m.status.Connected:
		right = sOK.Render("● подключено")
	case m.status.Crashed:
		right = sBad.Render("✕ xray остановлен")
	default:
		right = sDim.Render("○ не подключено")
	}
	right += " "
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m *Model) viewEmpty() string {
	title := sBold.Render("Вставь ссылку или ключ")
	hint := sDim.Render("Ctrl+Shift+V — подписка https://… или ключи vless:// vmess:// trojan:// ss:// hy2://")
	hint2 := sDim.Render("Дальше всё само: пинг → самый быстрый сервер → подключение")
	box := sBox.Render(lipgloss.JoinVertical(lipgloss.Center, title, "", m.input.View(), "", hint, hint2))
	return lipgloss.Place(m.width, m.bodyHeight(), lipgloss.Center, lipgloss.Center, box)
}

func (m *Model) viewList() string {
	h := m.bodyHeight()
	if len(m.rows) == 0 {
		return lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center,
			sDim.Render("Ничего не найдено по «"+m.search+"» — Esc, чтобы сбросить поиск"))
	}
	// Прокрутка.
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+h {
		m.offset = m.cursor - h + 1
	}
	if m.offset > max(0, len(m.rows)-h) {
		m.offset = max(0, len(m.rows)-h)
	}
	current := ""
	if m.status.Connected && m.status.Session != nil {
		current = m.status.Session.ServerID
	}
	var lines []string
	for i := m.offset; i < len(m.rows) && i < m.offset+h; i++ {
		r := m.rows[i]
		var line string
		if r.header {
			line = m.renderGroup(r)
		} else {
			line = m.renderServer(r, r.server.ID == current)
		}
		if i == m.cursor {
			line = sSel.Render(padRight(line, m.width))
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (m *Model) renderGroup(r row) string {
	arrow := "▾"
	if m.collapse[r.groupID] && m.search == "" {
		arrow = "▸"
	}
	left := " " + sGroup.Render(arrow+" "+truncate(r.groupName, m.width/2))
	count := sDim.Render(fmt.Sprintf(" %d", r.count))
	var meta []string
	if r.sub != nil {
		now := time.Now()
		if info, expired := app.FormatUserInfo(r.sub.Info, now); info != "" {
			if expired {
				meta = append(meta, sBad.Render(info))
			} else {
				meta = append(meta, sText.Render(info))
			}
		}
		if r.sub.LastErr != "" {
			meta = append(meta, sWarn.Render("⚠ не обновилась, копия от "+app.FormatAgo(r.sub.Updated, now)))
		} else if !r.sub.Updated.IsZero() {
			meta = append(meta, sDim.Render("обновлена "+app.FormatAgo(r.sub.Updated, now)))
		}
	}
	right := strings.Join(meta, sDim.Render(" · ")) + " "
	lw := lipgloss.Width(left + count)
	gap := m.width - lw - lipgloss.Width(right)
	if gap < 2 {
		return left + count
	}
	return left + count + strings.Repeat(" ", gap) + right
}

func (m *Model) renderServer(r row, current bool) string {
	s := r.server
	mark := "  "
	if current {
		mark = sCurrent.Render("● ")
	}
	protoW, pingW := 16, 9
	nameW := min(max(10, m.width-4-protoW-pingW-2), max(24, m.nameWidth()+2))
	name := truncate(s.Name, nameW)
	nameStyled := sText.Render(name)
	if current {
		nameStyled = sCurrent.Render(name)
	}
	pingTxt := app.PingLabel(s.Ping)
	pst := pingStyle(s.Ping)
	if m.pinging[s.ID] {
		pingTxt, pst = "…", sDim
	}
	return "  " + mark + nameStyled + strings.Repeat(" ", max(1, nameW-runewidth.StringWidth(name))) +
		sProto.Render(padRight(s.ProtoLabel(), protoW)) +
		pst.Render(padLeft(pingTxt, pingW))
}

// nameWidth — ширина самого длинного имени среди строк.
func (m *Model) nameWidth() int {
	w := 0
	for _, r := range m.rows {
		if !r.header {
			w = max(w, runewidth.StringWidth(r.server.Name))
		}
	}
	return w
}

func (m *Model) viewFooter() string {
	var b strings.Builder
	b.WriteString(sRule.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")
	l1, l2 := m.statusLines()
	b.WriteString(truncateStyled(l1, m.width) + "\n")
	b.WriteString(truncateStyled(l2, m.width) + "\n")
	b.WriteString(truncateStyled(m.messageLine(), m.width) + "\n")
	b.WriteString(truncateStyled(m.hintLine(), m.width))
	return b.String()
}

func (m *Model) statusLines() (string, string) {
	mode := app.ModeLabel(m.settings.Mode)
	routing := app.RoutingLabel(m.settings.Routing)
	if !m.status.Connected {
		if m.empty() {
			return "", ""
		}
		l1 := " " + sDim.Render("○ Не подключено") + sDim.Render("   режим ") + sText.Render(mode) +
			sDim.Render(" · ") + sText.Render(routing)
		l2 := " " + sDim.Render("Enter — подключиться к выбранному, f — к самому быстрому")
		if m.status.Crashed {
			l2 = " " + sBad.Render("xray остановился: "+m.status.Reason)
		}
		return l1, l2
	}
	s := m.status.Session
	l1 := " " + sOK.Render("● Подключено ") + sBold.Render(s.ServerName) + sDim.Render("  "+s.Protocol)
	var where string
	if s.Mode == store.ModeTUN {
		where = "TUN " + s.TunName + " (весь трафик)"
	} else {
		where = fmt.Sprintf("Proxy socks5 %s:%d", s.Listen, s.SocksPort)
		if s.HTTPPort > 0 {
			where += fmt.Sprintf(" · http :%d", s.HTTPPort)
		}
	}
	l1 += sDim.Render("   ") + sText.Render(where) + sDim.Render(" · ") + sText.Render(app.RoutingLabel(s.Routing))
	l2 := " " + sOK.Render("↑ "+padLeft(app.FormatSpeed(m.upSpeed), 11)) + "  " +
		sOK.Render("↓ "+padLeft(app.FormatSpeed(m.dnSpeed), 11)) +
		sDim.Render("   трафик ") + sText.Render("↑ "+app.FormatBytes(m.traffic.Up)+"  ↓ "+app.FormatBytes(m.traffic.Down)) +
		sDim.Render("   время ") + sText.Render(app.FormatDuration(time.Since(s.Started)))
	return l1, l2
}

func (m *Model) messageLine() string {
	switch m.mode {
	case mConfirm:
		return " " + sWarn.Render(m.confirmTxt) + sDim.Render("  y — да, любая другая — нет")
	case mSearch:
		return " " + sKey.Render("/") + " " + m.input.View()
	case mAdd:
		if !m.empty() {
			return " " + sKey.Render("Ссылка или ключ:") + " " + m.input.View()
		}
	case mEdit:
		for _, it := range settingsList {
			if it.key == m.editKey {
				return " " + sKey.Render(it.label+":") + " " + m.input.View()
			}
		}
	}
	if m.msg != "" {
		switch m.msgKind {
		case kErr:
			return " " + sBad.Render("✕ "+m.msg)
		case kOK:
			return " " + sOK.Render(m.msg)
		}
		return " " + sText.Render(m.msg)
	}
	if m.announce != "" {
		return " " + sAnnounce.Render("📢 "+strings.ReplaceAll(m.announce, "\n", " "))
	}
	if m.search != "" {
		return " " + sDim.Render("фильтр: ") + sText.Render(m.search) + sDim.Render("  (Esc — сбросить)")
	}
	// Подробности о выбранной строке.
	if m.cursor < len(m.rows) {
		r := m.rows[m.cursor]
		if !r.header && r.server.Ping < 0 && r.server.PingErr != "" {
			return " " + sBad.Render("✕ "+r.server.PingErr)
		}
		if r.header && r.sub != nil {
			var p []string
			if r.sub.LastErr != "" {
				p = append(p, sWarn.Render(r.sub.LastErr))
			}
			if r.sub.Support != "" {
				p = append(p, sDim.Render("поддержка: ")+sText.Render(r.sub.Support))
			}
			if r.sub.WebPage != "" {
				p = append(p, sDim.Render("сайт: ")+sText.Render(r.sub.WebPage))
			}
			if len(p) > 0 {
				return " " + strings.Join(p, sDim.Render(" · "))
			}
		}
	}
	return ""
}

func (m *Model) hintLine() string {
	type kv struct{ k, v string }
	var keys []kv
	switch {
	case m.mode == mAdd && m.empty():
		keys = []kv{{"Ctrl+Shift+V", "вставить"}, {"Enter", "добавить"}, {"Ctrl+C", "выход"}}
	case m.mode == mAdd || m.mode == mEdit:
		keys = []kv{{"Enter", "готово"}, {"Esc", "отмена"}}
	case m.mode == mSearch:
		keys = []kv{{"Enter", "применить"}, {"Esc", "сбросить"}}
	case m.mode == mSettings:
		keys = []kv{{"↑↓", "выбор"}, {"Enter", "изменить"}, {"Esc", "назад"}}
	case m.mode == mHelp:
		keys = []kv{{"любая клавиша", "закрыть"}}
	case m.tab == tabLogs:
		keys = []kv{{"↑↓ PgUp PgDn", "прокрутка"}, {"G", "в конец"}, {"Tab", "к серверам"}, {"q", "выход"}}
	default:
		keys = []kv{{"Enter", "подключить"}, {"d", "откл"}, {"p", "пинг"}, {"f", "быстрейший"}, {"u", "обновить"},
			{"a", "добавить"}, {"x", "удалить"}, {"/", "поиск"}, {"m", "режим"}, {"s", "настройки"}, {"?", "справка"}, {"q", "выход"}}
	}
	var parts []string
	for _, p := range keys {
		parts = append(parts, sKey.Render(p.k)+" "+sDim.Render(p.v))
	}
	return " " + strings.Join(parts, "  ")
}

func (m *Model) viewHelp() string {
	rows := [][2]string{
		{"Вставка (Ctrl+Shift+V)", "добавить подписку или ключи — в любой момент"},
		{"↑/↓, j/k", "выбор сервера"},
		{"Enter", "подключиться; на заголовке — свернуть/развернуть"},
		{"d", "отключиться"},
		{"p", "пинг всех (реальная задержка через xray)"},
		{"f", "пинг и подключение к самому быстрому"},
		{"u", "обновить подписки"},
		{"a", "добавить ссылку или ключ вручную"},
		{"x", "удалить сервер или подписку"},
		{"/", "поиск"},
		{"m", "режим: Proxy ↔ TUN (весь трафик, нужен root)"},
		{"r", "маршрутизация: всё через VPN → RU напрямую → свои правила"},
		{"s", "настройки"},
		{"Tab, l", "вкладка логов xray"},
		{"q", "выйти (VPN остаётся подключённым; отключить — d)"},
	}
	var b strings.Builder
	b.WriteString(sBold.Render("Горячие клавиши") + "\n")
	for _, r := range rows {
		b.WriteString(sKey.Render(padRight(r[0], 24)) + sText.Render(r[1]) + "\n")
	}
	b.WriteString("\n" + sDim.Render("Данные: "+m.app.Store.Dir))
	b.WriteString("\n" + sDim.Render("harley "+m.version))
	return m.panel(b.String())
}

func (m *Model) viewSettings() string {
	var b strings.Builder
	b.WriteString(sBold.Render("Настройки") + "\n" + sDim.Render(m.app.Store.SettingsPath()) + "\n\n")
	for i, it := range settingsList {
		line := padRight(it.label, 34) + sText.Render(truncate(it.value(m.settings), max(10, m.width-50)))
		if i == m.setCursor {
			line = sKey.Render("› ") + line
		} else {
			line = "  " + line
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n" + sDim.Render("«Свои правила» маршрутизации — custom_rules в config.json"))
	return m.panel(b.String())
}

// panel — рамка по центру, не шире и не выше области списка.
func (m *Model) panel(content string) string {
	maxW := max(20, m.width-6)
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		lines[i] = truncateStyled(l, maxW)
	}
	st := sBox
	if len(lines)+4 > m.bodyHeight() {
		st = st.Padding(0, 2)
	}
	return lipgloss.Place(m.width, m.bodyHeight(), lipgloss.Center, lipgloss.Center, st.Render(strings.Join(lines, "\n")))
}

func colorLog(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		low := strings.ToLower(l)
		switch {
		case strings.Contains(low, "[error]") || strings.Contains(low, "failed") || strings.Contains(low, "panic"):
			out[i] = sBad.Render(l)
		case strings.Contains(low, "[warning]"):
			out[i] = sWarn.Render(l)
		case strings.HasPrefix(l, "==="):
			out[i] = sTitle.Render(l)
		default:
			out[i] = sText.Render(l)
		}
	}
	if len(out) == 0 {
		return []string{sDim.Render("Лог пуст — xray ещё не запускался")}
	}
	return out
}

func truncate(s string, w int) string {
	if runewidth.StringWidth(s) <= w {
		return s
	}
	return runewidth.Truncate(s, w, "…")
}

func truncateStyled(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}

func padRight(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func padLeft(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}
