// Package app — сценарии harley (импорт, обновление подписок, пинг,
// подключение), общие для TUI и командной строки.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/parse"
	"github.com/nijiku49/tuixrayclient/internal/store"
	"github.com/nijiku49/tuixrayclient/internal/sub"
	"github.com/nijiku49/tuixrayclient/internal/xray"
)

// App — точка входа для всех сценариев.
type App struct {
	Store *store.Store
	// HTTPClient — для загрузки подписок (тесты подменяют).
	HTTPClient *http.Client
	Now        func() time.Time
	// XrayLayout — куда ставить xray; пусто — xray.DefaultLayout().
	XrayLayout xray.InstallLayout
}

// New открывает стандартное хранилище.
func New() (*App, error) {
	st, err := store.Open()
	if err != nil {
		return nil, err
	}
	return &App{Store: st, Now: time.Now}, nil
}

// NewAt — хранилище в каталоге (тесты).
func NewAt(dir string) (*App, error) {
	st, err := store.OpenAt(dir)
	if err != nil {
		return nil, err
	}
	return &App{Store: st, Now: time.Now}, nil
}

// Settings читает актуальные настройки.
func (a *App) Settings() (store.Settings, error) { return a.Store.LoadSettings() }

// SaveSettings сохраняет настройки.
func (a *App) SaveSettings(s store.Settings) error { return a.Store.SaveSettings(s) }

// State читает состояние.
func (a *App) State() (*store.State, error) { return a.Store.LoadState() }

// ImportReport — итог импорта.
type ImportReport struct {
	Added     int      // новых серверов
	Existing  int      // уже были
	SubsAdded []string // имена добавленных/обновлённых подписок
	ServerIDs []string // все серверы, пришедшие в этом импорте
	Errors    []string // некритичные ошибки (битые строки, недоступная подписка)
	Announce  []string
}

// Summary — короткая строка для статуса.
func (r ImportReport) Summary() string {
	var parts []string
	if len(r.SubsAdded) > 0 {
		parts = append(parts, "подписка «"+strings.Join(r.SubsAdded, "», «")+"»")
	}
	switch {
	case r.Added > 0:
		parts = append(parts, fmt.Sprintf("добавлено серверов: %d", r.Added))
	case r.Existing > 0:
		parts = append(parts, fmt.Sprintf("серверы уже были в списке (%d)", r.Existing))
	}
	if len(r.Errors) > 0 {
		parts = append(parts, fmt.Sprintf("пропущено с ошибками: %d", len(r.Errors)))
	}
	return strings.Join(parts, " · ")
}

// Import разбирает всё, что вставил пользователь, и добавляет в список.
func (a *App) Import(ctx context.Context, text string) (ImportReport, error) {
	var rep ImportReport
	in := parse.DetectInput(text)
	rep.Errors = append(rep.Errors, in.Errors...)

	for _, u := range in.SubURLs {
		id := model.SubIDFromURL(u)
		if _, err := a.Store.Update(func(st *store.State) error {
			if st.SubByID(id) == nil {
				st.Subscriptions = append(st.Subscriptions, &model.Subscription{ID: id, URL: u, Name: hostOf(u)})
			}
			return nil
		}); err != nil {
			return rep, err
		}
		res, err := a.UpdateSub(ctx, id)
		if res != nil {
			rep.SubsAdded = append(rep.SubsAdded, res.Name)
			rep.Added += res.Added
			rep.Existing += res.Existing
			rep.ServerIDs = append(rep.ServerIDs, res.ServerIDs...)
			if res.Announce != "" {
				rep.Announce = append(rep.Announce, res.Announce)
			}
		}
		if err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		}
	}

	if len(in.Servers) > 0 {
		if _, err := a.Store.Update(func(st *store.State) error {
			for _, s := range in.Servers {
				rep.ServerIDs = append(rep.ServerIDs, s.ID)
				if st.ServerByID(s.ID) != nil {
					rep.Existing++
					continue
				}
				s.SubID = model.ManualSubID
				st.Servers = append(st.Servers, s)
				rep.Added++
			}
			return nil
		}); err != nil {
			return rep, err
		}
	}
	if len(in.SubURLs) == 0 && len(in.Servers) == 0 {
		msg := "не удалось распознать ни ссылку, ни ключ"
		if len(in.Errors) > 0 {
			msg += ": " + in.Errors[0]
		}
		return rep, errors.New(msg)
	}
	if len(rep.ServerIDs) == 0 && len(rep.Errors) > 0 {
		return rep, errors.New(rep.Errors[0])
	}
	return rep, nil
}

func hostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

// SubUpdate — итог обновления подписки.
type SubUpdate struct {
	Name      string
	Added     int
	Existing  int
	ServerIDs []string
	Announce  string
}

// UpdateSub загружает подписку. Если сеть недоступна — серверы остаются
// из сохранённой копии, а ошибка записывается в подписку.
func (a *App) UpdateSub(ctx context.Context, id string) (*SubUpdate, error) {
	state, err := a.Store.LoadState()
	if err != nil {
		return nil, err
	}
	sb := state.SubByID(id)
	if sb == nil {
		return nil, fmt.Errorf("подписка %s не найдена", id)
	}
	settings, _ := a.Store.LoadSettings()
	opt := sub.Options{UserAgent: settings.UserAgent, Client: a.HTTPClient}
	if settings.SendHWID {
		opt.HWID = settings.HWID
	}
	res, fetchErr := sub.Fetch(ctx, sb.URL, opt)

	out := &SubUpdate{}
	_, err = a.Store.Update(func(st *store.State) error {
		sb := st.SubByID(id)
		if sb == nil {
			return fmt.Errorf("подписка удалена")
		}
		out.Name = sb.Name
		if fetchErr != nil && (res == nil || len(res.Servers) == 0) {
			sb.LastErr = fetchErr.Error()
			for _, s := range st.ServersOf(id) {
				out.ServerIDs = append(out.ServerIDs, s.ID)
			}
			// Серверов нет совсем — восстанавливаем из кэша последнего ответа.
			if len(out.ServerIDs) == 0 {
				if body, err := os.ReadFile(a.Store.CachePath(id)); err == nil {
					for _, s := range parse.ParseBody(body).Servers {
						s.SubID = id
						st.Servers = append(st.Servers, s)
						out.ServerIDs = append(out.ServerIDs, s.ID)
					}
				}
			}
			return nil
		}
		m := res.Meta
		if m.Title != "" {
			sb.Name = m.Title
		}
		sb.Info, sb.Interval, sb.Support, sb.WebPage = m.Info, m.IntervalHours, m.SupportURL, m.WebPage
		if m.Announce != "" && m.Announce != sb.Announce {
			out.Announce = m.Announce
		}
		sb.Announce = m.Announce
		sb.Updated = a.Now()
		sb.LastErr = ""
		out.Name = sb.Name

		// Заменяем серверы подписки, сохраняя результаты пинга.
		old := map[string]*model.Server{}
		for _, s := range st.ServersOf(id) {
			old[s.ID] = s
		}
		var fresh []*model.Server
		seen := map[string]bool{}
		for _, s := range res.Servers {
			if seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			s.SubID = id
			if o := old[s.ID]; o != nil {
				s.Ping, s.PingedAt = o.Ping, o.PingedAt
				out.Existing++
			} else {
				out.Added++
			}
			fresh = append(fresh, s)
			out.ServerIDs = append(out.ServerIDs, s.ID)
		}
		st.Servers = replaceGroup(st.Servers, id, fresh)
		return nil
	})
	if err != nil {
		return out, err
	}
	if fetchErr == nil && res != nil {
		_ = store.WriteFileAtomic(a.Store.CachePath(id), res.Body, 0o600)
	}
	if fetchErr != nil && len(out.ServerIDs) > 0 {
		return out, fmt.Errorf("%v — работаю на сохранённой копии", fetchErr)
	}
	return out, fetchErr
}

// replaceGroup заменяет серверы подписки, сохраняя положение группы.
func replaceGroup(all []*model.Server, subID string, fresh []*model.Server) []*model.Server {
	out := make([]*model.Server, 0, len(all)+len(fresh))
	inserted := false
	for _, s := range all {
		if s.SubID == subID {
			if !inserted {
				out = append(out, fresh...)
				inserted = true
			}
			continue
		}
		out = append(out, s)
	}
	if !inserted {
		out = append(out, fresh...)
	}
	return out
}

// SubDue — пора ли обновлять подписку по таймеру.
func (a *App) SubDue(sb *model.Subscription, settings store.Settings) bool {
	hours := sb.Interval
	if hours <= 0 {
		hours = settings.AutoUpdateHours
	}
	if hours <= 0 {
		return false
	}
	return a.Now().Sub(sb.Updated) >= time.Duration(hours)*time.Hour
}

// UpdateAll обновляет подписки (все или только «просроченные»).
func (a *App) UpdateAll(ctx context.Context, onlyDue bool) (updated []string, errs []error) {
	state, err := a.Store.LoadState()
	if err != nil {
		return nil, []error{err}
	}
	settings, _ := a.Store.LoadSettings()
	for _, sb := range state.Subscriptions {
		if onlyDue && !a.SubDue(sb, settings) {
			continue
		}
		res, err := a.UpdateSub(ctx, sb.ID)
		name := sb.Name
		if res != nil && res.Name != "" {
			name = res.Name
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		updated = append(updated, name)
	}
	return updated, errs
}

// Delete удаляет сервер или подписку целиком.
func (a *App) Delete(id string) error {
	_, err := a.Store.Update(func(st *store.State) error {
		if sb := st.SubByID(id); sb != nil {
			var subs []*model.Subscription
			for _, s := range st.Subscriptions {
				if s.ID != id {
					subs = append(subs, s)
				}
			}
			st.Subscriptions = subs
			st.Servers = replaceGroup(st.Servers, id, nil)
			_ = os.Remove(a.Store.CachePath(id))
			return nil
		}
		for i, s := range st.Servers {
			if s.ID == id {
				st.Servers = append(st.Servers[:i], st.Servers[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("не найдено: %s", id)
	})
	return err
}

// PingReport — итог пинга.
type PingReport struct {
	Results []xray.PingResult
	TCPOnly bool // xray не найден — только TCP-пинг
}

// Ping меряет задержку серверов (все, если ids пуст) и сохраняет результат.
func (a *App) Ping(ctx context.Context, ids []string) (PingReport, error) {
	state, err := a.Store.LoadState()
	if err != nil {
		return PingReport{}, err
	}
	settings, _ := a.Store.LoadSettings()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var servers []*model.Server
	for _, s := range state.Servers {
		if len(ids) == 0 || want[s.ID] {
			servers = append(servers, s)
		}
	}
	if len(servers) == 0 {
		return PingReport{}, errors.New("нет серверов для пинга")
	}
	timeout := time.Duration(settings.PingTimeout) * time.Second
	var rep PingReport
	bin, binErr := a.EnsureXray(ctx, settings)
	if binErr != nil {
		rep.TCPOnly = true
		rep.Results = xray.TCPPing(ctx, servers, timeout)
	} else {
		bind := ""
		if sess, ok := a.ActiveSession(); ok && sess.Mode == store.ModeTUN {
			bind = sess.BindIface
		}
		rep.Results = xray.URLTest(ctx, servers, xray.PingOptions{
			Bin: bin, URL: settings.PingURL, Timeout: timeout, WorkDir: a.Store.RunDir,
			AssetDir: xray.FindAssetDir(settings.AssetDir, bin), BindIface: bind,
		})
	}
	now := a.Now()
	_, err = a.Store.Update(func(st *store.State) error {
		for _, r := range rep.Results {
			if s := st.ServerByID(r.ID); s != nil {
				s.PingedAt = now
				if r.Err != nil {
					s.Ping, s.PingErr = -1, r.Err.Error()
				} else {
					s.Ping, s.PingErr = r.Ms, ""
				}
			}
		}
		return nil
	})
	return rep, err
}

// FirstPingError — самая частая причина неудачи пинга (для сообщения).
func FirstPingError(rep PingReport) string {
	count := map[string]int{}
	best := ""
	for _, r := range rep.Results {
		if r.Err == nil {
			continue
		}
		e := r.Err.Error()
		count[e]++
		if best == "" || count[e] > count[best] {
			best = e
		}
	}
	return best
}

// Fastest — сервер с наименьшим пингом среди ids (или всех).
func Fastest(st *store.State, ids []string) *model.Server {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var best *model.Server
	for _, s := range st.Servers {
		if len(ids) > 0 && !want[s.ID] {
			continue
		}
		if s.Ping > 0 && (best == nil || s.Ping < best.Ping) {
			best = s
		}
	}
	return best
}

// FindServer ищет сервер по ID, номеру (1..N), точному имени или
// уникальной подстроке имени.
func FindServer(st *store.State, query string) (*model.Server, error) {
	q := strings.TrimSpace(query)
	if s := st.ServerByID(q); s != nil {
		return s, nil
	}
	if n, err := strconv.Atoi(q); err == nil && n >= 1 && n <= len(st.Servers) {
		return st.Servers[n-1], nil
	}
	var matches []*model.Server
	for _, s := range st.Servers {
		if strings.EqualFold(s.Name, q) {
			return s, nil
		}
		if strings.Contains(strings.ToLower(s.Name), strings.ToLower(q)) {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("сервер %q не найден (смотри `harley list`)", q)
	case 1:
		return matches[0], nil
	}
	var names []string
	for _, m := range matches {
		names = append(names, m.Name)
	}
	sort.Strings(names)
	return nil, fmt.Errorf("под %q подходит несколько серверов: %s", q, strings.Join(names, ", "))
}

// EnsureXray находит xray, а если его нет и разрешено — скачивает
// официальный релиз (сценарий «вставил — работает» на чистом Alpine).
func (a *App) EnsureXray(ctx context.Context, settings store.Settings) (string, error) {
	bin, err := xray.FindBinary(settings.XrayPath)
	if err == nil || settings.XrayPath != "" || !settings.AutoInstallXray {
		return bin, err
	}
	res, ierr := xray.Install(ctx, xray.InstallOptions{Releases: settings.XrayReleases, Layout: a.XrayLayout})
	if ierr != nil {
		return "", fmt.Errorf("xray не найден, автоустановка не удалась: %w", ierr)
	}
	// Если поставили туда, где FindBinary не ищет, — запоминаем путь.
	if found, err := xray.FindBinary(""); err != nil || found != res.Bin {
		if cur, err := a.Store.LoadSettings(); err == nil {
			cur.XrayPath = res.Bin
			_ = a.Store.SaveSettings(cur)
		}
	}
	return res.Bin, nil
}

// WillInstallXray — xray нет и он будет скачан при подключении/пинге.
func (a *App) WillInstallXray() bool {
	s, err := a.Store.LoadSettings()
	if err != nil || s.XrayPath != "" || !s.AutoInstallXray {
		return false
	}
	_, err = xray.FindBinary("")
	return err != nil
}

// Session — активное подключение (session.json).
type Session struct {
	ServerID    string    `json:"server_id"`
	ServerName  string    `json:"server_name"`
	Protocol    string    `json:"protocol"`
	Mode        string    `json:"mode"`
	Routing     string    `json:"routing"`
	Started     time.Time `json:"started"`
	Pid         int       `json:"pid"`
	Listen      string    `json:"listen"`
	SocksPort   int       `json:"socks_port"`
	HTTPPort    int       `json:"http_port"`
	MetricsPort int       `json:"metrics_port"`
	TunName     string    `json:"tun_name,omitempty"`
	BindIface   string    `json:"bind_iface,omitempty"`
}

func (a *App) proc(bin, asset string) *xray.Proc {
	return &xray.Proc{
		Bin: bin, Config: a.Store.XrayConfigPath(), PidFile: a.Store.PidPath(),
		LogFile: a.Store.LogPath(), AssetDir: asset,
	}
}

func (a *App) loadSession() (*Session, error) {
	b, err := os.ReadFile(a.Store.SessionPath())
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ActiveSession — текущее подключение, если xray жив.
func (a *App) ActiveSession() (*Session, bool) {
	s, err := a.loadSession()
	if err != nil {
		return nil, false
	}
	if _, ok := a.proc("", "").Running(); !ok {
		return s, false
	}
	return s, true
}

// Connect подключается к серверу (serverID пуст — к последнему, а если
// его нет — к самому быстрому).
func (a *App) Connect(ctx context.Context, serverID string) (*Session, error) {
	settings, err := a.Store.LoadSettings()
	if err != nil {
		return nil, err
	}
	state, err := a.Store.LoadState()
	if err != nil {
		return nil, err
	}
	if len(state.Servers) == 0 {
		return nil, errors.New("список серверов пуст — добавь ссылку или ключ")
	}
	var srv *model.Server
	switch {
	case serverID != "":
		if srv = state.ServerByID(serverID); srv == nil {
			return nil, fmt.Errorf("сервер %s не найден", serverID)
		}
	case state.LastServerID != "" && state.ServerByID(state.LastServerID) != nil:
		srv = state.ServerByID(state.LastServerID)
	default:
		if srv = Fastest(state, nil); srv == nil {
			srv = state.Servers[0]
		}
	}

	bin, err := a.EnsureXray(ctx, settings)
	if err != nil {
		return nil, err
	}
	// Уже подключены — сначала отключаемся.
	if _, ok := a.ActiveSession(); ok {
		if err := a.Disconnect(); err != nil {
			return nil, err
		}
	} else {
		_ = a.proc(bin, "").Stop()
	}

	opts := xray.OptionsFromSettings(settings)
	sess := &Session{
		ServerID: srv.ID, ServerName: srv.Name, Protocol: srv.ProtoLabel(),
		Mode: settings.Mode, Routing: settings.Routing, Listen: settings.ListenAddr,
		SocksPort: settings.SocksPort, HTTPPort: settings.HTTPPort,
	}
	if settings.Mode == store.ModeTUN {
		if err := xray.CheckTUN(); err != nil {
			return nil, err
		}
		route, err := xray.DefaultRoute(settings.TunName)
		if err != nil {
			return nil, err
		}
		opts.BindInterface = route.Iface
		sess.TunName, sess.BindIface = settings.TunName, route.Iface
		if ips, err := xray.ResolveServer(srv.Address); err != nil {
			return nil, err
		} else if len(ips) > 0 {
			opts.ServerHosts = map[string][]string{srv.Address: ips}
		}
	}
	for _, p := range []int{settings.SocksPort, settings.HTTPPort} {
		if p > 0 && !xray.PortFree(settings.ListenAddr, p) {
			return nil, fmt.Errorf("порт %d уже занят другой программой — смени его в настройках (s) или останови другой VPN-клиент", p)
		}
	}
	if ports, err := xray.FreePorts(1); err == nil {
		opts.MetricsPort = ports[0]
		sess.MetricsPort = ports[0]
	}
	asset := xray.FindAssetDir(settings.AssetDir, bin)
	if xray.NeedsGeoFiles(opts) && asset == "" {
		return nil, errors.New("для маршрутизации «RU напрямую» нужны geoip.dat и geosite.dat — положи их в /usr/share/xray (см. README) или выбери «всё через VPN» (клавиша r)")
	}
	cfg, err := xray.Build(srv, opts)
	if err != nil {
		return nil, fmt.Errorf("не удалось собрать конфиг: %w", err)
	}
	if err := store.WriteFileAtomic(a.Store.XrayConfigPath(), cfg, 0o600); err != nil {
		return nil, err
	}
	p := a.proc(bin, asset)
	pid, err := p.Start(700 * time.Millisecond)
	if err != nil {
		return nil, err
	}
	if settings.Mode == store.ModeTUN {
		if err := xray.SetupTunRoutes(settings.TunName, 5*time.Second); err != nil {
			_ = p.Stop()
			xray.TeardownTunRoutes(settings.TunName)
			return nil, err
		}
	}
	sess.Pid = pid
	sess.Started = a.Now()
	b, _ := json.MarshalIndent(sess, "", "  ")
	if err := store.WriteFileAtomic(a.Store.SessionPath(), b, 0o600); err != nil {
		return sess, err
	}
	_, err = a.Store.Update(func(st *store.State) error {
		st.LastServerID = srv.ID
		return nil
	})
	return sess, err
}

// Disconnect останавливает xray и убирает маршруты.
func (a *App) Disconnect() error {
	sess, _ := a.loadSession()
	if err := a.proc("", "").Stop(); err != nil {
		return err
	}
	if sess != nil && sess.Mode == store.ModeTUN && sess.TunName != "" {
		xray.TeardownTunRoutes(sess.TunName)
	}
	_ = os.Remove(a.Store.SessionPath())
	return nil
}

// Status — состояние подключения.
type Status struct {
	Connected bool
	Session   *Session
	// Crashed — сессия есть, а xray умер; Reason — объяснение из лога.
	Crashed bool
	Reason  string
}

// GetStatus возвращает текущее состояние.
func (a *App) GetStatus() Status {
	sess, alive := a.ActiveSession()
	switch {
	case sess == nil:
		return Status{}
	case alive:
		return Status{Connected: true, Session: sess}
	}
	return Status{Session: sess, Crashed: true, Reason: xray.ExplainLog(xray.TailFile(a.Store.LogPath(), 30))}
}

// AutoConnect: пинг → самый быстрый → подключение (сценарий «вставил — работает»).
func (a *App) AutoConnect(ctx context.Context, ids []string) (*Session, *model.Server, error) {
	rep, err := a.Ping(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	state, err := a.Store.LoadState()
	if err != nil {
		return nil, nil, err
	}
	best := Fastest(state, ids)
	if best == nil {
		msg := "ни один сервер не ответил на пинг"
		if r := FirstPingError(rep); r != "" {
			msg += ": " + r
		}
		return nil, nil, errors.New(msg)
	}
	sess, err := a.Connect(ctx, best.ID)
	return sess, best, err
}
