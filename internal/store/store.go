// Package store хранит настройки и состояние harley на диске:
// ~/.config/harley/ (или /etc/harley/ при запуске от root).
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/sub"
)

// Режимы подключения.
const (
	ModeProxy = "proxy"
	ModeTUN   = "tun"
)

// Пресеты маршрутизации.
const (
	RouteAll      = "all"
	RouteRUDirect = "ru-direct"
	RouteCustom   = "custom"
)

// CustomRules — «свои правила». Значения в синтаксисе xray:
// "domain:example.com", "geosite:google", "full:a.b", "keyword:x";
// для IP — CIDR или "geoip:cn".
type CustomRules struct {
	DirectDomains []string `json:"direct_domains"`
	DirectIPs     []string `json:"direct_ips"`
	ProxyDomains  []string `json:"proxy_domains"`
	ProxyIPs      []string `json:"proxy_ips"`
	BlockDomains  []string `json:"block_domains"`
	BlockIPs      []string `json:"block_ips"`
	// DefaultDirect — всё, что не попало в правила, идёт напрямую.
	DefaultDirect bool `json:"default_direct"`
}

// Settings — config.json.
type Settings struct {
	XrayPath string `json:"xray_path"` // пусто — искать в PATH
	// AutoInstallXray — если xray нет, скачать официальный релиз (в Alpine
	// его нет в репозиториях).
	AutoInstallXray bool   `json:"auto_install_xray"`
	XrayReleases    string `json:"xray_releases"` // зеркало релизов; пусто — GitHub
	AssetDir        string `json:"asset_dir"`     // geoip.dat/geosite.dat; пусто — стандартные места

	Mode       string `json:"mode"` // proxy | tun
	ListenAddr string `json:"listen"`
	SocksPort  int    `json:"socks_port"`
	HTTPPort   int    `json:"http_port"`
	TunName    string `json:"tun_name"`
	TunMTU     int    `json:"tun_mtu"`

	Routing string      `json:"routing"` // all | ru-direct | custom
	Custom  CustomRules `json:"custom_rules"`
	DNS     []string    `json:"dns"` // DNS через VPN
	// IPv6 — отдавать приложениям IPv6-адреса. По умолчанию выключено: если
	// у VPN-сервера нет IPv6, приложения, выбравшие IPv6, зависают.
	IPv6 bool `json:"ipv6"`

	AutoConnect     bool   `json:"autoconnect"`       // после импорта: пинг → лучший → подключиться
	AutoUpdateHours int    `json:"auto_update_hours"` // если подписка не задаёт интервал
	UserAgent       string `json:"user_agent"`
	SendHWID        bool   `json:"send_hwid"`
	HWID            string `json:"hwid"`

	PingURL     string `json:"ping_url"`
	PingTimeout int    `json:"ping_timeout_sec"`
	LogLevel    string `json:"log_level"`
}

// Defaults — настройки по умолчанию.
func Defaults() Settings {
	return Settings{
		AutoInstallXray: true,
		Mode:            ModeProxy,
		ListenAddr:      "127.0.0.1",
		SocksPort:       10808,
		HTTPPort:        10809,
		TunName:         "harley0",
		TunMTU:          1500,
		Routing:         RouteAll,
		DNS:             []string{"1.1.1.1", "8.8.8.8"},
		AutoConnect:     true,
		AutoUpdateHours: 12,
		UserAgent:       sub.DefaultUserAgent,
		SendHWID:        true,
		PingURL:         "https://www.gstatic.com/generate_204",
		PingTimeout:     5,
		LogLevel:        "warning",
	}
}

// State — state.json: подписки, серверы и последний выбор.
type State struct {
	Subscriptions []*model.Subscription `json:"subscriptions"`
	Servers       []*model.Server       `json:"servers"`
	LastServerID  string                `json:"last_server_id,omitempty"`
}

// Store — каталог данных harley.
type Store struct {
	Dir    string
	RunDir string
}

// Open определяет каталоги и создаёт их.
func Open() (*Store, error) {
	s := &Store{Dir: DefaultDir()}
	if os.Geteuid() == 0 && os.Getenv("HARLEY_HOME") == "" {
		s.RunDir = "/run/harley"
	} else {
		s.RunDir = filepath.Join(s.Dir, "run")
	}
	return s, s.ensure()
}

// OpenAt — хранилище в произвольном каталоге (тесты).
func OpenAt(dir string) (*Store, error) {
	s := &Store{Dir: dir, RunDir: filepath.Join(dir, "run")}
	return s, s.ensure()
}

func (s *Store) ensure() error {
	for _, d := range []string{s.Dir, s.RunDir, filepath.Join(s.Dir, "cache")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("не удалось создать %s: %w", d, err)
		}
	}
	return nil
}

// DefaultDir: $HARLEY_HOME, /etc/harley для root, иначе ~/.config/harley.
func DefaultDir() string {
	if d := os.Getenv("HARLEY_HOME"); d != "" {
		return d
	}
	if os.Geteuid() == 0 {
		return "/etc/harley"
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "harley")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".config", "harley")
}

// Пути к файлам.
func (s *Store) SettingsPath() string { return filepath.Join(s.Dir, "config.json") }
func (s *Store) StatePath() string    { return filepath.Join(s.Dir, "state.json") }
func (s *Store) CachePath(subID string) string {
	return filepath.Join(s.Dir, "cache", subID+".txt")
}
func (s *Store) XrayConfigPath() string { return filepath.Join(s.RunDir, "xray.json") }
func (s *Store) PidPath() string        { return filepath.Join(s.RunDir, "xray.pid") }
func (s *Store) LogPath() string        { return filepath.Join(s.RunDir, "xray.log") }
func (s *Store) SessionPath() string    { return filepath.Join(s.RunDir, "session.json") }
func (s *Store) lockPath() string       { return filepath.Join(s.Dir, ".lock") }

// LoadSettings читает config.json; отсутствующие поля берутся по умолчанию.
// Если файла нет — создаёт его, чтобы пользователю было что редактировать.
func (s *Store) LoadSettings() (Settings, error) {
	st := Defaults()
	b, err := os.ReadFile(s.SettingsPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
		st.HWID = newHWID()
		return st, s.SaveSettings(st)
	case err != nil:
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return Defaults(), fmt.Errorf("%s: ошибка в JSON: %w", s.SettingsPath(), err)
	}
	if st.HWID == "" {
		st.HWID = newHWID()
		_ = s.SaveSettings(st)
	}
	st.normalize()
	return st, nil
}

func (st *Settings) normalize() {
	d := Defaults()
	if st.Mode != ModeTUN {
		st.Mode = ModeProxy
	}
	switch st.Routing {
	case RouteAll, RouteRUDirect, RouteCustom:
	default:
		st.Routing = RouteAll
	}
	if st.ListenAddr == "" {
		st.ListenAddr = d.ListenAddr
	}
	if st.SocksPort <= 0 || st.SocksPort > 65535 {
		st.SocksPort = d.SocksPort
	}
	if st.HTTPPort < 0 || st.HTTPPort > 65535 {
		st.HTTPPort = d.HTTPPort
	}
	if st.TunName == "" {
		st.TunName = d.TunName
	}
	if st.TunMTU <= 0 {
		st.TunMTU = d.TunMTU
	}
	if len(st.DNS) == 0 {
		st.DNS = d.DNS
	}
	if st.UserAgent == "" {
		st.UserAgent = d.UserAgent
	}
	if st.PingURL == "" {
		st.PingURL = d.PingURL
	}
	if st.PingTimeout <= 0 {
		st.PingTimeout = d.PingTimeout
	}
	if st.AutoUpdateHours < 0 {
		st.AutoUpdateHours = 0
	}
	if st.LogLevel == "" {
		st.LogLevel = d.LogLevel
	}
}

// SaveSettings пишет config.json.
func (s *Store) SaveSettings(st Settings) error {
	return writeJSON(s.SettingsPath(), st)
}

// LoadState читает state.json (пустое состояние, если файла нет).
func (s *Store) LoadState() (*State, error) {
	st := &State{}
	b, err := os.ReadFile(s.StatePath())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return &State{}, fmt.Errorf("%s повреждён: %w", s.StatePath(), err)
	}
	return st, nil
}

// SaveState пишет state.json атомарно.
func (s *Store) SaveState(st *State) error {
	return writeJSON(s.StatePath(), st)
}

// Update — чтение-изменение-запись состояния под файловой блокировкой,
// чтобы TUI и CLI (например, cron `harley update`) не затирали друг друга.
func (s *Store) Update(fn func(*State) error) (*State, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := s.LoadState()
	if err != nil {
		return nil, err
	}
	if err := fn(st); err != nil {
		return st, err
	}
	return st, s.SaveState(st)
}

func (s *Store) lock() (func(), error) {
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(b, '\n'), 0o600)
}

// WriteFileAtomic пишет файл через временный + rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func newHWID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Helpers по состоянию.

// ServerByID ищет сервер.
func (st *State) ServerByID(id string) *model.Server {
	for _, s := range st.Servers {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// SubByID ищет подписку.
func (st *State) SubByID(id string) *model.Subscription {
	for _, s := range st.Subscriptions {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// ServersOf возвращает серверы подписки.
func (st *State) ServersOf(subID string) []*model.Server {
	var out []*model.Server
	for _, s := range st.Servers {
		if s.SubID == subID {
			out = append(out, s)
		}
	}
	return out
}
