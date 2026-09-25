// harley — TUI VPN-клиент для Alpine Linux на базе xray-core.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/app"
	"github.com/nijiku49/tuixrayclient/internal/store"
	"github.com/nijiku49/tuixrayclient/internal/tui"
	"github.com/nijiku49/tuixrayclient/internal/xray"
)

// version задаётся при сборке: -ldflags "-X main.version=…".
var version = "dev"

const usage = `harley — VPN-клиент на xray-core (аналог Happ в терминале)

Использование:
  harley                        открыть TUI
  harley add <ссылка|ключ>…     добавить подписку или ключи (без аргументов — из stdin)
        --no-connect            не подключаться автоматически после импорта
  harley connect [сервер]       подключиться (сервер: номер, имя или его часть;
                                без аргумента — к последнему серверу)
  harley disconnect             отключиться
  harley status [-q]            состояние (код выхода 0 — подключено, 3 — нет)
  harley update [--due]         обновить подписки (--due — только те, у которых истёк интервал)
  harley ping                   пинг всех серверов (URL-тест через xray)
  harley list                   список серверов
  harley mode proxy|tun         режим подключения
  harley routing all|ru|custom  маршрутизация: всё через VPN / RU напрямую / свои правила
  harley logs [-n 50]           последние строки лога xray
  harley version                версия

Данные: ~/.config/harley/ (от root — /etc/harley/), переопределяется $HARLEY_HOME.
`

func main() {
	if len(os.Args) < 2 {
		runTUI()
		return
	}
	cmd, args := os.Args[1], os.Args[2:]
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "add", "import":
		err = cmdAdd(ctx, args)
	case "connect", "up":
		err = cmdConnect(ctx, args)
	case "disconnect", "down":
		err = cmdDisconnect()
	case "status":
		err = cmdStatus(args)
	case "update":
		err = cmdUpdate(ctx, args)
	case "ping":
		err = cmdPing(ctx)
	case "list", "ls":
		err = cmdList()
	case "mode":
		err = cmdMode(args)
	case "routing":
		err = cmdRouting(args)
	case "logs", "log":
		err = cmdLogs(args)
	case "tui":
		runTUI()
	case "version", "--version", "-v":
		fmt.Println("harley", version)
		if a, e := app.New(); e == nil {
			if s, e := a.Settings(); e == nil {
				if bin, e := xray.FindBinary(s.XrayPath); e == nil {
					fmt.Println(xray.Version(bin))
				}
			}
		}
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		var ex exitErr
		if errors.As(err, &ex) {
			os.Exit(ex.code)
		}
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

type exitErr struct{ code int }

func (e exitErr) Error() string { return fmt.Sprintf("exit %d", e.code) }

func openApp() *app.App {
	a, err := app.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
	return a
}

func runTUI() {
	a := openApp()
	if err := tui.Run(a, version); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func cmdAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	noConnect := fs.Bool("no-connect", false, "не подключаться после импорта")
	_ = fs.Parse(reorderFlags(args))
	text := strings.Join(fs.Args(), "\n")
	if text == "" || text == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<20))
		if err != nil {
			return err
		}
		text = string(b)
	}
	a := openApp()
	rep, err := a.Import(ctx, text)
	for _, e := range rep.Errors {
		fmt.Fprintln(os.Stderr, "  пропущено:", e)
	}
	for _, an := range rep.Announce {
		fmt.Println("📢", an)
	}
	if err != nil {
		return err
	}
	fmt.Println("✓", rep.Summary())
	settings, _ := a.Settings()
	if *noConnect || !settings.AutoConnect || len(rep.ServerIDs) == 0 {
		return nil
	}
	fmt.Printf("Пингую %d серверов и подключаюсь к самому быстрому…\n", len(rep.ServerIDs))
	sess, best, err := a.AutoConnect(ctx, rep.ServerIDs)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Подключено: %s (%d мс) — %s\n", best.Name, best.Ping, describeSession(sess))
	return nil
}

// reorderFlags позволяет писать флаги после позиционных аргументов.
func reorderFlags(args []string) []string {
	var flags, rest []string
	for _, a := range args {
		if strings.HasPrefix(a, "--") || (strings.HasPrefix(a, "-") && len(a) > 1) {
			flags = append(flags, a)
		} else {
			rest = append(rest, a)
		}
	}
	return append(flags, rest...)
}

func cmdConnect(ctx context.Context, args []string) error {
	a := openApp()
	id := ""
	if q := strings.TrimSpace(strings.Join(args, " ")); q != "" {
		st, err := a.State()
		if err != nil {
			return err
		}
		s, err := app.FindServer(st, q)
		if err != nil {
			return err
		}
		id = s.ID
	}
	sess, err := a.Connect(ctx, id)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Подключено: %s — %s\n", sess.ServerName, describeSession(sess))
	return nil
}

func describeSession(s *app.Session) string {
	var b strings.Builder
	b.WriteString(app.ModeLabel(s.Mode))
	if s.Mode == store.ModeTUN {
		fmt.Fprintf(&b, " (%s)", s.TunName)
	}
	if s.SocksPort > 0 {
		fmt.Fprintf(&b, ", SOCKS5 %s:%d", s.Listen, s.SocksPort)
	}
	if s.HTTPPort > 0 {
		fmt.Fprintf(&b, ", HTTP %s:%d", s.Listen, s.HTTPPort)
	}
	b.WriteString(", " + app.RoutingLabel(s.Routing))
	return b.String()
}

func cmdDisconnect() error {
	a := openApp()
	if err := a.Disconnect(); err != nil {
		return err
	}
	fmt.Println("✓ Отключено")
	return nil
}

func cmdStatus(args []string) error {
	quiet := len(args) > 0 && (args[0] == "-q" || args[0] == "--quiet")
	a := openApp()
	st := a.GetStatus()
	if quiet {
		if st.Connected {
			return nil
		}
		return exitErr{3}
	}
	switch {
	case st.Connected:
		s := st.Session
		fmt.Printf("● Подключено: %s [%s]\n  %s\n  Время: %s\n", s.ServerName, s.Protocol, describeSession(s),
			app.FormatDuration(time.Since(s.Started)))
		if s.MetricsPort > 0 {
			if tr, err := xray.QueryTraffic(context.Background(), s.MetricsPort); err == nil {
				fmt.Printf("  Трафик: ↑ %s ↓ %s\n", app.FormatBytes(tr.Up), app.FormatBytes(tr.Down))
			}
		}
		return nil
	case st.Crashed:
		fmt.Printf("✕ xray остановился: %s\n", st.Reason)
	default:
		fmt.Println("○ Не подключено")
	}
	return exitErr{3}
}

func cmdUpdate(ctx context.Context, args []string) error {
	onlyDue := len(args) > 0 && args[0] == "--due"
	a := openApp()
	updated, errs := a.UpdateAll(ctx, onlyDue)
	for _, u := range updated {
		fmt.Println("✓ обновлено:", u)
	}
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "✕", e)
	}
	if len(updated) == 0 && len(errs) == 0 {
		fmt.Println("нечего обновлять")
	}
	if len(errs) > 0 && len(updated) == 0 {
		return exitErr{1}
	}
	return nil
}

func cmdPing(ctx context.Context) error {
	a := openApp()
	rep, err := a.Ping(ctx, nil)
	if err != nil {
		return err
	}
	if rep.TCPOnly {
		fmt.Fprintln(os.Stderr, "xray не найден — показываю только TCP-пинг")
	}
	st, _ := a.State()
	byID := map[string]xray.PingResult{}
	for _, r := range rep.Results {
		byID[r.ID] = r
	}
	for i, s := range st.Servers {
		r, ok := byID[s.ID]
		if !ok {
			continue
		}
		res := app.PingLabel(r.Ms)
		if r.Err != nil {
			res = "✕ " + r.Err.Error()
		}
		fmt.Printf("%3d  %-40s %-14s %s\n", i+1, s.Name, s.ProtoLabel(), res)
	}
	return nil
}

func cmdList() error {
	a := openApp()
	st, err := a.State()
	if err != nil {
		return err
	}
	if len(st.Servers) == 0 {
		fmt.Println("Список пуст. Добавь подписку: harley add https://…")
		return nil
	}
	now := time.Now()
	current := ""
	if s := a.GetStatus(); s.Connected {
		current = s.Session.ServerID
	}
	printGroup := func(title, id string) {
		for i, s := range st.Servers {
			if s.SubID != id {
				continue
			}
			if title != "" {
				fmt.Println(title)
				title = ""
			}
			mark := " "
			if s.ID == current {
				mark = "●"
			}
			fmt.Printf("%s %3d  %-40s %-14s %s\n", mark, i+1, s.Name, s.ProtoLabel(), app.PingLabel(s.Ping))
		}
	}
	for _, sb := range st.Subscriptions {
		title := "▾ " + sb.Name
		if info, _ := app.FormatUserInfo(sb.Info, now); info != "" {
			title += "  (" + info + ")"
		}
		if sb.LastErr != "" {
			title += "  ⚠ " + sb.LastErr
		}
		printGroup(title, sb.ID)
	}
	printGroup("▾ Ключи", "manual")
	return nil
}

func cmdMode(args []string) error {
	a := openApp()
	s, err := a.Settings()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Println(app.ModeLabel(s.Mode))
		return nil
	}
	switch args[0] {
	case "tun":
		s.Mode = store.ModeTUN
	case "proxy":
		s.Mode = store.ModeProxy
	default:
		return fmt.Errorf("режим: proxy или tun")
	}
	if err := a.SaveSettings(s); err != nil {
		return err
	}
	fmt.Println("✓ Режим:", app.ModeLabel(s.Mode), "— применится при следующем подключении")
	return nil
}

func cmdRouting(args []string) error {
	a := openApp()
	s, err := a.Settings()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Println(app.RoutingLabel(s.Routing))
		return nil
	}
	switch args[0] {
	case "all":
		s.Routing = store.RouteAll
	case "ru", "ru-direct":
		s.Routing = store.RouteRUDirect
	case "custom":
		s.Routing = store.RouteCustom
	default:
		return fmt.Errorf("маршрутизация: all, ru или custom")
	}
	if err := a.SaveSettings(s); err != nil {
		return err
	}
	fmt.Println("✓ Маршрутизация:", app.RoutingLabel(s.Routing), "— применится при следующем подключении")
	return nil
}

func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	n := fs.Int("n", 50, "строк")
	_ = fs.Parse(args)
	a := openApp()
	for _, l := range xray.TailFile(a.Store.LogPath(), *n) {
		fmt.Println(l)
	}
	return nil
}
