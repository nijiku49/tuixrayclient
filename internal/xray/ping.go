package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

// PingResult — результат замера для одного сервера.
type PingResult struct {
	ID  string
	Ms  int // >0 — задержка
	Err error
}

// PingOptions — параметры URL-теста.
type PingOptions struct {
	Bin       string
	URL       string
	Timeout   time.Duration
	WorkDir   string // куда положить временный конфиг
	AssetDir  string
	BindIface string // если активен TUN
	Parallel  int
}

// URLTest измеряет реальную задержку: поднимает отдельный xray, у которого
// на каждый сервер свой SOCKS-вход, и делает через каждый HTTP-запрос к URL.
func URLTest(ctx context.Context, servers []*model.Server, o PingOptions) []PingResult {
	res := make([]PingResult, len(servers))
	for i, s := range servers {
		res[i].ID = s.ID
	}
	if len(servers) == 0 {
		return res
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Parallel <= 0 {
		o.Parallel = 16
	}
	fail := func(err error) []PingResult {
		for i := range res {
			if res[i].Err == nil && res[i].Ms == 0 {
				res[i].Err = err
			}
		}
		return res
	}
	ports, err := FreePorts(len(servers))
	if err != nil {
		return fail(err)
	}
	cfg, errs := BuildPing(servers, ports, o.BindIface)
	for i, e := range errs {
		if e != nil {
			res[i].Err = e
		}
	}
	if cfg == nil {
		return res
	}
	f, err := os.CreateTemp(o.WorkDir, "ping-*.json")
	if err != nil {
		return fail(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(cfg); err != nil {
		f.Close()
		return fail(err)
	}
	f.Close()

	xctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(xctx, o.Bin, "run", "-c", f.Name())
	cmd.Env = os.Environ()
	if o.AssetDir != "" {
		cmd.Env = append(cmd.Env, "XRAY_LOCATION_ASSET="+o.AssetDir)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("не удалось запустить xray: %w", err))
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() {
		cancel()
		<-exited
	}()

	// Ждём, пока xray начнёт слушать.
	var firstPort int
	for i, e := range errs {
		if e == nil {
			firstPort = ports[i]
			break
		}
	}
	if err := waitListen(firstPort, 5*time.Second, exited); err != nil {
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		return fail(fmt.Errorf("xray для пинга не запустился: %s", ExplainLog(lines)))
	}

	sem := make(chan struct{}, o.Parallel)
	var wg sync.WaitGroup
	for i := range servers {
		if res[i].Err != nil {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := probe(ctx, ports[i], o.URL, o.Timeout)
			res[i].Ms, res[i].Err = ms, err
		}(i)
	}
	wg.Wait()
	return res
}

func waitListen(port int, d time.Duration, exited <-chan struct{}) error {
	deadline := time.Now().Add(d)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return errors.New("xray завершился")
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("таймаут запуска")
}

// probe делает запрос через SOCKS5 на 127.0.0.1:port и меряет время.
func probe(ctx context.Context, port int, target string, timeout time.Duration) (int, error) {
	proxyURL, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(port))
	tr := &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, explainProbe(err)
	}
	resp.Body.Close()
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

func explainProbe(err error) error {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "Timeout") || strings.Contains(msg, "timeout"):
		return errors.New("таймаут")
	case strings.Contains(msg, "EOF") || strings.Contains(msg, "reset"):
		return errors.New("сервер недоступен")
	case strings.Contains(msg, "certificate"):
		return errors.New("ошибка TLS")
	}
	return errors.New("сервер недоступен")
}

// TCPPing — запасной вариант без xray: время установления TCP-соединения.
func TCPPing(ctx context.Context, servers []*model.Server, timeout time.Duration) []PingResult {
	res := make([]PingResult, len(servers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i, s := range servers {
		res[i].ID = s.ID
		wg.Add(1)
		go func(i int, s *model.Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if s.Protocol == model.Hysteria2 {
				res[i].Err = errors.New("UDP — только URL-тест")
				return
			}
			d := net.Dialer{Timeout: timeout}
			start := time.Now()
			c, err := d.DialContext(ctx, "tcp", s.Endpoint())
			if err != nil {
				res[i].Err = errors.New("сервер недоступен")
				return
			}
			c.Close()
			res[i].Ms = max(1, int(time.Since(start).Milliseconds()))
		}(i, s)
	}
	wg.Wait()
	return res
}
