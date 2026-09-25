package xray

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrNoXray — xray не установлен.
var ErrNoXray = errors.New("xray не найден: установи его командой `apk add xray` или укажи путь в xray_path (config.json)")

// FindBinary ищет xray: путь из настроек, затем PATH и стандартные места.
func FindBinary(configured string) (string, error) {
	if configured != "" {
		if isExec(configured) {
			return configured, nil
		}
		return "", fmt.Errorf("xray не найден по пути %s (xray_path в config.json); установи `apk add xray`", configured)
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/bin/xray", "/usr/local/bin/xray", "/usr/sbin/xray", "/usr/share/xray/xray", "/opt/xray/xray"} {
		if isExec(p) {
			return p, nil
		}
	}
	return "", ErrNoXray
}

func isExec(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// Version возвращает строку версии xray.
func Version(bin string) string {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line)
}

// FindAssetDir ищет каталог с geoip.dat и geosite.dat.
func FindAssetDir(configured, bin string) string {
	cands := []string{configured, os.Getenv("XRAY_LOCATION_ASSET")}
	if bin != "" {
		if real, err := filepath.EvalSymlinks(bin); err == nil {
			cands = append(cands, filepath.Dir(real))
		}
		cands = append(cands, filepath.Dir(bin))
	}
	cands = append(cands, "/usr/share/xray", "/usr/local/share/xray", "/usr/share/v2ray", "/usr/local/share/v2ray", "/opt/xray")
	for _, d := range cands {
		if d == "" {
			continue
		}
		if fileExists(filepath.Join(d, "geoip.dat")) && fileExists(filepath.Join(d, "geosite.dat")) {
			return d
		}
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Proc описывает фоновый процесс xray, переживающий выход harley:
// PID хранится в файле, вывод пишется в лог.
type Proc struct {
	Bin      string
	Config   string
	PidFile  string
	LogFile  string
	AssetDir string
}

func (p *Proc) env() []string {
	env := os.Environ()
	if p.AssetDir != "" {
		env = append(env, "XRAY_LOCATION_ASSET="+p.AssetDir)
	}
	return env
}

// Start запускает xray в отдельной сессии и убеждается, что он не упал
// сразу (ошибка конфига, занятый порт, нет прав на TUN).
func (p *Proc) Start(settle time.Duration) (int, error) {
	logf, err := os.OpenFile(p.LogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "=== harley: запуск xray %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	cmd := exec.Command(p.Bin, "run", "-c", p.Config)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = p.env()
	cmd.Dir = filepath.Dir(p.Config)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("не удалось запустить xray: %w", err)
	}
	pid := cmd.Process.Pid
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait() // забираем зомби, если harley ещё работает
		close(exited)
	}()
	if err := os.WriteFile(p.PidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		return 0, err
	}
	select {
	case <-exited:
		_ = os.Remove(p.PidFile)
		return 0, fmt.Errorf("xray завершился при запуске: %s", ExplainLog(TailFile(p.LogFile, 30)))
	case <-time.After(settle):
	}
	return pid, nil
}

// Running проверяет, жив ли xray из PID-файла.
func (p *Proc) Running() (int, bool) {
	return runningPid(p.PidFile)
}

func runningPid(pidFile string) (int, bool) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, pidAlive(pid)
}

func pidAlive(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// Поле состояния идёт после «(comm) ».
	if i := bytes.LastIndexByte(stat, ')'); i >= 0 && i+2 < len(stat) && stat[i+2] == 'Z' {
		return false
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	// PID мог достаться другому процессу — проверяем, что это «xray run -c …».
	return bytes.Contains(cmdline, []byte("\x00run\x00-c\x00"))
}

// Stop останавливает xray: SIGTERM, затем SIGKILL.
func (p *Proc) Stop() error {
	pid, ok := p.Running()
	defer os.Remove(p.PidFile)
	if !ok {
		return nil
	}
	proc, _ := os.FindProcess(pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("нет прав остановить xray (pid %d): он запущен от root — используй sudo", pid)
		}
		return nil
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = proc.Signal(syscall.SIGKILL)
	return nil
}

// TailFile — последние n строк файла.
func TailFile(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	const maxRead = 256 << 10
	if fi, err := f.Stat(); err == nil && fi.Size() > maxRead {
		_, _ = f.Seek(fi.Size()-maxRead, io.SeekStart)
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n*2 {
			lines = lines[len(lines)-n:]
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// ExplainLog превращает хвост лога xray в понятное сообщение.
func ExplainLog(lines []string) string {
	all := strings.Join(lines, "\n")
	low := strings.ToLower(all)
	switch {
	case strings.Contains(low, "address already in use"):
		return "порт уже занят другой программой — смени socks_port/http_port в настройках или останови другой VPN-клиент"
	case strings.Contains(low, "/dev/net/tun") || (strings.Contains(low, "tun") && strings.Contains(low, "no such file")):
		return "нет устройства /dev/net/tun — выполни `modprobe tun`"
	case strings.Contains(low, "operation not permitted") || strings.Contains(low, "permission denied"):
		return "нет прав: режим TUN требует root или CAP_NET_ADMIN — запусти через sudo/doas"
	case strings.Contains(low, "geoip.dat") || strings.Contains(low, "geosite.dat"):
		return "нет geoip.dat/geosite.dat для правил маршрутизации — положи их в /usr/share/xray или укажи asset_dir"
	case strings.Contains(low, "unknown config id: hysteria") || strings.Contains(low, "unknown transport protocol: hysteria"):
		return "эта версия xray не поддерживает Hysteria2 — обнови xray-core"
	case strings.Contains(low, "unknown config id: tun"):
		return "эта версия xray не поддерживает встроенный TUN — обнови xray-core или используй режим Proxy"
	case strings.Contains(low, "failed to load config") || strings.Contains(low, "failed to build"):
		if i := strings.LastIndex(all, " > "); i >= 0 {
			return "xray отверг конфиг: " + strings.TrimSpace(all[i+3:])
		}
	}
	// Последняя содержательная строка.
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" && !strings.HasPrefix(l, "===") {
			return l
		}
	}
	return "причина неизвестна, смотри вкладку логов"
}
