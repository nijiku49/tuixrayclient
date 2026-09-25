package xray

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// В репозиториях Alpine xray-core нет, поэтому harley умеет ставить его сам:
// официальный релиз с GitHub (статический Go-бинарник, работает на musl),
// с проверкой SHA-256 из .dgst и geo-файлами в комплекте.

// DefaultReleases — откуда качать релизы xray-core.
const DefaultReleases = "https://github.com/XTLS/Xray-core/releases"

// ReleaseAsset — имя архива релиза для архитектуры.
func ReleaseAsset(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	case "386":
		return "Xray-linux-32.zip", nil
	case "arm":
		return "Xray-linux-arm32-v7a.zip", nil
	case "riscv64":
		return "Xray-linux-riscv64.zip", nil
	}
	return "", fmt.Errorf("нет готовой сборки xray для архитектуры %s — собери из исходников (make xray)", goarch)
}

// InstallLayout — куда класть xray и geo-файлы.
type InstallLayout struct {
	BinDir   string
	AssetDir string
}

// DefaultLayout: от root — как официальный установщик xray
// (/usr/local/bin/xray, /usr/local/share/xray/*.dat), иначе всё в
// ~/.local/share/harley/xray/.
func DefaultLayout() InstallLayout {
	if os.Geteuid() == 0 {
		return InstallLayout{BinDir: "/usr/local/bin", AssetDir: "/usr/local/share/xray"}
	}
	d := userXrayDir()
	return InstallLayout{BinDir: d, AssetDir: d}
}

func userXrayDir() string {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "harley", "xray")
}

// InstallOptions — параметры установки.
type InstallOptions struct {
	Version  string // "" или "latest" — последний релиз, иначе тег вида v26.3.27
	Releases string // база релизов (зеркало); пусто — GitHub
	Arch     string // пусто — runtime.GOARCH
	FromFile string // локальный zip вместо скачивания
	Layout   InstallLayout
	Client   *http.Client
	// NoVerify — не проверять SHA-256 (только для --from без .dgst).
	NoVerify bool
}

// InstallResult — что установлено.
type InstallResult struct {
	Bin      string
	AssetDir string
	Version  string
	SHA256   string
}

// Install скачивает (или берёт из файла) релиз xray-core, проверяет
// контрольную сумму и распаковывает.
func Install(ctx context.Context, o InstallOptions) (*InstallResult, error) {
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.Layout.BinDir == "" {
		o.Layout = DefaultLayout()
	}
	if o.Layout.BinDir == "" {
		return nil, errors.New("не удалось определить каталог для xray")
	}
	asset, err := ReleaseAsset(o.Arch)
	if err != nil {
		return nil, err
	}
	var archive []byte
	var wantSum string
	if o.FromFile != "" {
		archive, err = os.ReadFile(o.FromFile)
		if err != nil {
			return nil, err
		}
		if b, err := os.ReadFile(o.FromFile + ".dgst"); err == nil {
			wantSum = ParseDgst(string(b))
		}
		if wantSum == "" && !o.NoVerify {
			return nil, fmt.Errorf("рядом с %s нет %s.dgst — положи его или добавь --no-verify", o.FromFile, filepath.Base(o.FromFile))
		}
	} else {
		url := releaseURL(o.Releases, o.Version, asset)
		client := o.Client
		if client == nil {
			client = &http.Client{Timeout: 5 * time.Minute}
		}
		dgst, err := download(ctx, client, url+".dgst", 1<<16)
		if err != nil {
			return nil, err
		}
		if wantSum = ParseDgst(string(dgst)); wantSum == "" {
			return nil, fmt.Errorf("не удалось прочитать SHA-256 из %s.dgst", asset)
		}
		if archive, err = download(ctx, client, url, 200<<20); err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256(archive)
	got := hex.EncodeToString(sum[:])
	if wantSum != "" && !strings.EqualFold(got, wantSum) {
		return nil, fmt.Errorf("контрольная сумма %s не совпала (ожидалась %s, получена %s) — архив повреждён или подменён", asset, wantSum, got)
	}
	res, err := unpack(archive, o.Layout)
	if err != nil {
		return nil, err
	}
	res.SHA256 = got
	res.Version = Version(res.Bin)
	if res.Version == "" {
		return res, fmt.Errorf("xray установлен в %s, но не запускается — проверь архитектуру (%s)", res.Bin, o.Arch)
	}
	return res, nil
}

func releaseURL(base, version, asset string) string {
	if base == "" {
		base = DefaultReleases
	}
	base = strings.TrimRight(base, "/")
	if version == "" || version == "latest" {
		return base + "/latest/download/" + asset
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return base + "/download/" + version + "/" + asset
}

func download(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "harley")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать xray (%s): %v — нет доступа к GitHub? Скачай архив вручную и выполни `harley install-xray --from Xray-linux-64.zip`", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("не удалось скачать xray: %s ответил HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("загрузка xray оборвалась: %v", err)
	}
	return b, nil
}

var hex64 = regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)

// ParseDgst достаёт SHA-256 из файла .dgst релиза xray
// (строки вида «SHA2-256= <hex>»; также понимает вывод sha256sum).
func ParseDgst(text string) string {
	for _, line := range strings.Split(text, "\n") {
		l := strings.ToUpper(line)
		if strings.Contains(l, "256") || !strings.Contains(l, "=") {
			if m := hex64.FindString(line); m != "" {
				return strings.ToLower(m)
			}
		}
	}
	return ""
}

func unpack(archive []byte, lay InstallLayout) (*InstallResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("архив xray повреждён: %v", err)
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[filepath.Base(f.Name)] = f
	}
	if files["xray"] == nil {
		return nil, errors.New("в архиве нет бинарника xray")
	}
	for _, d := range []string{lay.BinDir, lay.AssetDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("не удалось создать %s: %v (для установки в систему нужен root)", d, err)
		}
	}
	res := &InstallResult{Bin: filepath.Join(lay.BinDir, "xray"), AssetDir: lay.AssetDir}
	targets := []struct {
		name, dir string
		mode      os.FileMode
	}{
		{"xray", lay.BinDir, 0o755},
		{"geoip.dat", lay.AssetDir, 0o644},
		{"geosite.dat", lay.AssetDir, 0o644},
	}
	for _, t := range targets {
		f := files[t.name]
		if f == nil {
			continue // geo-файлы необязательны
		}
		if err := extract(f, filepath.Join(t.dir, t.name), t.mode); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func extract(f *zip.File, dst string, mode os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".harley-"+filepath.Base(dst)+"-*")
	if err != nil {
		return fmt.Errorf("нет прав на запись в %s: %v", filepath.Dir(dst), err)
	}
	if _, err := io.Copy(tmp, io.LimitReader(rc, 512<<20)); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Chmod(mode)
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	// rename поверх работающего xray безопасен: старый процесс держит свой inode.
	return os.Rename(tmp.Name(), dst)
}
