package xray

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeXrayZip — архив как у релиза xray-core, но вместо бинарника —
// sh-скрипт, отвечающий на `xray version`.
func fakeXrayZip(t *testing.T, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string, mode os.FileMode) {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	add("LICENSE", "MPL", 0o644)
	add("README.md", "readme", 0o644)
	add("geoip.dat", "GEOIP", 0o644)
	add("geosite.dat", "GEOSITE", 0o644)
	add("xray", "#!/bin/sh\necho 'Xray "+version+" (Xray, Penetrates Everything.)'\n", 0o755)
	zw.Close()
	return buf.Bytes()
}

// dgst — файл контрольных сумм в формате релизов xray-core.
func dgst(b []byte) string {
	return fmt.Sprintf("MD5= %x\nSHA1= %x\nSHA2-256= %x\nSHA2-512= %x\n",
		md5.Sum(b), sha256.Sum224(b), sha256.Sum256(b), sha512.Sum512(b))
}

func TestParseDgst(t *testing.T) {
	b := []byte("hello")
	want := fmt.Sprintf("%x", sha256.Sum256(b))
	if got := ParseDgst(dgst(b)); got != want {
		t.Fatalf("%s != %s", got, want)
	}
	// Вывод sha256sum тоже понимаем.
	if got := ParseDgst(want + "  Xray-linux-64.zip\n"); got != want {
		t.Fatal("формат sha256sum")
	}
	if ParseDgst("MD5= abc\n") != "" {
		t.Fatal("нет SHA-256 — пусто")
	}
}

func TestReleaseAssetAndURL(t *testing.T) {
	for arch, want := range map[string]string{"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip", "arm": "Xray-linux-arm32-v7a.zip"} {
		if got, _ := ReleaseAsset(arch); got != want {
			t.Errorf("%s → %s", arch, got)
		}
	}
	if _, err := ReleaseAsset("mips64"); err == nil {
		t.Error("неизвестная архитектура")
	}
	if u := releaseURL("", "", "X.zip"); u != "https://github.com/XTLS/Xray-core/releases/latest/download/X.zip" {
		t.Error(u)
	}
	if u := releaseURL("https://mirror/xray/", "26.3.27", "X.zip"); u != "https://mirror/xray/download/v26.3.27/X.zip" {
		t.Error(u)
	}
}

type fakeReleases struct {
	srv      *httptest.Server
	archive  []byte
	badSum   bool
	requests []string
}

func newFakeReleases(t *testing.T) *fakeReleases {
	f := &fakeReleases{archive: fakeXrayZip(t, "26.9.9")}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		asset, _ := ReleaseAsset("amd64")
		switch r.URL.Path {
		case "/latest/download/" + asset, "/download/v26.9.9/" + asset:
			w.Write(f.archive)
		case "/latest/download/" + asset + ".dgst", "/download/v26.9.9/" + asset + ".dgst":
			if f.badSum {
				w.Write([]byte(dgst([]byte("other"))))
				return
			}
			w.Write([]byte(dgst(f.archive)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestInstallDownload(t *testing.T) {
	f := newFakeReleases(t)
	dir := t.TempDir()
	lay := InstallLayout{BinDir: filepath.Join(dir, "bin"), AssetDir: filepath.Join(dir, "share")}
	res, err := Install(context.Background(), InstallOptions{Releases: f.srv.URL, Arch: "amd64", Layout: lay})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Version, "26.9.9") || res.Bin != filepath.Join(lay.BinDir, "xray") {
		t.Fatalf("%+v", res)
	}
	if fi, _ := os.Stat(res.Bin); fi.Mode().Perm()&0o111 == 0 {
		t.Fatal("xray не исполняемый")
	}
	for _, n := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(filepath.Join(lay.AssetDir, n)); err != nil {
			t.Fatalf("нет %s", n)
		}
	}
	if got := FindAssetDir(lay.AssetDir, res.Bin); got != lay.AssetDir {
		t.Fatalf("geo-файлы не находятся: %q", got)
	}
	if _, err := os.Stat(filepath.Join(lay.BinDir, "LICENSE")); err == nil {
		t.Fatal("лишние файлы не распаковываем")
	}
	// Конкретная версия.
	if _, err := Install(context.Background(), InstallOptions{Releases: f.srv.URL, Version: "v26.9.9", Arch: "amd64", Layout: lay}); err != nil {
		t.Fatal(err)
	}
	// Несуществующая версия — понятная ошибка.
	if _, err := Install(context.Background(), InstallOptions{Releases: f.srv.URL, Version: "v1.0.0", Arch: "amd64", Layout: lay}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	// Подменённый архив — отказ, старый xray не трогаем.
	f.badSum = true
	f.archive = fakeXrayZip(t, "6.6.6")
	if _, err := Install(context.Background(), InstallOptions{Releases: f.srv.URL, Arch: "amd64", Layout: lay}); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("подмена: %v", err)
	}
	if v := Version(res.Bin); !strings.Contains(v, "26.9.9") {
		t.Fatalf("старый xray испорчен: %q", v)
	}
}

func TestInstallFromFile(t *testing.T) {
	dir := t.TempDir()
	lay := InstallLayout{BinDir: dir, AssetDir: dir}
	archive := fakeXrayZip(t, "26.1.1")
	zipPath := filepath.Join(dir, "Xray-linux-64.zip")
	os.WriteFile(zipPath, archive, 0o644)
	if _, err := Install(context.Background(), InstallOptions{FromFile: zipPath, Arch: "amd64", Layout: lay}); err == nil || !strings.Contains(err.Error(), ".dgst") {
		t.Fatalf("без .dgst нужна явная --no-verify: %v", err)
	}
	if _, err := Install(context.Background(), InstallOptions{FromFile: zipPath, Arch: "amd64", Layout: lay, NoVerify: true}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(zipPath+".dgst", []byte(dgst(archive)), 0o644)
	res, err := Install(context.Background(), InstallOptions{FromFile: zipPath, Arch: "amd64", Layout: lay})
	if err != nil || !strings.Contains(res.Version, "26.1.1") {
		t.Fatalf("%v %v", res, err)
	}
	os.WriteFile(zipPath, []byte("not a zip"), 0o644)
	os.WriteFile(zipPath+".dgst", []byte(dgst([]byte("not a zip"))), 0o644)
	if _, err := Install(context.Background(), InstallOptions{FromFile: zipPath, Arch: "amd64", Layout: lay}); err == nil || !strings.Contains(err.Error(), "повреждён") {
		t.Fatalf("битый архив: %v", err)
	}
}
