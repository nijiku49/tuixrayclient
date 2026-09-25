package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

func TestDefaultDir(t *testing.T) {
	t.Setenv("HARLEY_HOME", "/custom/place")
	if DefaultDir() != "/custom/place" {
		t.Fatal("HARLEY_HOME")
	}
	t.Setenv("HARLEY_HOME", "")
	want := "/etc/harley"
	if os.Geteuid() != 0 {
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		want = "/xdg/harley"
	}
	if got := DefaultDir(); got != want {
		t.Fatalf("%s, ждали %s", got, want)
	}
}

func TestSettingsLifecycle(t *testing.T) {
	s, err := OpenAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if st.HWID == "" || !st.AutoConnect || st.Mode != ModeProxy || st.SocksPort != 10808 {
		t.Fatalf("умолчания: %+v", st)
	}
	if _, err := os.Stat(s.SettingsPath()); err != nil {
		t.Fatal("config.json должен создаваться при первом запуске")
	}
	// Частичный и некорректный конфиг дополняется умолчаниями.
	os.WriteFile(s.SettingsPath(), []byte(`{"mode":"weird","socks_port":99999,"autoconnect":false,"routing":"ru-direct"}`), 0o600)
	st, err = s.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode != ModeProxy || st.SocksPort != 10808 || st.AutoConnect || st.Routing != RouteRUDirect || st.HWID == "" {
		t.Fatalf("нормализация: %+v", st)
	}
	os.WriteFile(s.SettingsPath(), []byte(`{broken`), 0o600)
	if _, err := s.LoadSettings(); err == nil {
		t.Fatal("битый JSON — понятная ошибка")
	}
}

func TestStateUpdateConcurrent(t *testing.T) {
	s, _ := OpenAt(t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.Update(func(st *State) error {
				st.Servers = append(st.Servers, &model.Server{ID: string(rune('a' + i))})
				return nil
			})
		}(i)
	}
	wg.Wait()
	st, _ := s.LoadState()
	if len(st.Servers) != 20 {
		t.Fatalf("блокировка не сработала: %d серверов", len(st.Servers))
	}
	if fi, _ := os.Stat(filepath.Join(s.Dir, "state.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("права state.json: %v", fi.Mode().Perm())
	}
}
