package parse

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

const (
	keyVLESS  = "vless://u1@a.example.com:443?type=tcp&security=reality&pbk=K&sid=01&sni=www.google.com&fp=chrome&flow=xtls-rprx-vision#A"
	keyTrojan = "trojan://pw@b.example.com:443?sni=b.example.com#B"
	keyHy2    = "hy2://pw@c.example.com:443?sni=c.example.com#C"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func names(ss []*model.Server) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.Name)
	}
	return out
}

func TestParseBodyPlain(t *testing.T) {
	body := "#profile-title: base64:0JzQvtGPINC/0L7QtNC/0LjRgdC60LA=\n" +
		"#profile-update-interval: 6\n" +
		keyVLESS + "\n\n" + keyTrojan + "\r\n" + "garbage-line\n" + "vless://broken\n" + keyHy2 + "\n"
	r := ParseBody([]byte(body))
	if r.Format != FormatPlain {
		t.Fatalf("формат %q", r.Format)
	}
	if got := names(r.Servers); strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("серверы %v", got)
	}
	if len(r.Errors) != 1 {
		t.Fatalf("ожидалась 1 ошибка (сломанный vless), получили %v", r.Errors)
	}
	if r.Meta["profile-title"] == "" || r.Meta["profile-update-interval"] != "6" {
		t.Fatalf("метаданные из тела не прочитаны: %v", r.Meta)
	}
}

func TestParseBodyBase64(t *testing.T) {
	plain := keyVLESS + "\n" + keyTrojan + "\n" + keyHy2
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		b := enc.EncodeToString([]byte(plain))
		// Некоторые панели режут base64 на строки по 76 символов.
		var wrapped strings.Builder
		for i := 0; i < len(b); i += 76 {
			end := min(i+76, len(b))
			wrapped.WriteString(b[i:end] + "\n")
		}
		r := ParseBody([]byte(wrapped.String()))
		if r.Format != FormatBase64 || len(r.Servers) != 3 {
			t.Fatalf("base64: формат %q, серверов %d, ошибки %v", r.Format, len(r.Servers), r.Errors)
		}
	}
}

func TestParseBodyXrayArray(t *testing.T) {
	r := ParseBody(readTestdata(t, "xray_array.json"))
	if r.Format != FormatXray {
		t.Fatalf("формат %q", r.Format)
	}
	if len(r.Servers) != 3 {
		t.Fatalf("серверов %d (%v), ошибки %v", len(r.Servers), names(r.Servers), r.Errors)
	}
	de := r.Servers[0]
	checkFields(t, de, &model.Server{Name: "🇩🇪 Германия", Protocol: "vless", Address: "de.example.com", Port: 443,
		Security: "reality", PublicKey: "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", SNI: "www.google.com", Flow: "xtls-rprx-vision"})
	if len(de.Raw) == 0 {
		t.Fatal("Raw outbound не сохранён")
	}
	var deps []map[string]any
	if err := json.Unmarshal(de.RawDeps, &deps); err != nil || len(deps) != 1 || deps[0]["tag"] != "fragment" {
		t.Fatalf("цепочка dialerProxy не сохранена: %s", de.RawDeps)
	}
	checkFields(t, r.Servers[1], &model.Server{Protocol: "trojan", Address: "fi.example.com", Port: 8443, Network: "ws"})
	checkFields(t, r.Servers[2], &model.Server{Protocol: "hysteria2", Address: "hy.example.com", Port: 443})
	if r.Servers[0].ID == r.Servers[1].ID {
		t.Fatal("одинаковые ID у разных серверов")
	}
}

func TestParseBodyXraySingle(t *testing.T) {
	body := `{"remarks":"One","outbounds":[
	  {"tag":"a","protocol":"vless","settings":{"address":"x.example.com","port":443,"id":"uid"}},
	  {"tag":"b","protocol":"shadowsocks","settings":{"servers":[{"address":"y.example.com","port":1,"method":"aes-128-gcm","password":"p"}]}},
	  {"tag":"direct","protocol":"freedom"}]}`
	r := ParseBody([]byte(body))
	if len(r.Servers) != 2 || r.Servers[0].Name != "One / a" || r.Servers[1].Address != "y.example.com" {
		t.Fatalf("получили %v %v", names(r.Servers), r.Errors)
	}
}

func TestParseBodySingBox(t *testing.T) {
	r := ParseBody(readTestdata(t, "singbox.json"))
	if r.Format != FormatSingBox {
		t.Fatalf("формат %q", r.Format)
	}
	if got := strings.Join(names(r.Servers), ","); got != "NL Reality,US WS,Trojan gRPC,SS2022,Hy2 SB" {
		t.Fatalf("серверы %s, ошибки %v", got, r.Errors)
	}
	checkFields(t, r.Servers[0], &model.Server{Protocol: "vless", Security: "reality", PublicKey: "PBK_NL", ShortID: "0123",
		SNI: "www.apple.com", Fingerprint: "chrome", Flow: "xtls-rprx-vision", Network: "tcp"})
	checkFields(t, r.Servers[1], &model.Server{Protocol: "vmess", Network: "ws", Path: "/vm", Host: "us.example.com",
		Security: "tls", ALPN: []string{"http/1.1"}})
	checkFields(t, r.Servers[2], &model.Server{Network: "grpc", ServiceName: "tgrpc", Security: "tls"})
	checkFields(t, r.Servers[3], &model.Server{Protocol: "shadowsocks", Method: "2022-blake3-aes-128-gcm"})
	checkFields(t, r.Servers[4], &model.Server{Protocol: "hysteria2", Obfs: "salamander", ObfsPassword: "obfspw",
		HopPorts: "20000-30000", UpMbps: 20, DownMbps: 100, AllowInsecure: true})
}

func TestParseBodyClash(t *testing.T) {
	r := ParseBody(readTestdata(t, "clash.yaml"))
	if r.Format != FormatClash {
		t.Fatalf("формат %q", r.Format)
	}
	if got := strings.Join(names(r.Servers), ","); got != "🇳🇱 Clash Reality,VMess WS,Trojan,SS,Hy2,VLESS gRPC" {
		t.Fatalf("серверы %s, ошибки %v", got, r.Errors)
	}
	checkFields(t, r.Servers[0], &model.Server{Security: "reality", PublicKey: "PBK_CLASH", ShortID: "0a1b", SNI: "www.apple.com",
		Fingerprint: "chrome", Flow: "xtls-rprx-vision"})
	checkFields(t, r.Servers[1], &model.Server{Network: "ws", Path: "/vmws", Host: "vm.example.com", Security: "tls"})
	checkFields(t, r.Servers[2], &model.Server{Security: "tls", AllowInsecure: true, SNI: "tr.example.com"})
	checkFields(t, r.Servers[3], &model.Server{Method: "aes-256-gcm", Password: "sspass", Security: "none"})
	checkFields(t, r.Servers[4], &model.Server{Protocol: "hysteria2", Obfs: "salamander", ObfsPassword: "ob"})
	checkFields(t, r.Servers[5], &model.Server{Network: "grpc", ServiceName: "gsvc"})
}

func TestParseBodyGarbage(t *testing.T) {
	for _, body := range []string{"", "   ", "<html>Forbidden</html>", `{"hello":"world"}`} {
		r := ParseBody([]byte(body))
		if len(r.Servers) != 0 || len(r.Errors) == 0 {
			t.Errorf("%q: ожидалась ошибка без серверов, получили %v / %v", body, names(r.Servers), r.Errors)
		}
	}
}

func TestDetectInput(t *testing.T) {
	// Ссылка на подписку.
	in := DetectInput("  https://panel.example.com/sub/abcdef?format=raw \n")
	if len(in.SubURLs) != 1 || in.SubURLs[0] != "https://panel.example.com/sub/abcdef?format=raw" || len(in.Servers) != 0 {
		t.Fatalf("подписка: %+v", in)
	}
	// Один ключ.
	in = DetectInput(keyVLESS)
	if len(in.SubURLs) != 0 || len(in.Servers) != 1 {
		t.Fatalf("один ключ: %+v", in)
	}
	// Много ключей построчно.
	in = DetectInput(keyVLESS + "\n" + keyTrojan + "\n" + keyHy2)
	if len(in.Servers) != 3 {
		t.Fatalf("много ключей: %v", names(in.Servers))
	}
	// Терминал склеил строки через пробел; имя с пробелом не режется.
	in = DetectInput(keyVLESS + " " + keyTrojan + " " + "vless://u@h:1?security=none#My Server")
	if got := strings.Join(names(in.Servers), "|"); got != "A|B|My Server" {
		t.Fatalf("склеенные ключи: %q", got)
	}
	// CR вместо LF (так приходит bracketed paste).
	in = DetectInput(keyVLESS + "\r" + keyTrojan)
	if len(in.Servers) != 2 {
		t.Fatalf("CR-разделитель: %v", names(in.Servers))
	}
	// base64-блоб.
	in = DetectInput(base64.StdEncoding.EncodeToString([]byte(keyVLESS + "\n" + keyTrojan)))
	if len(in.Servers) != 2 || in.Format != FormatBase64 {
		t.Fatalf("base64: %+v", in)
	}
	// Смесь подписки и ключа.
	in = DetectInput("https://a.example.com/s\n" + keyHy2)
	if len(in.SubURLs) != 1 || len(in.Servers) != 1 {
		t.Fatalf("смесь: %+v", in)
	}
	// Целиком JSON и YAML.
	if in = DetectInput(string(readTestdata(t, "singbox.json"))); len(in.Servers) != 5 {
		t.Fatalf("sing-box вставкой: %d", len(in.Servers))
	}
	if in = DetectInput(string(readTestdata(t, "clash.yaml"))); len(in.Servers) != 6 {
		t.Fatalf("clash вставкой: %d", len(in.Servers))
	}
	// Мусор.
	if in = DetectInput("привет"); len(in.Errors) == 0 {
		t.Fatal("мусор должен давать ошибку")
	}
	if in = DetectInput(""); len(in.Errors) != 0 || len(in.Servers) != 0 {
		t.Fatal("пустой ввод — ничего не делаем")
	}
}
