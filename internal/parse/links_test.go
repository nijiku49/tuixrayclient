package parse

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

func mustParse(t *testing.T, link string) *model.Server {
	t.Helper()
	s, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink(%q): %v", link, err)
	}
	return s
}

func TestVLESSReality(t *testing.T) {
	s := mustParse(t, "vless://2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d@203.0.113.10:443"+
		"?type=tcp&security=reality&pbk=Q1w2e3R4t5Y6u7I8o9P0aSdFgHjKlZxCvBnM1234567&sid=6ba85179e30d4fc2"+
		"&spx=%2Fsearch&fp=chrome&sni=www.microsoft.com&flow=xtls-rprx-vision&encryption=none#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam")
	want := model.Server{
		Protocol: "vless", Address: "203.0.113.10", Port: 443,
		UUID: "2d2d7c1e-7a8b-4f3a-9d1c-0e1f2a3b4c5d", Encryption: "none", Flow: "xtls-rprx-vision",
		Network: "tcp", Security: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome",
		PublicKey: "Q1w2e3R4t5Y6u7I8o9P0aSdFgHjKlZxCvBnM1234567", ShortID: "6ba85179e30d4fc2", SpiderX: "/search",
		Name: "🇳🇱 Amsterdam",
	}
	checkFields(t, s, &want)
	if s.ID == "" || s.Link == "" {
		t.Fatal("ID/Link не заполнены")
	}
}

func TestVLESSTransports(t *testing.T) {
	cases := []struct {
		link string
		want model.Server
	}{
		{
			"vless://u1@example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=firefox#ws",
			model.Server{Network: "ws", Security: "tls", Path: "/ws?ed=2048", Host: "cdn.example.com",
				SNI: "cdn.example.com", ALPN: []string{"h2", "http/1.1"}, Fingerprint: "firefox"},
		},
		{
			"vless://u1@example.com:443?type=grpc&security=tls&serviceName=grpcsvc&mode=multi&authority=a.example.com#grpc",
			model.Server{Network: "grpc", Security: "tls", ServiceName: "grpcsvc", GRPCMulti: true, Authority: "a.example.com"},
		},
		{
			"vless://u1@example.com:80?type=httpupgrade&security=none&path=%2Fup&host=h.example.com#hu",
			model.Server{Network: "httpupgrade", Security: "none", Path: "/up", Host: "h.example.com"},
		},
		{
			"vless://u1@example.com:443?type=xhttp&security=reality&pbk=KEY&sid=ab&path=%2Fx&mode=stream-one&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#xh",
			model.Server{Network: "xhttp", Security: "reality", PublicKey: "KEY", ShortID: "ab", Path: "/x",
				XHTTPMode: "stream-one", XHTTPExtra: []byte(`{"xPaddingBytes":"100-1000"}`)},
		},
		{
			"vless://u1@example.com:443?type=splithttp&security=tls&path=%2Fsh#sh",
			model.Server{Network: "xhttp", Security: "tls", Path: "/sh"},
		},
		{
			"vless://u1@[2001:db8::1]:8443?type=raw&security=none&headerType=http&host=bing.com#v6",
			model.Server{Network: "tcp", Security: "none", HeaderType: "http", Host: "bing.com", Address: "2001:db8::1", Port: 8443},
		},
	}
	for _, c := range cases {
		s := mustParse(t, c.link)
		checkFields(t, s, &c.want)
	}
}

func TestVLESSErrors(t *testing.T) {
	for _, link := range []string{
		"vless://@example.com:443",                       // нет UUID
		"vless://u@example.com",                          // нет порта
		"vless://u@example.com:99999",                    // плохой порт
		"vless://u@example.com:443?security=reality",     // нет pbk
		"vless://u@example.com:443?type=h2&security=tls", // удалённый транспорт
		"vless://u@example.com:443?type=unknown",         // неизвестный транспорт
		"wireguard://whatever",                           // чужая схема
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("ожидалась ошибка для %q", link)
		}
	}
}

func TestVMessJSON(t *testing.T) {
	js := `{"v":"2","ps":"Тест VMess","add":"vm.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/vm","tls":"tls","sni":"vm.example.com","alpn":"http/1.1","fp":"chrome"}`
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		s := mustParse(t, "vmess://"+enc.EncodeToString([]byte(js)))
		checkFields(t, s, &model.Server{
			Protocol: "vmess", Name: "Тест VMess", Address: "vm.example.com", Port: 443,
			UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Encryption: "auto",
			Network: "ws", Host: "vm.example.com", Path: "/vm", Security: "tls", SNI: "vm.example.com",
			ALPN: []string{"http/1.1"}, Fingerprint: "chrome",
		})
	}
	// Порт числом, grpc.
	js2 := `{"ps":"g","add":"1.2.3.4","port":8443,"id":"id2","aid":"0","net":"grpc","path":"svc","type":"multi","tls":""}`
	s := mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(js2)))
	checkFields(t, s, &model.Server{Port: 8443, Network: "grpc", ServiceName: "svc", GRPCMulti: true, Security: "none"})
}

func TestVMessURI(t *testing.T) {
	s := mustParse(t, "vmess://uuid-1@host.example:10086?type=tcp&security=none&encryption=aes-128-gcm#uri")
	checkFields(t, s, &model.Server{Protocol: "vmess", UUID: "uuid-1", Port: 10086, Encryption: "aes-128-gcm", Name: "uri"})
}

func TestTrojan(t *testing.T) {
	s := mustParse(t, "trojan://p%40ss%3Aword@tr.example.com:443?sni=tr.example.com&type=ws&path=%2Ftr&allowInsecure=1#Trojan%20WS")
	checkFields(t, s, &model.Server{
		Protocol: "trojan", Password: "p@ss:word", Address: "tr.example.com", Port: 443,
		Security: "tls", SNI: "tr.example.com", Network: "ws", Path: "/tr", AllowInsecure: true, Name: "Trojan WS",
	})
	s = mustParse(t, "trojan://pw@1.1.1.1:443?security=reality&pbk=K&sid=01&type=grpc&serviceName=g")
	checkFields(t, s, &model.Server{Security: "reality", PublicKey: "K", Network: "grpc", ServiceName: "g"})
}

func TestShadowsocks(t *testing.T) {
	sip002 := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:secret")) + "@ss.example.com:8388#SS%201"
	s := mustParse(t, sip002)
	checkFields(t, s, &model.Server{Protocol: "shadowsocks", Method: "chacha20-ietf-poly1305", Password: "secret",
		Address: "ss.example.com", Port: 8388, Name: "SS 1"})

	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss@10.0.0.1:443")) + "#legacy"
	s = mustParse(t, legacy)
	checkFields(t, s, &model.Server{Method: "aes-256-gcm", Password: "pa:ss", Address: "10.0.0.1", Port: 443})

	// SS-2022: метод и ключ открытым текстом (percent-encoded).
	s2022 := "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@[::1]:8443#2022"
	s = mustParse(t, s2022)
	checkFields(t, s, &model.Server{Method: "2022-blake3-aes-256-gcm", Password: "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=", Address: "::1"})

	// 2022 с multi-user ключом «серверный:пользовательский».
	s = mustParse(t, "ss://"+base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:AAAA:BBBB"))+"@h:1")
	checkFields(t, s, &model.Server{Password: "AAAA:BBBB"})

	for _, bad := range []string{
		"ss://" + base64.StdEncoding.EncodeToString([]byte("rc4-md5:x")) + "@h:1",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:x")) + "@h:1?plugin=obfs-local%3Bobfs%3Dhttp",
	} {
		if _, err := ParseLink(bad); err == nil {
			t.Errorf("ожидалась ошибка для %q", bad)
		}
	}
}

func TestHysteria2(t *testing.T) {
	s := mustParse(t, "hysteria2://letmein@hy.example.com:443/?sni=real.example.com&obfs=salamander&obfs-password=gawr&insecure=1&pinSHA256=AB%3ACD#Hy2")
	checkFields(t, s, &model.Server{
		Protocol: "hysteria2", Password: "letmein", Address: "hy.example.com", Port: 443,
		SNI: "real.example.com", Obfs: "salamander", ObfsPassword: "gawr", AllowInsecure: true,
		PinSHA256: "AB:CD", Network: "hysteria", Security: "tls", Name: "Hy2",
	})
	s = mustParse(t, "hy2://user:pass@1.2.3.4:20000-30000,443?sni=x&upmbps=50&downmbps=100")
	checkFields(t, s, &model.Server{Password: "user:pass", Port: 20000, HopPorts: "20000-30000,443", UpMbps: 50, DownMbps: 100})
	s = mustParse(t, "hy2://pw@host.example")
	checkFields(t, s, &model.Server{Port: 443})
	if _, err := ParseLink("hy2://pw@h:443?obfs=unknown"); err == nil {
		t.Error("ожидалась ошибка для неизвестного obfs")
	}
}

func TestStableID(t *testing.T) {
	a := mustParse(t, "vless://u@h:1?security=none#name-a")
	b := mustParse(t, "vless://u@h:1?security=none#name-b")
	c := mustParse(t, "vless://u@h:2?security=none#name-a")
	if a.ID != b.ID {
		t.Error("имя не должно влиять на ID")
	}
	if a.ID == c.ID {
		t.Error("разные порты — разные ID")
	}
}

// checkFields сравнивает только ненулевые поля want.
func checkFields(t *testing.T, got, want *model.Server) {
	t.Helper()
	gv, wv := reflect.ValueOf(got).Elem(), reflect.ValueOf(want).Elem()
	for i := 0; i < wv.NumField(); i++ {
		wf := wv.Field(i)
		if wf.IsZero() {
			continue
		}
		name := wv.Type().Field(i).Name
		gf := gv.Field(i)
		if wf.Kind() == reflect.Slice && wf.Type().Elem().Kind() == reflect.Uint8 {
			if strings.TrimSpace(string(gf.Bytes())) != strings.TrimSpace(string(wf.Bytes())) {
				t.Errorf("%s: получили %s, ждали %s", name, gf.Bytes(), wf.Bytes())
			}
			continue
		}
		if !reflect.DeepEqual(gf.Interface(), wf.Interface()) {
			t.Errorf("%s: получили %#v, ждали %#v", name, gf.Interface(), wf.Interface())
		}
	}
}
