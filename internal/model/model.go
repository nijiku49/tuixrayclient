// Package model описывает серверы и подписки harley независимо от формата,
// из которого они были импортированы.
package model

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Протоколы.
const (
	VLESS       = "vless"
	VMess       = "vmess"
	Trojan      = "trojan"
	Shadowsocks = "shadowsocks"
	Hysteria2   = "hysteria2"
)

// Server — один сервер (outbound xray).
type Server struct {
	ID       string `json:"id"`
	SubID    string `json:"sub_id,omitempty"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`

	// Учётные данные.
	UUID       string `json:"uuid,omitempty"`       // vless, vmess
	Password   string `json:"password,omitempty"`   // trojan, ss, hy2
	Method     string `json:"method,omitempty"`     // ss
	Encryption string `json:"encryption,omitempty"` // vless ("none") / vmess cipher ("auto")
	AlterID    int    `json:"alter_id,omitempty"`   // vmess
	Flow       string `json:"flow,omitempty"`       // vless xtls-rprx-vision

	// Транспорт: tcp (raw), ws, grpc, httpupgrade, xhttp, kcp, h2.
	Network     string          `json:"network,omitempty"`
	HeaderType  string          `json:"header_type,omitempty"` // tcp: http
	Host        string          `json:"host,omitempty"`
	Path        string          `json:"path,omitempty"`
	ServiceName string          `json:"service_name,omitempty"` // grpc
	Authority   string          `json:"authority,omitempty"`    // grpc
	GRPCMulti   bool            `json:"grpc_multi,omitempty"`
	XHTTPMode   string          `json:"xhttp_mode,omitempty"`
	XHTTPExtra  json.RawMessage `json:"xhttp_extra,omitempty"`

	// Безопасность: none, tls, reality.
	Security      string   `json:"security,omitempty"`
	SNI           string   `json:"sni,omitempty"`
	Fingerprint   string   `json:"fp,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	AllowInsecure bool     `json:"insecure,omitempty"`
	PinSHA256     string   `json:"pin_sha256,omitempty"`
	VerifyName    string   `json:"vcn,omitempty"` // verifyPeerCertByName
	PublicKey     string   `json:"pbk,omitempty"`
	ShortID       string   `json:"sid,omitempty"`
	SpiderX       string   `json:"spx,omitempty"`

	// Hysteria2.
	Obfs         string `json:"obfs,omitempty"` // salamander
	ObfsPassword string `json:"obfs_password,omitempty"`
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	HopPorts     string `json:"hop_ports,omitempty"` // "20000-30000,443"

	// Raw — готовый outbound из xray-JSON подписки; используется как есть.
	Raw json.RawMessage `json:"raw,omitempty"`
	// RawDeps — JSON-массив вспомогательных outbound (dialerProxy-цепочки),
	// на которые ссылается Raw.
	RawDeps json.RawMessage `json:"raw_deps,omitempty"`
	// Link — исходная ссылка (если сервер пришёл ключом).
	Link string `json:"link,omitempty"`

	// Результат последнего пинга: >0 мс, 0 — не измерялся, <0 — ошибка.
	Ping     int       `json:"ping,omitempty"`
	PingedAt time.Time `json:"pinged_at,omitempty"`
	PingErr  string    `json:"ping_err,omitempty"` // причина последней неудачи
}

// ProtoLabel — короткое имя протокола для списка.
func (s *Server) ProtoLabel() string {
	switch s.Protocol {
	case VLESS:
		lbl := "VLESS"
		if s.Security == "reality" {
			lbl += "·Reality"
		}
		return lbl
	case VMess:
		return "VMess"
	case Trojan:
		return "Trojan"
	case Shadowsocks:
		return "SS"
	case Hysteria2:
		return "Hy2"
	}
	return s.Protocol
}

// Endpoint — host:port.
func (s *Server) Endpoint() string {
	return net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
}

// Fingerprint сервера для дедупликации и стабильного ID: одинаковые
// параметры подключения дают одинаковый ID независимо от имени.
func (s *Server) ComputeID() string {
	h := sha1.New()
	if len(s.Raw) > 0 {
		h.Write(s.Raw)
	} else {
		fmt.Fprintf(h, "%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
			s.Protocol, strings.ToLower(s.Address), s.Port, s.UUID, s.Password, s.Method,
			s.Network, s.Security, s.SNI, s.Path, s.Host, s.ServiceName, s.PublicKey)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Validate проверяет, что у сервера есть минимально нужные поля.
func (s *Server) Validate() error {
	if len(s.Raw) > 0 {
		return nil
	}
	if s.Address == "" {
		return fmt.Errorf("нет адреса сервера")
	}
	if s.Port <= 0 || s.Port > 65535 {
		return fmt.Errorf("неверный порт %d", s.Port)
	}
	switch s.Protocol {
	case VLESS, VMess:
		if s.UUID == "" {
			return fmt.Errorf("нет UUID")
		}
	case Trojan, Hysteria2:
		if s.Password == "" {
			return fmt.Errorf("нет пароля")
		}
	case Shadowsocks:
		if s.Method == "" || s.Password == "" {
			return fmt.Errorf("нет метода шифрования или пароля")
		}
	default:
		return fmt.Errorf("неподдерживаемый протокол %q", s.Protocol)
	}
	if s.Security == "reality" && s.PublicKey == "" {
		return fmt.Errorf("Reality без публичного ключа (pbk)")
	}
	return nil
}

// Subscription — подписка по URL.
type Subscription struct {
	ID       string    `json:"id"`
	URL      string    `json:"url"`
	Name     string    `json:"name"`
	Updated  time.Time `json:"updated,omitempty"`
	LastErr  string    `json:"last_error,omitempty"`
	Info     UserInfo  `json:"info,omitempty"`
	Interval int       `json:"interval_hours,omitempty"` // из profile-update-interval
	Support  string    `json:"support_url,omitempty"`
	WebPage  string    `json:"web_page,omitempty"`
	Announce string    `json:"announce,omitempty"`
}

// UserInfo — subscription-userinfo.
type UserInfo struct {
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	Expire   int64 `json:"expire,omitempty"` // unix
}

// Used — израсходованный трафик.
func (u UserInfo) Used() int64 { return u.Upload + u.Download }

// Empty — заголовок не пришёл.
func (u UserInfo) Empty() bool { return u == UserInfo{} }

// SubIDFromURL — стабильный ID подписки.
func SubIDFromURL(u string) string {
	h := sha1.Sum([]byte(strings.TrimSpace(u)))
	return "s" + hex.EncodeToString(h[:])[:10]
}

// ManualSubID — псевдо-подписка для ключей, добавленных вручную.
const ManualSubID = "manual"
