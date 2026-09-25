package parse

import (
	"encoding/json"
	"strings"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

// sing-box JSON: {"outbounds":[{"type":"vless","tag":"…","server":"…",…}]}.

type sbConfig struct {
	Outbounds []sbOutbound `json:"outbounds"`
}

type sbOutbound struct {
	Type        string    `json:"type"`
	Tag         string    `json:"tag"`
	Server      string    `json:"server"`
	ServerPort  int       `json:"server_port"`
	ServerPorts []string  `json:"server_ports"`
	UUID        string    `json:"uuid"`
	Flow        string    `json:"flow"`
	Security    string    `json:"security"`
	AlterID     int       `json:"alter_id"`
	Password    string    `json:"password"`
	Method      string    `json:"method"`
	Plugin      string    `json:"plugin"`
	UpMbps      int       `json:"up_mbps"`
	DownMbps    int       `json:"down_mbps"`
	TLS         *sbTLS    `json:"tls"`
	Transport   *sbTransp `json:"transport"`
	Obfs        *sbObfs   `json:"obfs"`
}

type sbTLS struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name"`
	Insecure   bool   `json:"insecure"`
	ALPN       sbList `json:"alpn"`
	UTLS       *struct {
		Enabled     bool   `json:"enabled"`
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
}

type sbTransp struct {
	Type        string            `json:"type"`
	Path        string            `json:"path"`
	Host        sbList            `json:"host"`
	Headers     map[string]sbList `json:"headers"`
	ServiceName string            `json:"service_name"`
}

type sbObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// sbList — строка или массив строк.
type sbList []string

func (l *sbList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = sbList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return nil
	}
	*l = many
	return nil
}

func (l sbList) First() string {
	if len(l) > 0 {
		return l[0]
	}
	return ""
}

func looksLikeSingBox(b []byte) bool {
	s := string(b)
	return strings.Contains(s, `"outbounds"`) && strings.Contains(s, `"type"`) &&
		(strings.Contains(s, `"server_port"`) || strings.Contains(s, `"server"`))
}

func parseSingBox(b []byte) ([]*model.Server, []string, error) {
	var c sbConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, nil, errf("sing-box JSON: %v", err)
	}
	var (
		out  []*model.Server
		errs []string
	)
	for _, ob := range c.Outbounds {
		var s *model.Server
		switch strings.ToLower(ob.Type) {
		case "vless":
			s = &model.Server{Protocol: model.VLESS, UUID: ob.UUID, Flow: ob.Flow, Encryption: "none"}
		case "vmess":
			s = &model.Server{Protocol: model.VMess, UUID: ob.UUID, AlterID: ob.AlterID, Encryption: ob.Security}
			if s.Encryption == "" {
				s.Encryption = "auto"
			}
		case "trojan":
			s = &model.Server{Protocol: model.Trojan, Password: ob.Password}
		case "shadowsocks":
			if ob.Plugin != "" {
				errs = append(errs, "sing-box: "+ob.Tag+": плагины ss не поддерживаются")
				continue
			}
			s = &model.Server{Protocol: model.Shadowsocks, Method: strings.ToLower(ob.Method), Password: ob.Password}
		case "hysteria2":
			s = &model.Server{Protocol: model.Hysteria2, Password: ob.Password, Network: "hysteria",
				UpMbps: ob.UpMbps, DownMbps: ob.DownMbps}
			if ob.Obfs != nil && ob.Obfs.Type != "" {
				s.Obfs, s.ObfsPassword = strings.ToLower(ob.Obfs.Type), ob.Obfs.Password
			}
			if len(ob.ServerPorts) > 0 {
				s.HopPorts = strings.ReplaceAll(strings.Join(ob.ServerPorts, ","), ":", "-")
			}
		default:
			continue // selector, urltest, direct, block, dns…
		}
		s.Name, s.Address, s.Port = ob.Tag, ob.Server, ob.ServerPort
		if s.Network == "" {
			s.Network = "tcp"
		}
		s.Security = "none"
		if t := ob.TLS; t != nil && (t.Enabled || s.Protocol == model.Hysteria2) {
			s.Security = "tls"
			s.SNI, s.AllowInsecure, s.ALPN = t.ServerName, t.Insecure, t.ALPN
			if t.UTLS != nil && t.UTLS.Enabled {
				s.Fingerprint = t.UTLS.Fingerprint
			}
			if t.Reality != nil && t.Reality.Enabled {
				s.Security = "reality"
				s.PublicKey, s.ShortID = t.Reality.PublicKey, t.Reality.ShortID
			}
		}
		if s.Protocol == model.Hysteria2 {
			s.Security = "tls"
		}
		if tr := ob.Transport; tr != nil {
			switch strings.ToLower(tr.Type) {
			case "ws":
				s.Network = "ws"
			case "grpc":
				s.Network = "grpc"
			case "httpupgrade":
				s.Network = "httpupgrade"
			case "http":
				// В sing-box "http" без TLS — это HTTP-обфускация поверх TCP,
				// с TLS — h2, которого больше нет в xray.
				if s.Security == "none" {
					s.Network, s.HeaderType = "tcp", "http"
				} else {
					errs = append(errs, "sing-box: "+ob.Tag+": транспорт h2 удалён из xray-core")
					continue
				}
			default:
				errs = append(errs, "sing-box: "+ob.Tag+": транспорт "+tr.Type+" не поддерживается")
				continue
			}
			s.Path, s.ServiceName = tr.Path, tr.ServiceName
			s.Host = tr.Host.First()
			if h, ok := tr.Headers["Host"]; ok && s.Host == "" {
				s.Host = h.First()
			}
		}
		if srv, err := finish(s); err == nil {
			out = append(out, srv)
		} else {
			errs = append(errs, "sing-box: "+ob.Tag+": "+err.Error())
		}
	}
	return out, errs, nil
}
