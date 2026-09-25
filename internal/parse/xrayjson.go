package parse

import (
	"encoding/json"
	"strings"

	"github.com/nijiku49/tuixrayclient/internal/model"
)

// xray JSON-подписка: один конфиг {"outbounds":[...]} или массив конфигов
// (так отдаёт Remnawave/Marzban для клиентов на xray).

type xrayConfig struct {
	Remarks   string            `json:"remarks"`
	Outbounds []json.RawMessage `json:"outbounds"`
}

type xrayOutbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *struct {
		Network  string `json:"network"`
		Security string `json:"security"`
		Sockopt  *struct {
			DialerProxy string `json:"dialerProxy"`
		} `json:"sockopt"`
		TLSSettings *struct {
			ServerName string `json:"serverName"`
		} `json:"tlsSettings"`
		RealitySettings *struct {
			ServerName string `json:"serverName"`
			PublicKey  string `json:"publicKey"`
		} `json:"realitySettings"`
	} `json:"streamSettings"`
	ProxySettings *struct {
		Tag string `json:"tag"`
	} `json:"proxySettings"`
}

type xraySettings struct {
	// Старый формат с vnext/servers.
	Vnext []struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []struct {
			ID   string `json:"id"`
			Flow string `json:"flow"`
		} `json:"users"`
	} `json:"vnext"`
	Servers []struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Password string `json:"password"`
		Method   string `json:"method"`
	} `json:"servers"`
	// Новый плоский формат.
	Address  string `json:"address"`
	Port     int    `json:"port"`
	ID       string `json:"id"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Flow     string `json:"flow"`
}

var xrayProxyProtocols = map[string]string{
	"vless":       model.VLESS,
	"vmess":       model.VMess,
	"trojan":      model.Trojan,
	"shadowsocks": model.Shadowsocks,
	"hysteria":    model.Hysteria2,
	"hysteria2":   model.Hysteria2,
}

func looksLikeXrayJSON(b []byte) bool {
	s := string(b)
	return strings.Contains(s, `"outbounds"`) && strings.Contains(s, `"protocol"`)
}

func parseXrayJSON(b []byte) ([]*model.Server, []string, error) {
	var configs []xrayConfig
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(b, &configs); err != nil {
			return nil, nil, errf("xray JSON: %v", err)
		}
	} else {
		var c xrayConfig
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, nil, errf("xray JSON: %v", err)
		}
		configs = []xrayConfig{c}
	}
	var (
		out  []*model.Server
		errs []string
	)
	for _, c := range configs {
		servers, e := serversFromXrayConfig(c)
		out = append(out, servers...)
		errs = append(errs, e...)
	}
	return out, errs, nil
}

func serversFromXrayConfig(c xrayConfig) ([]*model.Server, []string) {
	byTag := map[string]json.RawMessage{}
	parsed := make([]xrayOutbound, len(c.Outbounds))
	for i, raw := range c.Outbounds {
		_ = json.Unmarshal(raw, &parsed[i])
		if parsed[i].Tag != "" {
			byTag[parsed[i].Tag] = raw
		}
	}
	// Outbound, на которые ссылаются другие (dialerProxy/proxySettings),
	// — это вспомогательные цепочки (fragment и т.п.), а не отдельные серверы.
	referenced := map[string]bool{}
	for _, ob := range parsed {
		if dep := depTag(ob); dep != "" {
			referenced[dep] = true
		}
	}
	var proxies []int
	for i, ob := range parsed {
		if _, ok := xrayProxyProtocols[strings.ToLower(ob.Protocol)]; ok && !referenced[ob.Tag] {
			proxies = append(proxies, i)
		}
	}
	var (
		out  []*model.Server
		errs []string
	)
	for _, i := range proxies {
		ob := parsed[i]
		s := &model.Server{Protocol: xrayProxyProtocols[strings.ToLower(ob.Protocol)]}
		var st xraySettings
		_ = json.Unmarshal(ob.Settings, &st)
		switch {
		case len(st.Vnext) > 0:
			s.Address, s.Port = st.Vnext[0].Address, st.Vnext[0].Port
			if len(st.Vnext[0].Users) > 0 {
				s.UUID, s.Flow = st.Vnext[0].Users[0].ID, st.Vnext[0].Users[0].Flow
			}
		case len(st.Servers) > 0:
			s.Address, s.Port = st.Servers[0].Address, st.Servers[0].Port
			s.Password, s.Method = st.Servers[0].Password, st.Servers[0].Method
		default:
			s.Address, s.Port = st.Address, st.Port
			s.UUID, s.Password, s.Method, s.Flow = st.ID, st.Password, st.Method, st.Flow
		}
		if ss := ob.StreamSettings; ss != nil {
			s.Network, _ = normNetwork(ss.Network)
			s.Security = strings.ToLower(ss.Security)
			if ss.TLSSettings != nil {
				s.SNI = ss.TLSSettings.ServerName
			}
			if ss.RealitySettings != nil {
				s.SNI = ss.RealitySettings.ServerName
				s.PublicKey = ss.RealitySettings.PublicKey
			}
		}
		if s.Address == "" || s.Port == 0 {
			errs = append(errs, "xray JSON: outbound "+ob.Tag+" без адреса — пропущен")
			continue
		}
		s.Name = c.Remarks
		if len(proxies) > 1 && ob.Tag != "" {
			if s.Name != "" {
				s.Name += " / " + ob.Tag
			} else {
				s.Name = ob.Tag
			}
		}
		s.Raw = c.Outbounds[i]
		// Цепочка зависимостей.
		var deps []json.RawMessage
		seen := map[string]bool{}
		for cur := ob; ; {
			dep := depTag(cur)
			if dep == "" || seen[dep] {
				break
			}
			seen[dep] = true
			raw, ok := byTag[dep]
			if !ok {
				break
			}
			deps = append(deps, raw)
			var next xrayOutbound
			_ = json.Unmarshal(raw, &next)
			cur = next
		}
		if len(deps) > 0 {
			s.RawDeps, _ = json.Marshal(deps)
		}
		if srv, err := finish(s); err == nil {
			out = append(out, srv)
		} else {
			errs = append(errs, err.Error())
		}
	}
	return out, errs
}

func depTag(ob xrayOutbound) string {
	if ob.StreamSettings != nil && ob.StreamSettings.Sockopt != nil && ob.StreamSettings.Sockopt.DialerProxy != "" {
		return ob.StreamSettings.Sockopt.DialerProxy
	}
	if ob.ProxySettings != nil {
		return ob.ProxySettings.Tag
	}
	return ""
}
