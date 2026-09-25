package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Traffic — счётчики трафика через VPN (outbound proxy), в байтах.
type Traffic struct {
	Up, Down int64
}

// ParseMetrics разбирает /debug/vars из metrics xray.
func ParseMetrics(b []byte) (Traffic, error) {
	var v struct {
		Stats struct {
			Outbound map[string]map[string]int64 `json:"outbound"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return Traffic{}, err
	}
	p := v.Stats.Outbound[TagProxy]
	return Traffic{Up: p["uplink"], Down: p["downlink"]}, nil
}

// QueryTraffic опрашивает metrics xray на 127.0.0.1:port.
func QueryTraffic(ctx context.Context, port int) (Traffic, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/debug/vars", port), nil)
	resp, err := localClient.Do(req)
	if err != nil {
		return Traffic{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Traffic{}, err
	}
	return ParseMetrics(b)
}

// localClient ходит на 127.0.0.1 без системных прокси.
var localClient = &http.Client{Transport: &http.Transport{Proxy: nil}}
