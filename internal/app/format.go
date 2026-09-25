package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/nijiku49/tuixrayclient/internal/model"
	"github.com/nijiku49/tuixrayclient/internal/store"
)

// FormatBytes — «1.5 ГБ».
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ", "ПБ"}
	v := float64(n) / unit
	i := 0
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// FormatSpeed — «1.5 МБ/с».
func FormatSpeed(bps float64) string {
	if bps < 0 {
		bps = 0
	}
	return FormatBytes(int64(bps)) + "/с"
}

// FormatDuration — «01:02:03» или «2д 03:04:05».
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dд %02d:%02d:%02d", days, h, m, s)
	}
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// FormatAgo — «5 мин назад».
func FormatAgo(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "никогда"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "только что"
	case d < time.Hour:
		return fmt.Sprintf("%d мин назад", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d ч назад", int(d.Hours()))
	}
	return fmt.Sprintf("%d дн назад", int(d.Hours()/24))
}

// FormatUserInfo — «12.3 ГБ / 100 ГБ · до 01.02.2027» для подписки.
// expired — срок подписки истёк.
func FormatUserInfo(ui model.UserInfo, now time.Time) (text string, expired bool) {
	if ui.Empty() {
		return "", false
	}
	var parts []string
	if ui.Total > 0 {
		parts = append(parts, FormatBytes(ui.Used())+" / "+FormatBytes(ui.Total))
	} else if ui.Used() > 0 {
		parts = append(parts, FormatBytes(ui.Used())+" / ∞")
	}
	if ui.Expire > 0 {
		exp := time.Unix(ui.Expire, 0)
		if exp.Before(now) {
			parts = append(parts, "истекла "+exp.Format("02.01.2006"))
			expired = true
		} else {
			left := exp.Sub(now)
			s := "до " + exp.Format("02.01.2006")
			if left < 7*24*time.Hour {
				s += fmt.Sprintf(" (осталось %d дн)", int(left.Hours()/24))
			}
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " · "), expired
}

// ModeLabel — «TUN» / «Proxy».
func ModeLabel(mode string) string {
	if mode == store.ModeTUN {
		return "TUN"
	}
	return "Proxy"
}

// RoutingLabel — название пресета.
func RoutingLabel(r string) string {
	switch r {
	case store.RouteRUDirect:
		return "RU напрямую"
	case store.RouteCustom:
		return "свои правила"
	}
	return "всё через VPN"
}

// PingLabel — «45 мс», «✕», «—».
func PingLabel(ms int) string {
	switch {
	case ms > 0:
		return fmt.Sprintf("%d мс", ms)
	case ms < 0:
		return "✕"
	}
	return "—"
}
