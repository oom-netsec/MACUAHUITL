package i18n

import (
	"strings"
	"time"
)

// Capas de hora para mostrar: siempre local y con zona (FmtLocal agrega la zona).
const (
	LocalMin = "2006-01-02 15:04"
	LocalSec = "2006-01-02 15:04:05"
	LocalMs  = "2006-01-02 15:04:05.000"
)

// FmtLocal da la hora en la zona local con su zona al final («2026-11-17 22:13 CST»). Hora cero: «-». Si la zona no
// trae una abreviación corta (Windows a veces da el nombre largo), usa el desfase («-06:00»). Solo para mostrar: lo
// que se guarda y el JSON no pasan por aquí.
func FmtLocal(t time.Time, layout string) string {
	if t.IsZero() || t.Unix() == 0 {
		return "-"
	}
	t = t.In(time.Local)
	if z, _ := t.Zone(); len(z) > 5 || strings.ContainsAny(z, " ()") {
		return t.Format(layout + " -07:00")
	}
	return t.Format(layout + " MST")
}
