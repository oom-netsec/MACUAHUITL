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

// DisplayZone es la zona con que se muestran las horas; nil = la local del sistema. Solo la fijan las pruebas, para
// no tocar time.Local (que afecta a todo el proceso).
var DisplayZone *time.Location

// FmtLocal da la hora en la zona local con su zona al final («2026-11-17 22:13 CST»). Hora cero: «-». Si la zona no
// trae una abreviación corta y clara (las ambiguas o numéricas, o un nombre largo, se prestan a confusión), usa el desfase («-06:00»). Solo para mostrar: lo
// que se guarda y el JSON no pasan por aquí.
func FmtLocal(t time.Time, layout string) string {
	if t.IsZero() || t.Unix() == 0 {
		return "-"
	}
	loc := time.Local
	if DisplayZone != nil {
		loc = DisplayZone
	}
	t = t.In(loc)
	if z, _ := t.Zone(); len(z) > 5 || strings.ContainsAny(z, " ()") {
		return t.Format(layout + " -07:00")
	}
	return t.Format(layout + " MST")
}
