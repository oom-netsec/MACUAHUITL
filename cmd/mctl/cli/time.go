package cli

import (
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Time muestra milisegundos Unix en hora local con zona; 0 no es fecha y sale «-».
func Time(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return i18n.FmtLocal(time.UnixMilli(ms), i18n.LocalMin)
}

// TimeOf es la hora local con zona, al minuto.
func TimeOf(t time.Time) string { return i18n.FmtLocal(t, i18n.LocalMin) }

// TimeSecOf es la hora local con zona, a segundos.
func TimeSecOf(t time.Time) string { return i18n.FmtLocal(t, i18n.LocalSec) }
