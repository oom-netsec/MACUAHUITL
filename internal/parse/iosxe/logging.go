package iosxe

// show clock detail y show logging.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var clockRe = regexp.MustCompile(`^[*.]?(\d{1,2}:\d{2}:\d{2})(?:\.\d+)?\s+\S+\s+[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})`)

// ParseClock lee show clock detail: la hora local del equipo, sin zona (se devuelve como si fuera UTC).
func ParseClock(text string) (time.Time, bool) {
	for _, ln := range lines(text) {
		m := clockRe.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		if t, err := time.Parse("2006 Jan 2 15:04:05", fmt.Sprintf("%s %s %s %s", m[4], m[2], m[3], m[1])); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// LogLine es un mensaje de show logging con marca de fecha.
type LogLine struct {
	Unsynced bool   // la marca empieza con "*": reloj sin sincronizar
	Year     int    // 0 si la marca no trae año
	Month    string // Nov
	Day      string
	Clock    string // 09:58:12.345
	Zone     string // vacío si la marca no dice zona
	Text     string // lo que sigue a la marca
	Severity int    // 0-7 del mnemónico %FAC-SEV-NAME; -1 si no hay
}

var (
	// Marcas de "service timestamps log datetime": "*Nov  4 09:58:12.345:", "000045: Nov  4 2026 10:00:01.123 UTC:".
	logStampRe  = regexp.MustCompile(`^(?:\d+: )?([*.]?)([A-Z][a-z]{2})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)(?:\s+([A-Za-z]{2,5}))?: (.*)$`)
	logUptimeRe = regexp.MustCompile(`^(?:\d+: )?[*.]?(?:\d+[ywdhms])+\d*: %|^(?:\d+: )?[*.]?\d{2}:\d{2}:\d{2}: %`)
	mnemonicRe  = regexp.MustCompile(`%[A-Z0-9_]+-([0-7])-[A-Z0-9_]+`)
)

// LogUptimeStamp dice si la línea lleva marca de uptime (sin fecha absoluta).
func LogUptimeStamp(ln string) bool { return logUptimeRe.MatchString(ln) }

// ParseLogLine lee una línea de show logging; ok=false si no trae marca de fecha.
func ParseLogLine(ln string) (LogLine, bool) {
	m := logStampRe.FindStringSubmatch(ln)
	if m == nil {
		return LogLine{}, false
	}
	l := LogLine{Unsynced: m[1] != "", Month: m[2], Day: m[3], Clock: m[5], Zone: m[6], Text: m[7], Severity: -1}
	if m[4] != "" {
		l.Year, _ = strconv.Atoi(m[4])
	}
	if s := mnemonicRe.FindStringSubmatch(m[7]); s != nil {
		l.Severity, _ = strconv.Atoi(s[1])
	}
	return l, true
}

// At arma la fecha de la marca con el año dado; error si el mes o la hora no existen.
func (l LogLine) At(year int) (time.Time, error) {
	return time.Parse("2006 Jan 2 15:04:05.999999", fmt.Sprintf("%d %s %s %s", year, l.Month, l.Day, l.Clock))
}
