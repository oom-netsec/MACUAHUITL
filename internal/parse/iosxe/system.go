package iosxe

// Arranque, instalación, redundancia, verificación de imagen y cabecera de la
// configuración: lo que lee la verificación previa a un upgrade.

import (
	"regexp"
	"strings"
	"time"
)

// ---- show boot / show bootvar ----

type Boot struct {
	Entries []string // imágenes de la variable BOOT (la de "next reload" si la hay)
	Manual  bool     // MANUAL_BOOT = yes
}

var (
	bootLineRe   = regexp.MustCompile(`(?m)^BOOT variable = (.*)$`)
	bootNextRe   = regexp.MustCompile(`(?s)Boot Variables on next reload:\s*\n(?:.*?\n)?BOOT variable = ([^\n]*)`)
	bootManualRe = regexp.MustCompile(`(?mi)^(MANUAL_BOOT variable|Manual Boot)\s*=\s*yes`)
)

// ParseBoot da ok=false si no hay línea "BOOT variable"; Manual se llena igual.
func ParseBoot(text string) (Boot, bool) {
	b := Boot{Manual: bootManualRe.MatchString(text)}
	raw, ok := "", false
	if m := bootNextRe.FindStringSubmatch(text); m != nil {
		raw, ok = m[1], true
	} else if m := bootLineRe.FindStringSubmatch(text); m != nil {
		raw, ok = m[1], true
	}
	for _, e := range strings.Split(raw, ";") {
		if e = strings.TrimSpace(strings.SplitN(e, ",", 2)[0]); e != "" {
			b.Entries = append(b.Entries, e)
		}
	}
	return b, ok
}

// ---- show install summary ----

// InstallPkg es una fila de la tabla: tipo (IMG, SMU...), estado (U, C, I, D, A) y archivo.
type InstallPkg struct{ Type, State, File string }

var installRe = regexp.MustCompile(`(?m)^\s*(IMG|SMU|APSP|APDP|ROMMON|PKG)\s+([A-Z])\s+(\S+)`)

func ParseInstallSummary(text string) ([]InstallPkg, bool) {
	var out []InstallPkg
	for _, m := range installRe.FindAllStringSubmatch(text, -1) {
		out = append(out, InstallPkg{m[1], m[2], m[3]})
	}
	return out, len(out) > 0
}

// ---- show redundancy ----

type Redundancy struct {
	Mode       string // sso, rpr, non-redundant...
	StandbyHot bool
	Simplex    bool
}

var redModeRe = regexp.MustCompile(`(?mi)Operating Redundancy Mode\s*=\s*(.+?)\s*$`)

func ParseRedundancy(text string) (Redundancy, bool) {
	m := redModeRe.FindStringSubmatch(text)
	if m == nil {
		return Redundancy{}, false
	}
	return Redundancy{Mode: m[1], StandbyHot: strings.Contains(text, "STANDBY HOT"), Simplex: strings.Contains(strings.ToLower(text), "simplex")}, true
}

// ---- verify /md5 ----

// MD5 es la suma que calculó el equipo; Path va vacío cuando la salida solo trae "computed signature".
type MD5 struct{ Path, Sum string }

var (
	md5ComputedRe = regexp.MustCompile(`(?i)computed signature\s*=?\s*([0-9a-f]{32})`)
	md5VerifiedRe = regexp.MustCompile(`(?i)verif(?:ied|y /md5) \(([^)]*)\)\s*=\s*([0-9a-f]{32})`)
)

func ParseVerifyMD5(text string) (MD5, bool) {
	if m := md5ComputedRe.FindStringSubmatch(text); m != nil {
		return MD5{Sum: strings.ToLower(m[1])}, true
	}
	if m := md5VerifiedRe.FindStringSubmatch(text); m != nil {
		return MD5{Path: m[1], Sum: strings.ToLower(m[2])}, true
	}
	return MD5{}, false
}

// ---- cabecera de show running-config ----

// ConfigHeader son las líneas de comentario con las que IOS abre show running-config.
type ConfigHeader struct {
	NoChange              bool      // "No configuration change since last restart"
	LastChange, Saved     string    // texto tras "at", sin interpretar
	LastChangeAt, SavedAt time.Time // cero si la fecha no se pudo leer
}

var (
	cfgChangeRe = regexp.MustCompile(`(?m)^! Last configuration change at (.*)$`)
	cfgSavedRe  = regexp.MustCompile(`(?m)^! NVRAM config last updated at (.*)$`)
)

// ParseConfigHeader da ok si trae alguna de las tres marcas.
func ParseConfigHeader(text string) (ConfigHeader, bool) {
	var h ConfigHeader
	h.NoChange = strings.Contains(text, "No configuration change since last restart")
	if m := cfgChangeRe.FindStringSubmatch(text); m != nil {
		h.LastChange = m[1]
		h.LastChangeAt, _ = iosTime(m[1])
	}
	if m := cfgSavedRe.FindStringSubmatch(text); m != nil {
		h.Saved = m[1]
		h.SavedAt, _ = iosTime(m[1])
	}
	return h, h.NoChange || h.LastChange != "" || h.Saved != ""
}

// iosTime lee "09:40:11 UTC Tue Nov 3 2026 by admin" (con o sin milisegundos).
func iosTime(s string) (time.Time, bool) {
	f := strings.Fields(s)
	if len(f) < 6 {
		return time.Time{}, false
	}
	v := strings.Join(f[:6], " ")
	for _, layout := range []string{"15:04:05 MST Mon Jan 2 2006", "15:04:05.000 MST Mon Jan 2 2006"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
