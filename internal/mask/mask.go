// Package mask aplica las reglas de enmascarado de secretos por plataforma
// sobre los outputs (spec §12.5).
//
// No hace: decidir si se enmascara; eso lo decide el trabajo.
package mask

import (
	"regexp"
	"strings"
)

type rule struct {
	kind  string
	block string // "" = en cualquier lugar; si no, solo dentro de ese bloque
	re    *regexp.Regexp
	not   *regexp.Regexp // si la línea la cumple, la regla no aplica
}

// Línea de keyring IKEv1: ahí «address/hostname/ipv6» no es la llave.
var keyringLine = regexp.MustCompile(`^\s*pre-shared-key (?:address|hostname|ipv6) \S`)

// Cada expresión captura (prefijo)(valor)(resto); solo se reemplaza el valor.
var iosRules = []rule{
	{"enable-secret", "", regexp.MustCompile(`^(\s*enable (?:secret|password) (?:level \d+ )?(?:[0-9] )?)(\S+)(.*)$`), nil},
	{"user-secret", "", regexp.MustCompile(`^(\s*username \S+ (?:.*? )?(?:secret|password) (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"snmp-community", "", regexp.MustCompile(`^(\s*snmp-server community )(\S+)(.*)$`), nil},
	{"tacacs-key", "", regexp.MustCompile(`^(\s*tacacs-server (?:host \S+ )?key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"radius-key", "", regexp.MustCompile(`^(\s*radius-server (?:host \S+ .*?)?key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"psk", "", regexp.MustCompile(`^(\s*crypto isakmp key (?:[0-9] )?)(\S+)(.*)$`), nil},
	// Keyring IKEv1: la llave va tras «key», no tras address/hostname/ipv6.
	{"psk", "", regexp.MustCompile(`^(\s*pre-shared-key (?:address|hostname|ipv6) .*? key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"psk", "", regexp.MustCompile(`^(\s*pre-shared-key (?:local |remote )?(?:[0-9] )?)(\S+)(.*)$`), keyringLine},
	{"ntp-key", "", regexp.MustCompile(`^(\s*ntp authentication-key \d+ (?:md5|hmac-sha\S*|cmac-aes-128) )(\S+)(.*)$`), nil},
	{"snmp-user-auth", "", regexp.MustCompile(`^(\s*snmp-server user .*? auth (?:md5|sha\S*) )(\S+)(.*)$`), nil},
	{"snmp-user-priv", "", regexp.MustCompile(`^(\s*snmp-server user .*? priv (?:des|3des|aes(?: \d+)?) )(\S+)(.*)$`), nil},
	{"snmp-community", "", regexp.MustCompile(`^(\s*snmp-server host \S+ (?:(?:informs|traps) )?(?:version (?:1|2c|3 (?:auth|noauth|priv)) )?)(\S+)(.*)$`), nil},
	{"bgp-password", "", regexp.MustCompile(`^(\s*neighbor \S+ password (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"ppp-password", "", regexp.MustCompile(`^(\s*ppp (?:chap password|pap sent-username \S+ password) (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"wifi-psk", "", regexp.MustCompile(`^(\s*(?:security wpa psk set-key|wpa-psk) (?:ascii|hex) (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"fhrp-key", "", regexp.MustCompile(`^(\s*(?:standby|vrrp) \d+ authentication (?:md5 key-string (?:[0-9] )?|text )?)(\S+)(.*)$`), nil},
	{"key-string", "", regexp.MustCompile(`^(\s*key-string (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"tacacs-key", "", regexp.MustCompile(`^(\s*server-private \S+ (?:.*? )?key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"client-password", "", regexp.MustCompile(`^(\s*ip (?:ftp|http client) password (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"config-key", "", regexp.MustCompile(`^(\s*key config-key password-encrypt )(\S+)(.*)$`), nil},
	{"ospf-key", "", regexp.MustCompile(`^(\s*ip ospf authentication-key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"ospf-key", "", regexp.MustCompile(`^(\s*ip ospf message-digest-key \d+ md5 (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"tacacs-key", "tacacs", regexp.MustCompile(`^(\s+key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"radius-key", "radius", regexp.MustCompile(`^(\s+key (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"dot1x-password", "dot1x", regexp.MustCompile(`^(\s+password (?:[0-9] )?)(\S+)(.*)$`), nil},
	{"line-password", "line", regexp.MustCompile(`^(\s+password (?:[0-9] )?)(\S+)(.*)$`), nil},
}

var (
	keyBegin  = regexp.MustCompile(`^-----BEGIN .*PRIVATE KEY-----`)
	keyEnd    = regexp.MustCompile(`^-----END .*PRIVATE KEY-----`)
	certChain = regexp.MustCompile(`^crypto pki certificate chain `)
	keyBody   = regexp.MustCompile(`^(?:[A-Za-z0-9+/=]*|Proc-Type: .*|DEK-Info: .*)$`)
)

func blockOf(line string) string {
	switch {
	case strings.HasPrefix(line, "tacacs server "):
		return "tacacs"
	case strings.HasPrefix(line, "radius server "):
		return "radius"
	case strings.HasPrefix(line, "dot1x credentials "):
		return "dot1x"
	case strings.HasPrefix(line, "line "):
		return "line"
	}
	return ""
}

// Apply devuelve text con los secretos reemplazados por <MASKED:tipo> y cuántos hubo por tipo.
// shortcut: solo reglas IOS/IOS-XE; cada plataforma de la Fase 2 agrega las suyas.
func Apply(platform, text string) (string, map[string]int) {
	var out strings.Builder
	st := Stream{counts: map[string]int{}}
	for _, raw := range strings.SplitAfter(text, "\n") {
		if l, ok := st.Line(raw); ok {
			out.WriteString(l)
		}
	}
	return out.String(), st.counts
}

// Stream aplica las reglas línea a línea conservando el estado entre líneas (bloque, llaves y
// cadenas de certificados), para enmascarar una salida que llega por trozos.
type Stream struct {
	block, skip string
	n           int
	counts      map[string]int
	// MaxSkip: líneas máximas que se descartan dentro de una llave o cadena sin cierre (0 = sin tope).
	MaxSkip int
}

// Line enmascara una línea (con su fin de línea, si lo trae). ok=false: la línea se omite (cuerpo de una llave).
func (s *Stream) Line(raw string) (out string, ok bool) {
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	line, eol := splitEOL(raw)
	if s.skip != "" {
		if s.n++; s.MaxSkip > 0 && s.n > s.MaxSkip {
			s.skip = ""
		}
	}
	switch s.skip {
	case "key":
		if keyEnd.MatchString(line) {
			s.skip = ""
			return "", false
		}
		if keyBody.MatchString(strings.TrimSpace(line)) {
			return "", false
		}
		s.skip = "" // llave sin END: lo que no es cuerpo PEM sigue su camino, no se descarta el resto
	case "chain":
		// La cadena (uno o varios certificados con su quit, o en show startup-config solo una referencia
		// a nvram sin quit) termina en la siguiente línea de primer nivel, que sí se procesa.
		if strings.TrimSpace(line) == "" || line[0] == ' ' || line[0] == '\t' {
			return "", false
		}
		s.skip = ""
	}
	if keyBegin.MatchString(line) {
		s.counts["private-key"]++
		s.skip, s.n = "key", 0
		return "<MASKED:private-key>" + eol, true
	}
	if certChain.MatchString(line) {
		s.counts["private-key"]++
		s.skip, s.n = "chain", 0
		return line + eol + " <MASKED:private-key>" + eol, true
	}
	if line != "" && line[0] != ' ' && line[0] != '\t' {
		s.block = blockOf(line)
	}
	return maskLine(line, s.block, s.counts) + eol, true
}

// Prompted enmascara una línea tecleada o repetida tras un prompt (sin sangría). El bloque lo da
// el modo del prompt ("line", "tacacs", "radius"); si no, el que dejó la línea anterior.
func (s *Stream) Prompted(line, block string) string {
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	s.skip = "" // un prompt no es cuerpo de llave ni de certificado: lo que esté abierto termina aquí
	if line != "" {
		s.block = blockOf(line)
	}
	if block == "" {
		block = s.block
	}
	return maskLine(" "+line, block, s.counts)[1:]
}

// maskLine aplica reglas hasta que ninguna cambie la línea: una línea puede traer
// varios secretos (snmp-server user … auth X priv Y).
func maskLine(line, block string, counts map[string]int) string {
	for changed := true; changed; {
		changed = false
		for _, r := range iosRules {
			if r.block != "" && r.block != block || r.not != nil && r.not.MatchString(line) {
				continue
			}
			m := r.re.FindStringSubmatch(line)
			if m == nil || strings.HasPrefix(m[2], "<MASKED:") {
				continue
			}
			counts[r.kind]++
			line, changed = m[1]+"<MASKED:"+r.kind+">"+m[3], true
		}
	}
	return line
}

func splitEOL(s string) (string, string) {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2], "\r\n"
	}
	if strings.HasSuffix(s, "\n") {
		return s[:len(s)-1], "\n"
	}
	return s, ""
}
