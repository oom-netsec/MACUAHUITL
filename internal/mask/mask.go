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
	guard bool           // si el valor es una palabra clave (md5, use-vrf, default…), la regla no aplica
}

const (
	typ = `(?:[0-9] )?` // tipo de cifrado opcional («0 », «7 »…)
	// El valor es una palabra o una cadena entre comillas (NX-OS: "ab cd"); sigue el resto de la línea.
	val = `("[^"]*"|\S+)(.*)$`
)

// R arma una regla: el prefijo (hasta el valor) es el grupo 1, el valor el 2 y el resto el 3.
func R(kind, block, prefix string) rule {
	return rule{kind: kind, block: block, re: regexp.MustCompile(`^(` + prefix + `)` + val)}
}

// full arma una regla con la expresión completa (prefijo, valor y resto) para las salidas de show.
func full(kind, expr string) rule { return rule{kind: kind, re: regexp.MustCompile(expr)} }

func (r rule) unless(not *regexp.Regexp) rule { r.not = not; return r }
func (r rule) guarded() rule                  { r.guard = true; return r }

// Línea de keyring IKEv1: ahí «address/hostname/ipv6» no es la llave.
var keyringLine = regexp.MustCompile(`^\s*pre-shared-key (?:address|hostname|ipv6) \S`)

// HSRP/VRRP con key-chain o sin autenticación: no hay secreto en la línea.
var fhrpNoKey = regexp.MustCompile(`authentication (?:md5 key-chain|none)\b`)

// Cada regla captura (prefijo)(valor)(resto); solo se reemplaza el valor.
var iosRules = []rule{
	R("enable-secret", "", `\s*enable (?:algorithm-type \S+ )?(?:secret|password) (?:level \d+ )?`+typ),
	R("user-secret", "", `\s*username \S+ (?:.*? )?(?:secret|password) `+typ),
	R("snmp-community", "", `\s*snmp-server community `),
	R("tacacs-key", "", `\s*tacacs-server (?:host \S+ (?:.*? )?)?key `+typ),
	R("radius-key", "", `\s*radius-server (?:host \S+ .*?)?key `+typ),
	R("psk", "", `\s*crypto isakmp key `+typ),
	// Keyring IKEv1: la llave va tras «key», no tras address/hostname/ipv6.
	R("psk", "", `\s*pre-shared-key (?:address|hostname|ipv6) .*? key `+typ),
	R("psk", "", `\s*pre-shared-key (?:local |remote )?`+typ).unless(keyringLine),
	R("ntp-key", "", `\s*ntp authentication-key \d+ (?:md5|hmac-sha\S*|cmac-aes-128) `),
	R("snmp-user-auth", "", `\s*snmp-server user .*? auth (?:md5|sha-2 \d+|sha\S*) `),
	R("snmp-user-priv", "", `\s*snmp-server user .*? priv (?:(?:des|3des|aes(?:[- ]\d+)?) )?`),
	// La comunidad va tras vrf/use-vrf, informs/traps y version; use-vrf sin valor no es la comunidad.
	R("snmp-community", "", `\s*snmp-server host \S+ (?:(?:use-)?vrf \S+ )*(?:(?:informs|traps) )?(?:version (?:1|2c|3 (?:auth|noauth|priv)) )?`).guarded(),
	R("snmp-community", "", `\s*snmp mib community-map `),
	R("bgp-password", "", `\s*neighbor \S+ password `+typ),
	R("ppp-password", "", `\s*ppp (?:chap password|pap sent-username \S+ password) `+typ),
	R("wifi-psk", "", `\s*(?:\S+ )*?(?:security wpa psk set-key|wpa-psk|set-key) (?:ascii|hex) `+typ),
	R("wifi-psk", "", `\s*psk key `+typ),
	R("fhrp-key", "", `\s*(?:standby|vrrp)(?: \d+)? authentication (?:md5 key-string `+typ+`|text )?`).unless(fhrpNoKey),
	R("fhrp-key", "", `\s*glbp \d+ authentication (?:md5 key-string `+typ+`|text )`),
	R("fhrp-key", "", `\s+authentication (?:text |md5 key-string `+typ+`)`), // NX-OS: anidado bajo hsrp/vrrp/glbp
	R("key-string", "", `\s*key-string `+typ),
	R("tacacs-key", "", `\s*server-private \S+ (?:.*? )?key `+typ),
	R("client-password", "", `\s*ip (?:ftp|http client) password `+typ),
	R("config-key", "", `\s*key config-key password-encrypt `),
	R("config-key", "", `\s*key config-key \d+ `),
	R("ospf-key", "", `\s*ip ospf authentication-key `+typ),
	R("ospf-key", "", `\s*ip ospf message-digest-key \d+ md5 `+typ),
	R("ospf-key", "", `\s*area \S+ virtual-link \S+ (?:.*? )?(?:message-digest-key \d+ md5|authentication-key) `+typ),
	// OSPFv3 (IOS «ipv6 ospf», NX-OS/IOS-XE «ospfv3»): autenticación y cifrado IPsec.
	R("ospf-key", "", `\s*(?:ipv6 ospf|ospfv3(?: \d+)?) authentication ipsec spi \d+ (?:md5|sha1) `+typ),
	R("ospf-key", "", `\s*(?:ipv6 ospf|ospfv3(?: \d+)?) encryption ipsec spi \d+ esp (?:aes-cbc (?:\d+ )?|3des |des )`+typ),
	R("ospf-key", "", `\s*(?:ipv6 ospf|ospfv3(?: \d+)?) encryption ipsec spi \d+ esp (?:.*? )?(?:md5|sha1) `+typ),
	R("ospf-key", "", `\s*area \S+ (?:virtual-link \S+ )?authentication ipsec spi \d+ (?:md5|sha1) `+typ),
	R("ospf-key", "", `\s*area \S+ (?:virtual-link \S+ )?encryption ipsec spi \d+ esp (?:aes-cbc (?:\d+ )?|3des |des )`+typ),
	R("ospf-key", "", `\s*area \S+ (?:virtual-link \S+ )?encryption ipsec spi \d+ esp (?:.*? )?(?:md5|sha1) `+typ),
	R("eigrp-key", "", `\s*authentication mode hmac-sha-256 `+typ),
	// ISE/TrustSec: PAC dentro de «radius server …»; CoA de ISE en «aaa server radius dynamic-author».
	R("radius-key", "", `\s*pac key `+typ),
	R("radius-key", "", `\s*(?:client \S+ (?:vrf \S+ )?)?server-key `+typ),
	R("radius-key", "", `\s*dtls key `+typ),
	// LISP (fabric SD-Access).
	R("lisp-key", "", `\s*authentication-key `+typ),
	R("lisp-key", "", `\s*(?:ipv[46] )?(?:etr )?map-server \S+ (?:.*? )?key `+typ),
	// 9800: credenciales de gestión de los AP en «ap profile», 802.1X de AP, usuarios locales y EWC.
	R("user-secret", "", `\s*mgmtuser username \S+ (?:.*? )?password `+typ),
	R("user-secret", "", `\s*mgmtuser username \S+ (?:.*? )?secret `+typ),
	R("dot1x-password", "", `\s*(?:ap )?dot1x username \S+ (?:.*? )?password `+typ),
	R("user-secret", "", `\s*wireless ewc-ap (?:.*? )?password `+typ),
	R("user-secret", "", `\s*wireless ewc-ap (?:.*? )?secret `+typ),
	R("user-secret", "username", `\s+(?:password|secret) `+typ),
	// LDAP (IOS «bind authenticate», NX-OS «ldap-server host … rootDN … password»), IS-IS, LDP, MSDP, PIM, BFD, GLBP.
	R("ldap-password", "", `\s*bind authenticated? (?:.*? )?password `+typ),
	R("ldap-password", "", `\s*ldap-server host \S+ (?:.*? )?password `+typ),
	R("isis-password", "", `\s*(?:area|domain)-password `+typ),
	R("isis-password", "", `\s*isis password `+typ),
	R("ldp-password", "", `\s*mpls ldp neighbor \S+ (?:.*? )?password `+typ),
	R("ldp-password", "", `\s*mpls ldp password fallback `+typ),
	R("msdp-password", "", `\s*ip msdp password (?:peer )?\S+ `+typ),
	R("pim-key", "", `\s*ip pim hello-authentication ah-md5 `+typ),
	R("bfd-key", "", `\s*bfd authentication \S+ key-id \d+ (?:hex-)?key `),
	// VPN y PKI.
	R("psk", "", `\s*authentication (?:local|remote) pre-share key `+typ),
	R("psk", "ezvpn", `\s+key `+typ),
	R("psk", "", `\s*group \S+ key `+typ), // cliente EzVPN (crypto ipsec client ezvpn)
	R("l2tp-password", "", `\s*l2tp tunnel password `+typ),
	R("nhrp-key", "", `\s*ip(?:v6)? nhrp authentication `),
	R("ipsec-key", "", `\s*set session-key (?:inbound|outbound) esp \d+ cipher `),
	R("ipsec-key", "", `\s*set session-key (?:inbound|outbound) esp \d+ (?:.*? )?authenticator `),
	R("ipsec-key", "", `\s*set session-key (?:inbound|outbound) ah \d+ `),
	R("pki-password", "trustpoint", `\s+password `+typ),
	R("pki-password", "", `\s*database archive (?:.*? )?password `+typ),
	R("pki-password", "", `\s*crypto pki (?:import|export) (?:.*? )?password `+typ),
	R("pki-password", "", `\s*crypto (?:key|pki) (?:import|export) (?:(?:rsa|ec) )?\S+ pem (?:terminal|url \S+|\S+:\S*) (?:(?:3des|des|aes) )?`).guarded(),
	R("pki-password", "", `\s*crypto ca (?:export|import) \S+ pkcs12 \S+ `),
	// TrustSec, MACsec, WCCP, VTP, Umbrella y licencias inteligentes.
	R("cts-key", "", `\s*cts credentials id \S+ password `+typ),
	R("cts-key", "", `\s*cts sxp (?:default password|connection peer \S+ (?:.*? )?password) `+typ).guarded(),
	R("cts-key", "", `\s*cts device-id \S+ password `+typ),
	R("macsec-key", "", `\s*sap pmk `),
	R("macsec-key", "", `\s*key-octet-string `+typ),
	R("wccp-password", "", `\s*ip wccp (?:.*? )?password `+typ),
	R("vtp-password", "", `\s*vtp password `+typ),
	R("token", "umbrella", `\s+token `),
	R("token", "", `\s*api-key `+typ),
	R("token", "", `\s*api-key (?:.*? )?secret `+typ),
	R("token", "", `\s*license smart (?:.*? )?idtoken `),
	// Salida de show snmp community / show snmp host de IOS: la comunidad v1/v2c es el secreto (v3 es un usuario).
	R("snmp-community", "", `\s*Community (?:name|Index|SecurityName): `),
	full("snmp-community", `^(\s*user: )(\S+)(\s+security model: v(?:1|2c)\b.*)$`),
	// Otras salidas de show que imprimen secretos.
	full("psk", `^(\s*Pre-[Ss]hared [Kk]ey(?: \(\w+\))?\s*[:=]\s*)(\S.*?)(\s*)$`),
	full("key-string", `^(\s*[Kk]ey \d+ -- text (?:\d+ )?)("[^"]*"|\S+)(.*)$`), // show key chain
	full("fhrp-key", `^(\s*Authentication text, string )("[^"]*"|\S+)(.*)$`),   // show standby / show glbp
	full("vtp-password", `^(\s*VTP Password:\s*)(\S+)(.*)$`),
	full("cts-pac", `^(\s*PAC-Opaque\s*[:=]\s*)(\S+)(.*)$`),
	full("user-secret", `^(\s*Mgmt (?:Password|Secret)\s*[:=]\s*)(\S.*?)(\s*)$`),
	full("dot1x-password", `^(\s*Dot1x Password\s*[:=]\s*)(\S.*?)(\s*)$`),
	full("wifi-psk", `^(\s*PSK\s*[:=]\s*)(\S.*?)(\s*)$`).guarded(),
	R("tacacs-key", "tacacs", `\s+key `+typ),
	R("radius-key", "radius", `\s+key `+typ),
	R("dot1x-password", "dot1x", `\s+password `+typ),
	R("line-password", "line", `\s+password `+typ),
}

// Palabras que, como valor, no son un secreto sino otra palabra clave del comando (ntp … key 5 prefer, password default…).
var guardWords = map[string]bool{
	"md5": true, "sha1": true, "sha-1": true, "sha-2": true, "sha256": true, "sha-256": true, "sha512": true, "hmac-sha-256": true,
	"prefer": true, "iburst": true, "burst": true, "use-vrf": true, "vrf": true, "filter-vrf": true, "version": true,
	"source": true, "source-interface": true, "minpoll": true, "maxpoll": true, "priority": true, "--": true, "text": true,
	"key-string": true, "ascii": true, "hex": true, "mode-list": true, "cryptographic-algorithm": true, "key": true,
	"password": true, "secret": true, "level": true, "encrypt": true, "aes": true, "aes-cbc": true, "des": true, "3des": true,
	"null": true, "chain": true, "key-chain": true, "keychain": true, "required": true, "fallback": true, "default": true,
	"none": true, "option": true, "recovery": true, "hidden": true, "traps": true, "informs": true, "udp-port": true,
	"timeout": true, "port": true, "retransmit": true, "authenticate": true, "transport": true, "mode": true,
	"single-connection": true, "role": true, "enabled": true, "disabled": true, "not": true, "n/a": true,
}

// Palabras clave que cierran un valor de tipo 0 (que puede llevar espacios) en el comando que lo trae.
var tailStops = map[string]bool{
	"role": true, "hidden": true, "localizedkey": true, "level-1": true, "level-2": true, "priority": true,
	"mode-list": true, "eap-type": true, "timeout": true, "retransmit": true, "expire": true, "sshkey": true, "privilege": true,
	"cryptographic-algorithm": true, "auth-port": true, "acct-port": true, "single-connection": true,
	"port": true, "view": true, "address": true, "hostname": true, "no-xauth": true, "vrf": true, "use-vrf": true, "type": true,
}

// tail amplía un valor de tipo 0: sigue hasta el fin de la línea o hasta una palabra clave de tailStops.
// Devuelve lo que se suma al valor y lo que queda de la línea.
func tail(rest string) (more, left string) {
	end, pos := 0, 0
	for {
		loc := nextToken.FindStringIndex(rest[pos:])
		if loc == nil || tailStops[strings.TrimSpace(rest[pos+loc[0]:pos+loc[1]])] || typedWord.MatchString(rest[pos:]) {
			return rest[:end], rest[end:]
		}
		pos += loc[1]
		end = pos
	}
}

var (
	nextToken = regexp.MustCompile(`^\s+\S+`)
	// Otra palabra de secreto con su tipo (… password 0 x secret 0 y): ahí empieza otro valor.
	typedWord = regexp.MustCompile(`^\s+(?:password|secret|key|key-string) [0-9](?: |$)`)
	typeZero  = regexp.MustCompile(`(?:^|\s)0 $`)
)

var (
	keyBegin  = regexp.MustCompile(`^\s*-----BEGIN .*PRIVATE KEY-----`)
	keyEnd    = regexp.MustCompile(`^\s*-----END .*PRIVATE KEY-----`)
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
	case strings.HasPrefix(line, "crypto isakmp client configuration group "):
		return "ezvpn"
	case strings.HasPrefix(line, "crypto pki trustpoint "):
		return "trustpoint"
	case strings.HasPrefix(line, "user-name "):
		return "username"
	case strings.HasPrefix(line, "parameter-map type umbrella"):
		return "umbrella"
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
	table       string // tabla de NX-OS/IOS en curso: "community", "host" o "isakmp"
	rows        int    // filas vistas de la tabla en curso
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
	if out, ok := s.snmpTable(line); ok {
		return out + eol, true
	}
	if line != "" && line[0] != ' ' && line[0] != '\t' {
		s.block = blockOf(line)
	}
	return maskLine(line, s.block, s.counts) + eol, true
}

var (
	nxCommunityHead = regexp.MustCompile(`^Community\s+Group / Access`)
	nxHostHead      = regexp.MustCompile(`^Host\s+Port\s+Version\s+Level\s+Type\s+SecName`)
	isakmpHead      = regexp.MustCompile(`^Keyring\s+Hostname/Address\s+Preshared Key`)
	dashes          = regexp.MustCompile(`^-[- ]*$`) // separador: guiones, con o sin espacios entre columnas
	digits          = regexp.MustCompile(`^\d+$`)
)

// fieldStart devuelve dónde empieza el campo n (desde 0) de la línea.
func fieldStart(line string, n int) int {
	pos := 0
	for i := 0; ; i++ {
		for pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
			pos++
		}
		if i == n || pos >= len(line) {
			return pos
		}
		for pos < len(line) && line[pos] != ' ' && line[pos] != '\t' {
			pos++
		}
	}
}

var hostLabel = regexp.MustCompile(`^\s*[A-Z][A-Za-z ]*:(?:\s|$)`) // «Use VRF: x», «Source interface: x»…

// tableRow dice si la línea es una fila de la tabla en curso. Ante la duda es fila (se tapa de más, no de menos):
// solo lo claramente ajeno (otra salida, un prompt) cierra la tabla. keep: línea de la tabla que no es fila.
func (s *Stream) tableRow(line string, f []string) (row, keep bool) {
	switch s.table {
	case "community":
		// La 1.ª columna es la comunidad aunque las columnas no cuadren o vengan con tabuladores.
		last := f[0][len(f[0])-1]
		return len(f) <= 4 && last != '#' && last != '>', false
	case "host":
		// Entre host y host van «Use VRF:», «Source interface:», «Notification type:»… y separadores.
		return len(f) >= 6 && digits.MatchString(f[1]), hostLabel.MatchString(line)
	}
	return len(f) >= 3, false // isakmp: llavero, equipo y llave
}

// snmpTable enmascara las tablas de show snmp community (comunidad en la 1.ª columna) y show snmp host (SecName en la
// última; en v1/v2c es la comunidad) de NX-OS, y la de show crypto isakmp key (llave desde la 3.ª columna). Se cierra con
// una línea en blanco o un separador (tras alguna fila), con una línea sin forma de fila o con Prompted. Las filas
// también pasan por maskLine. ok=false: la línea no es de una tabla y sigue el camino normal.
func (s *Stream) snmpTable(line string) (string, bool) {
	t := strings.TrimSpace(line)
	switch {
	case nxCommunityHead.MatchString(line):
		s.table, s.rows = "community", 0
		return line, true
	case nxHostHead.MatchString(line):
		s.table, s.rows = "host", 0
		return line, true
	case isakmpHead.MatchString(line):
		s.table, s.rows = "isakmp", 0
		return line, true
	case s.table == "":
		return "", false
	case s.table == "host" && dashes.MatchString(t):
		return line, true // los separadores entre hosts no cierran la tabla
	case t == "" || dashes.MatchString(t):
		if s.rows > 0 {
			s.table = "" // fin de la tabla
			return "", false
		}
		return line, true // línea en blanco o separador entre el encabezado y las filas
	}
	f := strings.Fields(line)
	row, keep := s.tableRow(line, f)
	if keep {
		return maskLine(line, "", s.counts), true
	}
	if !row {
		s.table = ""
		return "", false
	}
	s.rows++
	line = maskLine(line, "", s.counts) // la fila también pasa por las reglas
	if f = strings.Fields(line); len(f) == 0 {
		return line, true
	}
	switch {
	case s.table == "community" && !strings.HasPrefix(f[0], "<MASKED:"):
		s.counts["snmp-community"]++
		line = strings.Replace(line, f[0], "<MASKED:snmp-community>", 1)
	case s.table == "host" && len(f) >= 3 && (f[2] == "v1" || f[2] == "v2c") && !strings.HasPrefix(f[len(f)-1], "<MASKED:"):
		s.counts["snmp-community"]++
		i := strings.LastIndex(line, f[len(f)-1])
		line = line[:i] + "<MASKED:snmp-community>" + line[i+len(f[len(f)-1]):]
	case s.table == "isakmp" && len(f) >= 3 && !strings.HasPrefix(f[2], "<MASKED:"):
		s.counts["psk"]++
		line = line[:fieldStart(line, 2)] + "<MASKED:psk>"
	}
	return line, true
}

// Prompted enmascara una línea tecleada o repetida tras un prompt (sin sangría). El bloque lo da
// el modo del prompt ("line", "tacacs", "radius"); si no, el que dejó la línea anterior.
func (s *Stream) Prompted(line, block string) string {
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	s.table = "" // ni una tabla de show sigue abierta tras un prompt
	s.skip = ""  // un prompt no es cuerpo de llave ni de certificado: lo que esté abierto termina aquí
	if line != "" {
		s.block = blockOf(line)
	}
	if block == "" {
		block = s.block
	}
	return maskLine(" "+line, block, s.counts)[1:]
}

// archiveLog: línea de show archive log config; tras «|» va un comando de configuración.
var archiveLog = regexp.MustCompile(`^(\s*\d+\s+\d+\s+\S+\s+\|)(.*)$`)

// loggedCmd: mensaje de syslog (%PARSER-5-CFGLOG_LOGGEDCMD) con el comando de configuración tras «logged command:».
var loggedCmd = regexp.MustCompile(`^(.*logged command:)(.*)$`)

// maskLine aplica reglas hasta que ninguna cambie la línea: una línea puede traer
// varios secretos (snmp-server user … auth X priv Y).
func maskLine(line, block string, counts map[string]int) string {
	if m := loggedCmd.FindStringSubmatch(line); m != nil {
		return m[1] + maskLine(m[2], "", counts)
	}
	if m := archiveLog.FindStringSubmatch(line); m != nil {
		return m[1] + maskLine(m[2], "", counts)
	}
	for changed := true; changed; {
		changed = false
		for _, r := range iosRules {
			if r.block != "" && r.block != block || r.not != nil && r.not.MatchString(line) {
				continue
			}
			m := r.re.FindStringSubmatch(line)
			if m == nil || strings.HasPrefix(m[2], "<MASKED:") || r.guard && isGuard(m[2]) {
				continue
			}
			// En tipo 0 la clave puede llevar espacios: llega hasta el fin de línea o una palabra clave del comando.
			if typeZero.MatchString(m[1]) && m[2][0] != '"' {
				_, m[3] = tail(m[3])
			}
			counts[r.kind]++
			line, changed = m[1]+"<MASKED:"+r.kind+">"+m[3], true
		}
	}
	// Una descripción o un comentario de ACL es texto libre: no se toca.
	if freeText.MatchString(line) {
		return line
	}
	line = maskGeneric(line, counts)
	return urlPassword.ReplaceAllStringFunc(line, func(m string) string {
		sm := urlPassword.FindStringSubmatch(m)
		if strings.HasPrefix(sm[2], "<MASKED:") {
			return m
		}
		counts["url-password"]++
		return sm[1] + "<MASKED:url-password>@"
	})
}

// wordLen: largo de la primera palabra (sin recorrer toda la línea).
func wordLen(s string) int {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return i
	}
	return len(s)
}

func isGuard(v string) bool {
	if v == "" || v[0] == '"' {
		return false
	}
	return guardWords[strings.ToLower(v[:wordLen(v)])]
}

var freeText = regexp.MustCompile(`^\s*(?:\d+\s+)?(?:description|remark)\s`)

// Credenciales en una URL (scp://usuario:CLAVE@host/…) en cualquier línea, también en logs.
var urlPassword = regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^/\s:@]+:)(\S+)@`)

// Forma genérica <palabra de secreto> <tipo de cifrado> <valor> en cualquier posición: tapa lo que ninguna regla por
// comando conoce (0 claro; 3, 4, 5, 6, 7, 8 y 9 cifrados o con hash).
var genericHead = regexp.MustCompile(`(?:^|[\s-])(?:password|secret|key|key-string|server-key|authentication-key|pre-shared-key|hex-key|key-octet-string) [03-9] `)

func maskGeneric(line string, counts map[string]int) string {
	var out strings.Builder
	for pos := 0; ; {
		loc := genericHead.FindStringIndex(line[pos:])
		if loc == nil {
			out.WriteString(line[pos:])
			return out.String()
		}
		vs := pos + loc[1] // inicio del valor
		out.WriteString(line[pos:vs])
		rest := line[vs:]
		end := 0
		switch {
		case rest == "" || rest[0] == ' ' || rest[0] == '\t':
		case rest[0] == '"':
			if i := strings.Index(rest[1:], `"`); i >= 0 {
				end = i + 2
			} else {
				end = wordLen(rest)
			}
		default:
			end = wordLen(rest)
			if line[vs-2] == '0' {
				more, _ := tail(rest[end:])
				end += len(more)
			}
		}
		v := rest[:end]
		switch {
		case v == "": // sin valor
		case strings.HasPrefix(v, "<MASKED:") || isGuard(v):
			out.WriteString(v)
		default:
			counts["secret"]++
			out.WriteString("<MASKED:secret>")
		}
		pos = vs + end
	}
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
