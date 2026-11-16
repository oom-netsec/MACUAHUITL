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
	notFn func(line, platform string) bool
	stop  *regexp.Regexp // en tipo 0, la clave llega hasta aquí (sufijo propio del comando); si no, hasta el fin de línea
	guard bool           // si el valor es una palabra clave (md5, use-vrf, default…), la regla no aplica
}

const (
	typ = `(?:[0-9] )?` // tipo de cifrado opcional («0 », «7 »…)
	// El valor es una palabra o una cadena entre comillas (NX-OS: "ab cd"); sigue el resto de la línea.
	val = `("[^"]*"|\S+)(.*)$`
)

// R arma una regla: el prefijo (hasta el valor) es el grupo 1, el valor el 2 y el resto el 3.
func R(kind, block, prefix string) rule {
	return rule{kind: kind, block: block, re: regexp.MustCompile(`(?i)^(` + prefix + `)` + val)}
}

// full arma una regla con la expresión completa (prefijo, valor y resto) para las salidas de show.
func full(kind, expr string) rule { return rule{kind: kind, re: regexp.MustCompile(`(?i)` + expr)} }

func (r rule) unless(not *regexp.Regexp) rule                   { r.not = not; return r }
func (r rule) guarded() rule                                    { r.guard = true; return r }
func (r rule) unlessFn(f func(line, platform string) bool) rule { r.notFn = f; return r }

// stopAt: la clave tipo 0 (con espacios) termina donde empieza el sufijo propio de ESE comando.
func (r rule) stopAt(expr string) rule { r.stop = regexp.MustCompile(`(?i)` + expr); return r }

// Línea de keyring IKEv1: ahí «address/hostname/ipv6» no es la llave.
var keyringLine = regexp.MustCompile(`^\s*pre-shared-key (?:address|hostname|ipv6) \S`)

// HSRP/VRRP con key-chain o sin autenticación: no hay secreto en la línea.
var fhrpNoKey = regexp.MustCompile(`authentication (?:md5 key-chain|none)\b`)

// Comunidad de ASA con tipo de cifrado (0 claro, 8 cifrada).
const commTyp = `(?:[08] )?`

var ipOnly = regexp.MustCompile(`^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:.]*:[0-9a-fA-F:.]*:[0-9a-fA-F:.]*)$`)

// isASASNMPHost: «snmp-server host IFNAME X …» de ASA (interfaz que no es IP y luego el destino), no IOS/NX-OS.
// Con la palabra «community», con una IP tras la interfaz o con trap/poll/version tras el destino es ASA.
func isASASNMPHost(line, platform string) bool {
	f := strings.Fields(strings.ToLower(line))
	if len(f) < 4 || f[0] != "snmp-server" || f[1] != "host" || f[2][0] < 'a' || f[2][0] > 'z' || strings.Contains(f[2], ":") {
		return false
	}
	j := 4
	for j < len(f) && (f[j] == "trap" || f[j] == "poll") {
		j++
	}
	if j < len(f) && f[j] == "community" {
		return true
	}
	switch f[3] {
	case "version", "vrf", "use-vrf", "informs", "inform", "traps", "trap", "poll", "udp-port", "source-interface":
		return false
	}
	if ipOnly.MatchString(f[3]) {
		return platform == "asa" || platform == "ftd" // «host nombre 1.2.3.4» en IOS es una comunidad con forma de IP
	}
	return len(f) > 4 && (f[4] == "trap" || f[4] == "poll" || f[4] == "version")
}

// ISE (ADE-OS): «username U password hash|plain X role …»; la regla de
// IOS tomaría «hash»/«plain» como el valor y dejaría el secreto a la vista.
var iseHashPlain = regexp.MustCompile(`(?i)^\s*username \S+ password (?:hash|plain) \S`)

// Cada regla captura (prefijo)(valor)(resto); solo se reemplaza el valor.
var iosRules = []rule{
	R("enable-secret", "", `\s*enable (?:algorithm-type \S+ )?(?:secret|password) (?:level \d+ )?`+typ),
	R("user-secret", "", `\s*username \S+ (?:.*? )?(?:secret|password) `+typ).unless(iseHashPlain),
	R("snmp-community", "", `\s*snmp-server community `+commTyp).stopAt(`\s+(?:ro|rw)(?:\s+\S+)?\s*$`),
	R("tacacs-key", "", `\s*tacacs-server (?:host \S+ (?:.*? )?)?key `+typ),
	R("radius-key", "", `\s*radius-server (?:host \S+ .*?)?key `+typ),
	R("psk", "", `\s*(?:crypto )?isakmp key `+typ), // ASA anterior a 8.4: «isakmp key X address …»
	// Keyring IKEv1: la llave va tras «key», no tras address/hostname/ipv6.
	R("psk", "", `\s*pre-shared-key (?:address|hostname|ipv6) .*? key `+typ),
	R("psk", "", `\s*pre-shared-key (?:local |remote )?`+typ).unless(keyringLine),
	R("ntp-key", "", `\s*ntp authentication-key \d+ (?:md5|sha\d*|hmac-sha\S*|cmac(?:-aes-128)?) (?:(?:hash|plain) )?`+typ),
	R("snmp-user-auth", "", `\s*snmp-server user .*? auth (?:md5|sha-2 \d+|sha\S*) `),
	R("snmp-user-priv", "", `\s*snmp-server user .*? priv (?:(?:des|3des|aes(?:[- ]\d+)?) )?`),
	// La comunidad va tras vrf/use-vrf, informs/traps y version; use-vrf sin valor no es la comunidad.
	// ASA: «host IFNAME IP [trap|poll] community X»; la IP no es la comunidad.
	R("snmp-community", "", `\s*snmp-server host \S+ \S+ (?:(?:trap|poll) )*community `+commTyp).stopAt(`(?:\s+(?:version (?:1|2c|3)|udp-port \d+))+\s*$`),
	R("snmp-community", "", `\s*snmp-server host-group \S+ \S+ (?:(?:trap|poll) )*community `+commTyp).stopAt(`(?:\s+(?:version (?:1|2c|3)|udp-port \d+))+\s*$`),
	R("snmp-community", "", `\s*snmp-server host \S+ (?:(?:use-)?vrf \S+ )*(?:(?:informs|traps) )?(?:version (?:1|2c|3 (?:auth|noauth|priv)) )?`).guarded().unlessFn(isASASNMPHost),
	R("snmp-community", "", `\s*snmp mib community-map `),
	R("bgp-password", "", `\s*neighbor \S+ password `+typ),
	R("ppp-password", "", `\s*ppp (?:chap password|pap sent-username \S+ password) `+typ),
	R("wifi-psk", "", `\s*(?:\S+ )*?(?:security wpa psk set-key|wpa-psk|set-key) (?:ascii|hex) `+typ),
	R("wifi-psk", "", `\s*psk key `+typ),
	R("fhrp-key", "", `\s*(?:standby|vrrp)(?: \d+)? authentication (?:md5 key-string `+typ+`|text )?`).unless(fhrpNoKey),
	R("fhrp-key", "", `\s*glbp \d+ authentication (?:md5 key-string `+typ+`|text )`),
	R("fhrp-key", "", `\s*authentication (?:text |md5 key-string `+typ+`)`), // NX-OS: anidado bajo hsrp/vrrp/glbp (o suelto en un log)
	R("key-string", "", `\s*key-string `+typ),
	R("tacacs-key", "", `\s*server-private \S+ (?:.*? )?key `+typ),
	R("client-password", "", `\s*ip (?:ftp|http client) password `+typ),
	R("config-key", "", `\s*key config-key password-encrypt(?:ion)? `),
	R("config-key", "", `\s*key config-key password-encrypt(?:ion)? \S+ `), // la clave anterior
	// FTD CLISH: clave de registro y NAT ID del gestor.
	R("manager-regkey", "", `\s*configure manager add \S+ `),
	R("manager-natid", "", `\s*configure manager add \S+ \S+ `),
	R("config-key", "", `\s*key config-key \d+ `),
	R("ospf-key", "", `\s*(?:ip )?ospf authentication-key `+typ),
	R("ospf-key", "", `\s*(?:ip )?ospf message-digest-key \d+ md5 `+typ),
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
	// ASA: passwd, IKEv1/IKEv2, failover, LDAP, EIGRP y licencia inteligente.
	R("enable-secret", "", `\s*passwd `),
	R("psk", "", `\s*(?:ikev1|ikev2 (?:local|remote)-authentication) pre-shared-key `+typ),
	R("failover-key", "", `\s*failover (?:key (?:hex )?|ipsec pre-shared-key )`+typ),
	R("ldap-password", "", `\s*ldap-login-password `+typ),
	R("eigrp-key", "", `\s*eigrp authentication key \d+ `+commTyp).stopAt(`\s+key-id \d+\s*$`),
	R("eigrp-key", "", `\s*authentication key eigrp \d+ `+commTyp).stopAt(`\s+key-id \d+\s*$`),
	R("aaa-key", "aaaserver", `\s+key `+typ),
	R("cluster-key", "cluster", `\s+key `+typ),
	R("radius-key", "", `\s*radius-common-pw `+typ),
	R("user-secret", "", `\s*vpdn username \S+ password `+typ).stopAt(`\s+store-local\s*$`),
	R("aaa-key", "", `\s*aaa-server \S+ (?:\(\S+\) )?host \S+ `).guarded(), // forma de una línea
	R("token", "licsmart", `\s+token `),
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
	// NX-OS en JSON/XML (en cualquier parte de la línea): ver maskStructured.
	full("psk", `^(\s*Pre-[Ss]hared [Kk]ey(?: \(\w+\))?\s*[:=]\s*)(\S.*?)(\s*)$`),
	full("key-string", `^(\s*[Kk]ey \d+ -- text (?:\d+ )?)("[^"]*"|\S+)(.*)$`), // show key chain
	full("fhrp-key", `^(\s*Authentication text, string )("[^"]*"|\S+)(.*)$`),   // show standby / show glbp
	full("vtp-password", `^(\s*VTP Password:\s*)(\S+)(.*)$`),
	full("cts-pac", `^(\s*PAC-Opaque\s*[:=]\s*)(\S+)(.*)$`),
	full("user-secret", `^(\s*Mgmt (?:Password|Secret)\s*[:=]\s*)(\S.*?)(\s*)$`),
	full("dot1x-password", `^(\s*Dot1x Password\s*[:=]\s*)(\S.*?)(\s*)$`),
	// show snmpcommunity de AireOS: nombre en claro, IP, máscara, modo y estado.
	full("snmp-community", `^()(\S+)(\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+(?:Read Only|Read/Write)\s+(?:Enable|Disable)\s*)$`),
	full("wifi-psk", `^(\s*PSK\s*[:=]\s*)(\S.*?)(\s*)$`).guarded(),
	R("tacacs-key", "tacacs", `\s+key `+typ),
	R("radius-key", "radius", `\s+key `+typ),
	R("dot1x-password", "dot1x", `\s+password `+typ),
	R("line-password", "line", `\s+password `+typ),
}

// Palabras que, como valor, no son un secreto sino otra palabra clave del comando (ntp … key 5 prefer, password default…).
var guardWords = map[string]bool{
	"md5": true, "sha1": true, "sha-1": true, "sha-2": true, "sha256": true, "sha-256": true, "sha512": true, "hmac-sha-256": true, "hmac-sha2-256": true, "hmac-sha2-512": true, "cmac-aes-128": true, "cmac": true, "sha2": true, "sha384": true, "sha-384": true, "sha224": true, "sha-224": true, "hmac-sha1": true, "hmac-sha-1": true, "hmac-sha384": true, "hmac-sha2-384": true, "hmac-sha-384": true, "hmac-sha512": true, "hmac-sha-512": true, "hmac-sha2-224": true,
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
		if loc == nil || tailStops[strings.ToLower(strings.TrimSpace(rest[pos+loc[0]:pos+loc[1]]))] || typedWord.MatchString(rest[pos:]) {
			return rest[:end], rest[end:]
		}
		pos += loc[1]
		end = pos
	}
}

var (
	nextToken = regexp.MustCompile(`^\s+\S+`)
	// Otra palabra de secreto con su tipo (… password 0 x secret 0 y): ahí empieza otro valor.
	typedWord = regexp.MustCompile(`(?i)^\s+(?:password|secret|key|key-string) [0-9](?: |$)`)
	typeZero  = regexp.MustCompile(`(?:^|\s)0 $`)
)

var (
	keyBegin  = regexp.MustCompile(`^\s*-----BEGIN .*PRIVATE KEY-----`)
	keyEnd    = regexp.MustCompile(`^\s*-----END .*PRIVATE KEY-----`)
	certChain = regexp.MustCompile(`^crypto pki certificate chain `)
	keyBody   = regexp.MustCompile(`^(?:[A-Za-z0-9+/=]*|Proc-Type: .*|DEK-Info: .*)$`)
)

func blockOf(line string) string {
	line = strings.ToLower(line)
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
	case strings.HasPrefix(line, "crypto pki trustpoint "), strings.HasPrefix(line, "crypto ca trustpoint "):
		return "trustpoint"
	case strings.HasPrefix(line, "cluster group "):
		return "cluster"
	case strings.HasPrefix(line, "aaa-server "):
		return "aaaserver"
	case strings.TrimSpace(line) == "license smart":
		return "licsmart"
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
	return apply(platform, text, (*Stream).Line)
}

// ApplyPlain es Apply sin el corte de union.go: exactamente la cadena de la v0.6.5. Es para quien compone él mismo
// (syslogd) y necesita S1 intacto.
func ApplyPlain(platform, text string) (string, map[string]int) {
	return apply(platform, text, (*Stream).line1)
}

func apply(platform, text string, line func(*Stream, string) (string, bool)) (string, map[string]int) {
	var out strings.Builder
	st := Stream{counts: map[string]int{}, Platform: platform}
	for _, raw := range strings.SplitAfter(text, "\n") {
		if l, ok := line(&st, raw); ok {
			out.WriteString(l)
		}
	}
	return out.String(), st.counts
}

// Stream aplica las reglas línea a línea conservando el estado entre líneas (bloque, llaves y
// cadenas de certificados), para enmascarar una salida que llega por trozos.
type Stream struct {
	block, skip string
	shadow      *Stream  // tras una marca de recorte: la v0.6.5 con la marca como una línea más (ver shadowSpans)
	qblock      string   // bloque de la última línea de configuración citada sin sangría (quoted)
	twin        [][2]int // tramos que taparía la cadena de reglas sobre la copia con los espacios Unicode normalizados (LineS1)
	table       string   // tabla de NX-OS/IOS en curso: "community", "host" o "isakmp"
	rows        int      // filas vistas de la tabla en curso
	n           int
	counts      map[string]int
	// MaxSkip: líneas máximas que se descartan dentro de una llave o cadena sin cierre (0 = sin tope).
	MaxSkip int
	// Platform: la de la salida ("asa", "ios-xe"…); decide formas ambiguas entre plataformas. Vacía = no es ASA.
	Platform string
}

// Line enmascara una línea (con su fin de línea, si lo trae). ok=false: la línea se omite (cuerpo de una llave).
// Es line1 (la v0.6.5) más el corte de los comandos citados (union.go); el estado del flujo lo decide line1.
func (s *Stream) Line(raw string) (string, bool) {
	out, ok := s.LineS1(raw)
	if !ok {
		return out, ok
	}
	return s.CutLine(raw, out), ok
}

// LineS1 es Line sin el corte: la salida de la v0.6.5 (S1) y el estado del flujo. Quien aplica sobre S1 una red por
// contenido propia (la terminal) la corre antes de CutLine: S1 → red M₁ → corte M₂.
func (s *Stream) LineS1(raw string) (string, bool) {
	s.twin = nil
	if isTruncMark(raw) {
		// La marca es transparente para S1 (sombra a), pero la v0.6.5 la ve como una línea más (sombra b): desde aquí corren las
		// dos y cada línea se tapa con la unión de lo que tapan (ver shadowSpans).
		if s.shadow == nil {
			c := *s
			c.counts, c.shadow = map[string]int{}, nil
			s.shadow = &c
		}
		s.shadow.line1(raw)
		return raw, true
	}
	if line, eol := splitEOL(raw); hasHigh(line) {
		// Las reglas de configuración impresa solo ven el espacio ASCII (NBSP entre «api-key» y el valor): se corre la misma
		// cadena sobre la copia normalizada, con el estado de antes de esta línea, y lo que tape se corta sobre S1 en CutLine.
		pre := *s
		pre.counts = map[string]int{}
		s.twin = twinSpans(line, func(n string) string {
			t, _ := pre.line1(n + eol)
			return strings.TrimSuffix(t, eol)
		})
	}
	out, ok := s.line1(raw)
	if s.shadow != nil {
		s.shadowSpans(raw, out, ok)
	}
	return out, ok
}

// shadowSpans corre la sombra b (la v0.6.5 con la marca como una línea más) sobre raw y, si su salida difiere de la de a
// (outA), suma a s.twin lo que b tapa y a no: CutLine lo corta sobre la salida de a. La salida es la unión de a y b; nunca
// muestra más que ref065 con la marca ni sin ella. La sombra solo existe tras una marca (salidas de más de 64 MiB) y dura
// hasta el fin del flujo o el siguiente prompt (Prompted).
func (s *Stream) shadowSpans(raw, outA string, okA bool) {
	line, eol := splitEOL(raw)
	t, okB := s.shadow.line1(raw)
	switch {
	case !okB && okA: // b descarta la línea (cuerpo de una llave): a la deja entera, se tapa entera
		s.twin = append(s.twin, [2]int{0, len(line)})
	case okB && t != outA: // si b tapa lo mismo que a no se suma nada: no se pierde el tipo del marcador ni sube el conteo
		s.twin = append(s.twin, diffSpans(line, strings.TrimSuffix(t, eol))...)
	}
}

// truncMark es la línea fija que el driver inserta al recortar una salida enorme (iosxe.add). No lleva ningún valor, así
// que es transparente: se emite tal cual y no toca el estado (bloque, llave, cadena, tabla), y S1 ve el texto como si no existiera.
var truncMark = regexp.MustCompile(`^\[\x{2026} output truncated: \d+ bytes omitted \x{2026}\]$`)

func isTruncMark(raw string) bool {
	line, _ := splitEOL(raw)
	return truncMark.MatchString(line)
}

// CutLine es el corte de Line sobre s1, la salida (de LineS1, quizá con la red por contenido ya aplicada) de raw.
func (s *Stream) CutLine(raw, s1 string) string {
	if isTruncMark(raw) {
		return s1
	}
	line, eol := splitEOL(raw)
	orig, spans := lineSpans(line, s.Platform)
	spans = mergeSpans(append(spans, s.twin...))
	if strings.HasSuffix(s1, eol) {
		spans = mergeSpans(append(spans, quoteTail(orig, s1[:len(s1)-len(eol)])...))
	}
	if len(spans) == 0 || !strings.HasSuffix(s1, eol) || strings.Contains(s1[:len(s1)-len(eol)], "\n") {
		return s1
	}
	cutOut, n := cut(orig, s1[:len(s1)-len(eol)], spans)
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	s.counts["secret"] += n
	return cutOut + eol
}

func (s *Stream) line1(raw string) (out string, ok bool) {
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
		// Una línea «> …» no es cuerpo PEM, pero tampoco prueba que la llave terminó (prompt de FTD que se cuela).
		if t := strings.TrimSpace(line); keyBody.MatchString(t) || strings.HasPrefix(t, ">") {
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
	return s.quoted(maskLine(line, s.block, s.Platform, s.counts)) + eol, true // las reglas propias primero; lo citado, después
}

// notQuotedCfg: líneas cuyo texto entre comillas no es configuración (texto libre, inventario, imagen de arranque,
// descripciones de show interfaces y del JSON de NX-OS).
var notQuotedCfg = regexp.MustCompile(`(?i)^\s*(?:(?:\d+\s+)?(?:description|remark)[\s:]|"description"\s*:|NAME:\s*"|System image file is)`)

// quoted enmascara lo que una línea de salida cita entre comillas con las mismas reglas que la línea suelta: show tech
// del ASA repite líneas de configuración en sus avisos («*** Output from config line 9, "enable password …"»), y los
// ERROR:/WARNING: y los errores de parser de IOS-XE y NX-OS hacen lo mismo (hueco real visto en CML, 2026-11-14).
// Corre después de las reglas propias de la línea. Las comillas pueden venir impares, sin cerrar, anidadas o escapadas:
// se revisa cada tramo entre dos comillas (los tramos parten la línea: costo lineal) y, una sola vez, todo lo que sigue
// a la primera comilla (la clave puede ir entre comillas dentro de la cita). maskCited, que tapa key/password/secret
// sueltos, solo corre en los tramos que quedan dentro de comillas por paridad y parecen configuración; lo de afuera
// («Interface "outside" key exchange failed») solo pasa por las reglas. Un tramo con sangría hereda el bloque de la
// última línea citada sin sangría, como en la configuración de verdad.
func (s *Stream) quoted(line string) string {
	if strings.Contains(line, `\"`) { // comillas escapadas: son comillas internas de la cita
		line = strings.ReplaceAll(line, `\"`, `"`)
	}
	first := strings.IndexByte(line, '"')
	if first < 0 || notQuotedCfg.MatchString(line) {
		return line
	}
	odd := strings.Count(line, `"`)%2 == 1 // con un total impar, la paridad no dice qué va dentro: maskCited en todos
	var b strings.Builder
	b.WriteString(line[:first+1])
	for k, rest := 0, line[first+1:]; ; k++ {
		seg, next, more := rest, "", false
		if j := strings.IndexByte(rest, '"'); j >= 0 {
			seg, next, more = rest[:j], rest[j+1:], true
		}
		b.WriteString(s.maskQuoted(seg, odd || k%2 == 0))
		if !more {
			break
		}
		b.WriteByte('"')
		rest = next
	}
	out := b.String()
	if tail := out[first+1:]; tail != "" {
		if m := maskLine(tail, s.qblock, s.Platform, s.counts); m != tail {
			out = out[:first+1] + m
		}
	}
	return out
}

// maskQuoted aplica las reglas a un tramo; inside: el tramo va entre comillas (fija el bloque y admite maskCited si
// parece configuración: empieza en minúscula o con sangría; «Press any key to continue» no cambia).
func (s *Stream) maskQuoted(t string, inside bool) string {
	if t == "" {
		return t
	}
	if inside && t[0] != ' ' && t[0] != '\t' {
		s.qblock = blockOf(t)
	}
	out := maskLine(t, s.qblock, s.Platform, s.counts)
	if c := t[0]; inside && (c == ' ' || c == '\t' || c >= 'a' && c <= 'z') {
		out = maskCitedText(out, s.counts)
	}
	return out
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
		// La 1.ª columna es la comunidad aunque las columnas no cuadren o vengan con tabuladores. Una línea con sangría,
		// un «!» o una palabra de primer nivel de la config no es una fila: es lo que sigue a la tabla sin línea en
		// blanco (p. ej. la running-config), y cierra la tabla.
		last := f[0][len(f[0])-1]
		indented := line[0] == ' ' || line[0] == '\t'
		return len(f) <= 4 && last != '#' && (last != '>' || f[0] == ">") && !indented && f[0] != "!" && !configTop[f[0]], false
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
		return maskLine(line, "", s.Platform, s.counts), true
	}
	if !row {
		s.table = ""
		return "", false
	}
	s.rows++
	line = maskLine(line, "", s.Platform, s.counts) // la fila también pasa por las reglas
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
	s.table = ""   // ni una tabla de show sigue abierta tras un prompt
	s.shadow = nil // ni la sombra de una marca de recorte: su tabla tampoco sigue abierta
	s.skip = ""    // un prompt no es cuerpo de llave ni de certificado: lo que esté abierto termina aquí
	if line != "" {
		s.block = blockOf(line)
	}
	if block == "" {
		block = s.block
	}
	return s.quoted(maskLine(" "+line, block, s.Platform, s.counts)[1:])
}

// SetBlock fija el bloque en curso (el que da un prompt); "" = fuera de todo bloque.
func (s *Stream) SetBlock(block string) { s.block = block }

// Typed enmascara una línea tecleada llevando el bloque entre líneas: una línea que abre un bloque
// (aaa-server …, tacacs server …) lo fija para las siguientes, y exit/end lo cierran.
func (s *Stream) Typed(line string) string {
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "exit", "end":
		s.block = ""
	default:
		if b := blockOf(strings.TrimLeft(line, " \t")); b != "" {
			s.block = b
		}
	}
	return s.quoted(maskLine(" "+line, s.block, s.Platform, s.counts)[1:])
}

// Peek enmascara una línea tecleada sobre una copia: ni el bloque ni los contadores de s cambian.
func (s Stream) Peek(line string) string {
	s.counts = nil
	return s.Typed(line)
}

// looseBlocks son los bloques que tienen reglas propias.
var looseBlocks = []string{"line", "aaaserver", "tacacs", "radius", "licsmart", "username", "dot1x", "ezvpn", "trustpoint", "umbrella", "cluster"}

// TypedLoose enmascara una línea tecleada cuyo bloque no confirmó ningún prompt: si el bloque en curso no
// la tapa, la prueba con cada bloque que tenga reglas propias y graba la primera versión que tape algo
// (tapar de más ahí es aceptable).
func (s *Stream) TypedLoose(line string) string {
	out := s.Typed(line)
	if out != line {
		return out
	}
	for _, b := range looseBlocks {
		tmp := Stream{Platform: s.Platform}
		if m := tmp.Prompted(line, b); m != line {
			return m
		}
	}
	return out
}

// archiveLog: línea de show archive log config; tras «|» va un comando de configuración.
// Las líneas de continuación traen solo la barra («|  key X»).
var archiveLog = regexp.MustCompile(`^(\s*\d+\s+\d+\s+\S+\s+\||\s*\|\s)(.*)$`)

// cliHistory: línea numerada de show cli history de NX-OS («  12  09:01:55  comando»; la hora puede faltar).
var cliHistory = regexp.MustCompile(`(?i)^(\s*\d+:?\s+(?:\d\d:\d\d:\d\d\s+)?)([a-z].*)$`)

// loggedCmd: mensaje de syslog (%PARSER-5-CFGLOG_LOGGEDCMD) con el comando de configuración tras «logged command:».
var loggedCmd = regexp.MustCompile(`^(.*logged command:)(.*)$`)

// Otras salidas que repiten configuración: show history all de IOS-XE («CMD: 'comando' hora»), el accounting de
// NX-OS («…:cmd=configure terminal ; snmp-server community X …»), show archive config differences («+línea» / «-línea»)
// y el eco de un comando tras el prompt («R1(config)#enable password X»).
var (
	histCmd    = regexp.MustCompile(`^(\s*CMD: ')(.*)('.*)$`) // hasta el último apóstrofo: el comando puede llevar otros
	acctCmd    = regexp.MustCompile(`^(.*?:cmd=)(.*?)(\s*\((?:SUCCESS|FAILURE)\))?$`)
	diffLine   = regexp.MustCompile(`^( ?[+-])((?i:\s+(?:no|default)\s+)?[a-z].*)$`) // el diff de IOS usa a lo sumo un espacio antes del signo; «- no cmd» con espacio también
	promptEcho = regexp.MustCompile(`^([\w.\-/:]{1,63}(?:\([\w.\-]+\))?[#>] ?)(\S.*)$`)
)

// cmdSyslog: syslogs de ASA/FTD que citan el comando ejecutado (111008, 111009, 111010); el comando va entre comillas.
var cmdSyslog = []*regexp.Regexp{
	regexp.MustCompile(`^(.*%(?:ASA|FTD)-\d-111008: User '.*?' executed the ')(.*)(' command\.?\s*)$`),
	regexp.MustCompile(`^(.*%(?:ASA|FTD)-\d-111010: User '.*?', running '.*?' from IP \S+, executed ')(.*)('\s*)$`),
	regexp.MustCompile(`^(.*%(?:ASA|FTD)-\d-111009: User '.*?' executed cmd: )(.*)()$`),
}

// negada: sangría y uno o más «no»/«default» (en cualquier caja: IOS acepta NO y la terminal guarda lo tecleado); el
// resto es el comando. Se quitan todos de una pasada: «no no no …» no debe volverse cuadrático.
var negada = regexp.MustCompile(`(?i)^(\s*(?:(?:no|default)\s+)+)(\S.*)$`)

// maskLogged tapa un comando citado por un log (CFGLOG, archive log): las reglas y, como el bloque se perdió y el
// comando puede venir abreviado, Command (que no toca una descripción ni un remark).
func maskLogged(cmd, platform string, counts map[string]int) string {
	out, _ := maskCommand(maskLine(cmd, "", platform, counts), counts, false)
	return out
}

// Path enmascara una ruta «sección > línea» (la de iosconf.Node.Path): cada nivel va con su sangría para que valgan las
// reglas de bloque («radius server R > key 7 X»). Devuelve la ruta con <MASKED:tipo> en lugar de los valores.
func Path(platform, path string) string {
	parts := strings.Split(path, " > ")
	var b strings.Builder
	for i, p := range parts {
		b.WriteString(strings.Repeat(" ", min(i, 1)) + p + "\n")
	}
	m, _ := Apply(platform, b.String())
	lines := strings.Split(strings.TrimSuffix(m, "\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimPrefix(lines[i], " ")
	}
	return strings.Join(lines, " > ")
}

// Cmd enmascara un comando suelto del que se perdió su bloque (una línea rechazada, citada en un log): las reglas más
// los key/password/secret/token sueltos. Para quien muestra una línea sin saber de qué sección venía.
// Si trae varias líneas, cada una se procesa por separado.
func Cmd(platform, cmd string) string {
	counts := map[string]int{}
	lines := strings.Split(cmd, "\n")
	for i, l := range lines {
		sp := commandSpans(spLogBlock, l)
		sp = mergeSpans(append(sp, twinSpans(l, func(n string) string { return maskLogged(n, platform, counts) })...)) // las reglas solo ven el espacio ASCII
		lines[i], _ = cut(l, maskLogged(l, platform, counts), sp)
	}
	return strings.Join(lines, "\n")
}

// maskCited tapa en un comando citado los valores tras las palabras de secreto, también abreviadas (ver Command).
func maskCited(cmd string, counts map[string]int) string {
	out, _ := maskCommand(cmd, counts, false)
	return out
}

// maskCitedText es maskCited para un texto entre comillas cualquiera: ahí «token X» es una palabra más.
func maskCitedText(cmd string, counts map[string]int) string {
	out, _ := maskCommand(cmd, counts, true)
	return out
}

// maskLine aplica reglas hasta que ninguna cambie la línea: una línea puede traer
// varios secretos (snmp-server user … auth X priv Y).
func maskLine(line, block, platform string, counts map[string]int) string {
	// «no <comando>» (reversas, scripts de cambio, diffs) lleva el mismo secreto que el comando: se enmascara el resto.
	if m := negada.FindStringSubmatch(line); m != nil {
		ind := m[1][:len(m[1])-len(strings.TrimLeft(m[1], " \t"))]
		return m[1] + maskLine(ind+m[2], block, platform, counts)[len(ind):]
	}
	if m := loggedCmd.FindStringSubmatch(line); m != nil {
		return m[1] + maskLogged(m[2], platform, counts)
	}
	if strings.Contains(line, "-1110") { // filtro barato: las expresiones de cmdSyslog corren por cada línea
		for _, re := range cmdSyslog {
			if m := re.FindStringSubmatch(line); m != nil {
				return m[1] + maskCited(maskLine(m[2], "", platform, counts), counts) + m[3]
			}
		}
	}
	if m := archiveLog.FindStringSubmatch(line); m != nil && !strings.HasSuffix(strings.TrimRight(line, " \t"), "|") { // una fila de tabla markdown termina en «|»
		return m[1] + maskLogged(m[2], platform, counts)
	}
	if m := cliHistory.FindStringSubmatch(line); m != nil && platform == "nx-os" {
		return m[1] + maskLogged(m[2], platform, counts)
	}
	if m := histCmd.FindStringSubmatch(line); m != nil {
		return m[1] + maskCited(maskLine(m[2], "", platform, counts), counts) + m[3]
	}
	if m := acctCmd.FindStringSubmatch(line); m != nil {
		parts := strings.Split(m[2], " ; ")
		for i, p := range parts {
			if !strings.HasPrefix(strings.TrimSpace(p), "show ") { // un show no lleva secretos y su texto («key mypubkey») confunde a maskCited
				parts[i] = maskCited(maskLine(p, "", platform, counts), counts)
			}
		}
		return m[1] + strings.Join(parts, " ; ") + m[3]
	}
	if m := diffLine.FindStringSubmatch(line); m != nil { // fuera de su bloque: maskCited tapa key/password/secret sueltos
		return m[1] + maskCited(maskLine(m[2], "", platform, counts), counts)
	}
	// En AireOS «abc#def  0.0.0.0 …» es una fila de comunidades, no un prompt con eco.
	if m := promptEcho.FindStringSubmatch(line); m != nil && platform != "wlc-aireos" {
		block := ""
		if strings.Contains(m[1], "(config-line)") {
			block = "line"
		}
		return m[1] + maskLine(" "+m[2], block, platform, counts)[1:] // como Typed; sin maskCited: «R1#show crypto key mypubkey rsa» no lleva secreto
	}
	for changed := true; changed; {
		changed = false
		for _, r := range iosRules {
			if r.block != "" && r.block != block || r.not != nil && r.not.MatchString(line) || r.notFn != nil && r.notFn(line, platform) {
				continue
			}
			m := r.re.FindStringSubmatch(line)
			if m == nil || strings.HasPrefix(m[2], "<MASKED:") || m[2] == "*****" || r.guard && isGuard(m[2]) {
				continue
			}
			// En tipo 0 la clave puede llevar espacios: llega hasta el fin de línea o una palabra clave del comando.
			if typeZero.MatchString(m[1]) && m[2][0] != '"' {
				if r.stop != nil {
					m[3] = m[3][r.stopIndex(m[3]):]
				} else {
					_, m[3] = tail(m[3])
				}
			}
			counts[r.kind]++
			line, changed = m[1]+"<MASKED:"+r.kind+">"+m[3], true
		}
	}
	// Una descripción o un comentario de ACL es texto libre: no se toca.
	if freeText.MatchString(line) {
		return line
	}
	line = maskStructured(line, counts)
	line = maskGeneric(line, counts)
	return urlPassword.ReplaceAllStringFunc(line, func(m string) string {
		sm := urlPassword.FindStringSubmatch(m)
		if strings.HasPrefix(sm[2], "<MASKED:") || urlPort.MatchString(sm[2]) {
			return m
		}
		counts["url-password"]++
		return sm[1] + "<MASKED:url-password>@"
	})
}

// Campos de NX-OS (show … | json / xml) que llevan un secreto.
const structFields = `community_name|snmp_community|community|password|passphrase|secret|shared_secret|key|key_string|keystring|pre_shared_key|secname|tacacs_key|radius_key|auth_password|priv_password`

var (
	jsonSecret = regexp.MustCompile(`(?i)("(?:` + structFields + `)"\s*:\s*")([^"]*)(")`)
	// XML con prefijo de namespace («<nf:community_name>») y CDATA; un valor ya tapado empieza con «<» y no casa.
	xmlSecret = regexp.MustCompile(`(?i)(<(?:[\w.-]+:)?(?:` + structFields + `)>\s*(?:<!\[CDATA\[)?)([^<\]\s][^<\]]*?)(\s*(?:\]\]>)?\s*</)`)
)

// maskStructured tapa los campos JSON y XML de secreto en cualquier parte de la línea (NX-OS imprime el JSON compacto
// en una sola línea). shortcut: el valor en la línea siguiente al campo no se cubre (NX-OS no lo imprime así).
func maskStructured(line string, counts map[string]int) string {
	if !strings.ContainsAny(line, `":<`) {
		return line
	}
	sub := func(re *regexp.Regexp) {
		line = re.ReplaceAllStringFunc(line, func(m string) string {
			sm := re.FindStringSubmatch(m)
			if sm[2] == "" || strings.HasPrefix(sm[2], "<MASKED:") {
				return m
			}
			counts["secret"]++
			return sm[1] + "<MASKED:secret>" + sm[3]
		})
	}
	sub(jsonSecret)
	sub(xmlSecret)
	return line
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

var freeText = regexp.MustCompile(`(?i)^\s*(?:\d+\s+)?(?:description|remark)\s`)

// Credenciales en una URL (scp://usuario:CLAVE@host/…) en cualquier línea, también en logs.
// configTop son palabras de primer nivel de la config de NX-OS/IOS que nunca son una fila de show snmp community.
var configTop = map[string]bool{
	"hostname": true, "version": true, "interface": true, "feature": true, "vlan": true, "vrf": true, "username": true,
	"role": true, "snmp-server": true, "ip": true, "ipv6": true, "router": true, "line": true, "boot": true, "ntp": true,
	"logging": true, "aaa": true, "tacacs-server": true, "radius-server": true, "spanning-tree": true,
	"policy-map": true, "class-map": true, "control-plane": true, "system": true, "no": true, "cfs": true,
	"copp": true, "power": true, "show": true, "Cisco": true, "Building": true, "Current": true, "end": true,
}

// urlPort: lo que parece clave en «host:8443/ruta…@x» es un puerto con ruta, no una clave.
var urlPort = regexp.MustCompile(`^\d+/`)

var urlPassword = regexp.MustCompile(`([a-z][a-z0-9+.-]*://[^/\s:@]+:)(\S+)@`)

// Forma genérica <palabra de secreto> <tipo de cifrado> <valor> en cualquier posición: tapa lo que ninguna regla por
// comando conoce (0 claro; 3, 4, 5, 6, 7, 8 y 9 cifrados o con hash).
var genericHead = regexp.MustCompile(`(?i)(?:^|[\s-])(?:password|secret|key|key-string|server-key|authentication-key|pre-shared-key|hex-key|key-octet-string) [03-9] `)

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

// stopIndex: dónde empieza el sufijo propio del comando; si no hay, la clave llega al fin de la línea.
func (r rule) stopIndex(rest string) int {
	if loc := r.stop.FindStringIndex(rest); loc != nil {
		return loc[0]
	}
	return len(rest)
}

// Sintaxis de configuración de AireOS: sin tipo de cifrado; el usuario, índice, IP, puerto y WLAN no se tapan. En el
// modo «(Nombre) config>» se teclea SIN el prefijo «config»: por eso cada regla va dos veces, con «config » en
// cualquier bloque y sin él solo en el bloque «aireconfig» (así el «radius …» suelto de otras plataformas no cambia).
var aireosRules = []struct {
	kind, body string
	skip       func(line, platform string) bool
}{
	{"radius-key", `radius (?:auth|acct) add (?:encrypt )?\d+ \S+ \d+ (?:ascii|hex) `, nil},
	{"radius-key", `radius auth keywrap add (?:ascii|hex) `, nil},
	{"radius-key", `radius auth keywrap add (?:ascii|hex) \S+ `, nil},
	{"tacacs-key", `tacacs (?:auth|acct|athr) add (?:encrypt )?\d+ \S+ \d+ (?:ascii|hex) `, nil},
	{"user-secret", `(?:mgmtuser|netuser) (?:add|password) \S+ `, aireEncrypt},
	{"user-secret", `mgmtuser add encrypt \S+ `, notAireEncrypt},
	{"psk", `mesh security psk provisioning key `, nil},
	{"snmp-community", `snmp community (?:create|delete|mode (?:enable|disable)|accessmode (?:ro|rw)|(?:ipaddr|ipv6addr) \S+ \S+) `, nil},
	{"snmp-user-auth", `snmp v3user create \S+ \S+ \S+ \S+ `, nil},
	{"snmp-user-priv", `snmp v3user create \S+ \S+ \S+ \S+ \S+ `, nil},
	{"user-secret", `local-auth (?:.*? )?password `, nil},
	{"psk", `local-auth method fast server-key `, nil},
	{"user-secret", `ap mgmtuser add username \S+ password `, nil},
	{"user-secret", `ap mgmtuser add username \S+ password \S+ secret `, nil},
	{"dot1x-password", `ap 802\.1Xuser add username \S+ password `, nil},
	{"wifi-psk", `wlan security static-wep-key encryption \d+ \d+ (?:ascii|hex) `, nil},
	{"ldap-password", `ldap simple-bind authenticated \d+ (?:username \S+ password |\S+ )`, nil},
}

func init() {
	for _, r := range aireosRules {
		cfg, bare := R(r.kind, "", `\s*config `+r.body), R(r.kind, "aireconfig", `\s*`+r.body)
		cfg.notFn, bare.notFn = r.skip, r.skip
		iosRules = append(iosRules, cfg, bare)
	}
	// «transfer download|upload password» se teclea en el prompt normal, sin «config».
	iosRules = append(iosRules, R("transfer-password", "", `\s*transfer (?:download|upload) password `), R("transfer-password", "", `\s*transfer download certpassword `))
}

// aireEncrypt: «mgmtuser add encrypt USUARIO CLAVE [read-write|read-only]». Un usuario llamado «encrypt» con la forma
// clásica («add encrypt CLAVE read-only») no cuenta: el nivel de acceso queda en el 4.º lugar.
func aireEncrypt(line, _ string) bool {
	f := strings.Fields(strings.ToLower(line))
	for i, w := range f {
		if w != "mgmtuser" {
			continue
		}
		acc := func(j int) bool { return j < len(f) && (f[j] == "read-write" || f[j] == "read-only") }
		// El eco partido puede traer el nivel a medias («read-»): también cuenta.
		part := func(j int) bool {
			return j < len(f) && (strings.HasPrefix("read-write", f[j]) || strings.HasPrefix("read-only", f[j]))
		}
		return len(f) >= i+5 && f[i+1] == "add" && f[i+2] == "encrypt" && !acc(i+4) && (len(f) == i+5 || part(i+5))
	}
	return false
}

func notAireEncrypt(line, p string) bool { return !aireEncrypt(line, p) }

// ISE: usuarios, claves NTP y usuarios de repositorios con «hash|plain» antes del valor; el usuario, el rol y el índice no se tapan.
var iseRules = []rule{
	R("user-secret", "", `\s*username \S+ password (?:hash|plain) `),
	// SNMPv3: dos claves (autenticación y privacidad) tras hash|plain; cada regla tapa una y la otra regla la otra.
	R("snmp-user-auth", "", `\s*snmp-server user \S+ v3 (?:hash|plain) `),
	R("snmp-user-priv", "", `\s*snmp-server user \S+ v3 (?:hash|plain) \S+ `),
	R("snmp-user-auth", "", `\s*snmp-server host \S+ version 3 \S+ \S+ (?:hash|plain) `),
	R("snmp-user-priv", "", `\s*snmp-server host \S+ version 3 \S+ \S+ (?:hash|plain) \S+ `),
	R("client-password", "", `\s*user \S+ password (?:hash|plain) `), // dentro de «repository NAME»
	// backup, restore, backup-logs y «cli backup …» de una kron policy-list.
	R("backup-key", "", `\s*(?:cli )?(?:backup|restore|backup-logs) (?:.*? )?encryption-key (?:hash|plain) `),
}

func init() { iosRules = append(iosRules, iseRules...) }
