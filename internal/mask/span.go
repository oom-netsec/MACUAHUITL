package mask

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// spKeys: palabras de secreto.
var spKeys = []string{
	"secret", "password", "key", "key-string", "community", "token", "pre-shared-key", "psk", "idtoken", "text",
	"nthash", "authentication-key", "message-digest-key", "auth", "priv", "passphrase",
}

// spDashKeys: palabras con guion que solo se abrevian pasado el primer guion («area-p», no «ar»): una abreviatura más
// corta chocaría con «area 0», «domain name»… Se tapa lo que sigue.
var spDashKeys = []string{
	"area-password", "domain-password", "radius-common-pw", "ldap-login-password", "wpa-psk", "set-key", "password-encryption",
	"auth-password", "priv-password", "shared-secret", "server-key", "enable-password", "login-password", "tunnel-password", "session-key",
}

// Submodos donde IOS acepta «k» por key (el bloque que da el prompt: ver blockOfPrompt de la terminal).
var spShortKeyBlocks = map[string]bool{"tacacs": true, "radius": true, "ezvpn": true}

// spLogBlock: bloque que usan los comandos citados por un log: el prompt se perdió, así que un «k» al inicio es key.
const spLogBlock = "log"

var (
	spToken  = regexp.MustCompile(`"[^"]*"|\S+`)
	spPlain  = regexp.MustCompile(`(?i)^\s*(?:(?:no|default)\s+)*(?:(?:\d+\s+)?(?:description|remark)|banner|alias)\s`)
	spDigits = regexp.MustCompile(`^\d+$`)
	spIface  = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*\d+(?:/\d+)+(?:\.\d+)?$`)
	// Palabras que siguen a key/password pero son parte del comando, no el valor.
	spNotSecret = map[string]bool{"chain": true, "generate": true, "zeroize": true, "config-key": true, "export": true, "import": true, "exchange": true, "add": true, "delete": true, "keywrap": true}
)

func spPrefix(word, w string, min int) bool { return len(w) >= min && strings.HasPrefix(word, w) }

// spKeyword dice si w es una palabra de secreto o su abreviatura (2 o más letras; «k» en los submodos de
// spShortKeyBlocks y, en un comando citado, al inicio del comando).
func spKeyword(w string, noToken bool, block string, isFirst bool) bool {
	w = strings.ToLower(w)
	if w == "pkcs12" { // «crypto ca export TP pkcs12 [ARCHIVO] FRASE»: la frase va tras la palabra
		return true
	}
	if w == "k" {
		return spShortKeyBlocks[block] || isFirst
	}
	if len(w) < 2 || w == "authentication" || w == "message-digest" { // palabras del comando, no del secreto
		return false
	}
	dash := strings.Contains(w, "-")
	for _, k := range spKeys {
		if (strings.HasPrefix(k, w) || dash && hyphenPrefix(k, w)) && !(noToken && k == "token") {
			return true
		}
	}
	for _, k := range spDashKeys {
		if i := strings.IndexByte(k, '-'); dash && hyphenPrefix(k, w) || strings.HasPrefix(k, w) && len(w) > i {
			return true
		}
	}
	return false
}

// spProse: palabras que, tras una palabra de secreto, delatan prosa de un aviso y no un comando («password mismatch for
// user», «key changed»). Solo se miran en el texto citado entre comillas.
var spProse = map[string]bool{"mismatch": true, "failed": true, "expired": true, "rejected": true, "changed": true, "will": true,
	"is": true, "has": true, "for": true, "from": true, "to": true, "not": true, "was": true, "must": true, "cannot": true,
	"invalid": true, "required": true, "missing": true, "incorrect": true, "does": true}

// commandSpans devuelve, para un comando tecleado o citado, los tramos [s, t) del original que Command tapa: desde el
// valor (el token que sigue a la palabra de secreto) hasta el fin de la línea. No combina nada con las reglas: de eso se
// encarga cut.
func commandSpans(block, cmd string) [][2]int {
	sp := spansIn(block, cmd, false)
	if n := normSpaces(cmd); n != cmd { // IOS toma el NBSP como parte del token: se prueba el original y la copia, y se juntan
		sp = mergeSpans(append(sp, spansIn(block, n, false)...))
	}
	return sp
}

// spansIn es commandSpans; quoted: cmd es un texto citado entre comillas («token X» es una palabra más y la prosa de la
// lista spProse no es un comando).
//
// Cada segmento « ; » se evalúa por separado para reconocer su primer comando (los anteriores al de la palabra de secreto
// quedan visibles), pero el primer tramo se alarga hasta el fin de la línea, también en NX-OS e ISE: ahí « ; » separa
// comandos, y lo que sigue a un « ; » dentro de un valor («password abc ; def») es el resto del secreto; adivinar dónde
// termina falla hacia el lado de mostrar. Costo aceptado: no se ven los comandos posteriores al secreto.
func spansIn(block, cmd string, quoted bool) (spans [][2]int) {
	pos := 0
	segs := strings.Split(cmd, spSep)
	for i, seg := range segs {
		sp := spansSeg(block, seg, quoted)
		if len(sp) == 0 && i < len(segs)-1 && !(quoted && spProse[strings.ToLower(firstField(segs[i+1]))]) {
			// el segmento termina en una palabra de secreto sin valor («password ; X»): lo que sigue al « ; » es el valor;
			// en una cita, «password ; is wrong» es prosa
			if d := spansSeg(block, seg+" X", quoted); len(d) > 0 && d[len(d)-1][0] == len(seg)+1 {
				sp = [][2]int{{len(seg), len(seg)}}
			}
		}
		spans = append(spans, shiftSpans(sp, pos)...)
		pos += len(seg) + len(spSep)
	}
	if len(spans) > 0 {
		spans = [][2]int{{spans[0][0], len(cmd)}}
	}
	return spans
}

func spansSeg(block, cmd string, quoted bool) (spans [][2]int) {
	toks := spToken.FindAllStringIndex(cmd, -1)
	n := len(toks) // las palabras de secreto se buscan hasta la barra; el valor, una vez hallada la palabra, llega al fin
	for i, t := range toks {
		if cmd[t[0]:t[1]] == "|" { // lo que sigue a la barra es un filtro de un show, no un secreto; en un comando con secreto no hay filtro
			n = i
			break
		}
	}
	if t := toks[max(len(toks)-1, 0):]; quoted && len(t) == 1 && t[0][1]-t[0][0] > 1 && cmd[t[0][1]-1] == '"' && cmd[t[0][0]] != '"' { // la comilla que cierra la cita no es del último token
		t[0][1]--
	}
	tok := func(i int) string { return cmd[toks[i][0]:toks[i][1]] }
	low := func(i int) string { return strings.ToLower(tok(i)) }
	first := 0
	if n > 0 && strings.EqualFold(tok(0), "do") {
		first = 1
	}
	for first < n && (strings.EqualFold(tok(first), "no") || strings.EqualFold(tok(first), "default")) { // «no show …»: el comando es lo que sigue
		first++
	}
	if first < n && len(tok(first)) >= 2 && strings.HasPrefix("show", low(first)) || spPlain.MatchString(cmd) {
		return nil
	}
	if first < n {
		fam := low(first) // primera palabra del comando
		// «int te 1/0/1» y «snmp-server group G v3 priv read V» no llevan secretos: «te»/«se»/«priv» no son palabras clave ahí.
		if spPrefix("interface", fam, 3) || spPrefix("snmp-server", fam, 6) && first+1 < n && spPrefix("group", low(first+1), 2) {
			return nil
		}
	}
	// FTD: «configure manager add HOST CLAVE [ID]» y «configure user add USUARIO CLAVE»: la clave va por posición.
	if first+4 < n && spPrefix("configure", low(first), 4) && spPrefix("add", low(first+2), 2) && (spPrefix("manager", low(first+1), 3) || spPrefix("user", low(first+1), 3)) {
		if onlyMasked(cmd, toks[first+4:]) {
			return nil
		}
		return [][2]int{{toks[first+4][0], toks[n-1][1]}}
	}
	host := first+3 < n && spPrefix("snmp-server", low(first), 6) && spPrefix("host", low(first+1), 2) && ipOnly.MatchString(tok(first+2))
	for i := first; i < n; i++ {
		// «snmp-server host IP …»: la community va por posición (tras vrf, informs, version…): se tapa todo lo que sigue a la IP.
		// «tacacs-server k X»: IOS acepta «k» por key justo tras tacacs-server o radius-server.
		// «ip nhrp authentication X»: ahí «authentication» sí lleva el secreto.
		// «standby 1 authentication X» / «glbp 1 authentication X»: igual, tras el número de grupo.
		nhrp := i == first+2 && spPrefix("authentication", low(i), 4) && (spPrefix("nhrp", low(first+1), 2) ||
			(spPrefix("standby", low(first), 3) || spPrefix("glbp", low(first), 2)) && spDigits.MatchString(tok(first+1)))
		short := i == first+1 && low(i) == "k" && (spPrefix("tacacs-server", low(first), 3) || spPrefix("radius-server", low(first), 3))
		if !(host && i == first+2) && !short && !nhrp && (!spKeyword(tok(i), quoted && !spPrefix("license", low(first), 3), block, i == first) || notKeyword(low, tok, i, first, n, block)) {
			continue
		}
		j := i + 1
		if j >= n || notSecretValue(low, i, j, first, n) || quoted && spProse[low(j)] {
			continue
		}
		e := len(toks)                  // hasta el fin del segmento, también pasada una barra o un « ; » (con split, el segmento ya no los trae)
		if onlyMasked(cmd, toks[j:e]) { // el único valor ya está tapado (con su tipo)
			i = e - 1
			continue
		}
		end := toks[e-1][1]
		if strings.Count(cmd[toks[j][0]:end], `"`)%2 == 1 && end-1 > toks[j][0] && cmd[end-1] == '"' { // la comilla que cierra un texto citado no es del valor
			end--
		}
		spans = append(spans, [2]int{toks[j][0], end})
		i = e - 1
	}
	return spans
}

// spSkip: palabras que siguen a una palabra de secreto pero son estructura del comando y no el valor: algoritmos,
// tipos de cifrado y las palabras de lo que viene después del valor. Las que llevan número detrás (level, timeout…)
// se saltan junto con él.
var (
	spAlgo = map[string]bool{"md5": true, "des": true, "3des": true, "128": true, "192": true, "256": true, "hex": true, "ascii": true,
		"encrypted": true, "hash": true, "plain": true, "pbkdf2": true, "scrypt": true, "aes": true, "aes-128": true, "aes-192": true, "aes-256": true}
	spStruct = map[string]bool{"inform": true, "informs": true, "traps": true, "trap": true, "poll": true, "ro": true, "rw": true, "role": true, "address": true, "hostname": true, "network-admin": true, "network-operator": true,
		"network-user": true, "vdc-admin": true, "vdc-operator": true, "level-1": true, "level-2": true, "level-1-2": true, "localizedkey": true, "view": true,
		"group": true, "prefer": true, "encryption": true, "key-id": true, "single-connection": true}
	spStructNum = map[string]bool{"level": true, "timeout": true, "access": true, "privilege": true, "priv": true, "port": true, "auth-port": true,
		"acct-port": true, "udp-port": true, "retransmit": true, "expire": true, "key-id": true, "vrf": true, "use-vrf": true, "version": true}
)

// structWord: w es una de las palabras de m o su abreviatura (2 o más letras): IOS acepta «lev 5», «vers 2c», «asc».
func structWord(w string, m map[string]bool) bool {
	if m[w] {
		return true
	}
	if len(w) < 2 {
		return false
	}
	for k := range m {
		if strings.HasPrefix(k, w) {
			return true
		}
	}
	return false
}

// spAlgoExacto: algoritmos de verdad (no cualquier palabra que empiece con sha, aes o hmac: «Shadow2024x» es una contraseña).
var spAlgoExacto = regexp.MustCompile(`(?i)^(?:sha(?:-?(?:1|2|224|256|384|512))?|hmac-?(?:md5|sha(?:-?(?:1|2|224|256|384|512))?(?:-(?:256|384|512))?)(?:-96)?|aes-?(?:128|192|256)(?:-cmac)?|cmac(?:-aes-128)?)$`)

// SecretValue es un valor que Command tapó, para que la terminal tape su repetición por contenido. Primary: el primer valor
// de un secreto (no se desaloja de la lista antes que las palabras que lo siguen). Persist: sigue vigente tras el prompt sin
// pendientes (la frase de un secreto de varias palabras y sus palabras que no son minúsculas puras).
type SecretValue struct {
	Text             string
	Primary, Persist bool
}

// secretGroups: los valores de un tramo, cada uno como la lista de sus palabras. Un valor es el primer token tras una
// palabra de secreto que no sea un tipo (0-9), un algoritmo, otra palabra de secreto ni estructura del comando y que sirva
// para tapar su repetición (spValue); si le siguen más palabras (tipo 0 con espacios: «Pa55w0rd Xq7z9») son del mismo valor
// hasta la primera palabra estructural o de secreto. Pasada una estructura («RO», «view V», «timeout 5») ya no se recuerda
// nada hasta la siguiente palabra de secreto: «VIEWALL» o «ACL_SNMP» no son el secreto.
func secretGroups(span string) (groups [][]string) {
	toks := spToken.FindAllString(span, -1)
	armed, have := true, false
	for i := 0; i < len(toks); {
		w := strings.ToLower(toks[i])
		switch {
		case spKeyword(w, false, spLogBlock, false), localRemote(w):
			armed, have = true, false
			i++
			continue
		case len(w) == 1 && w[0] >= '0' && w[0] <= '9', structWord(w, spAlgo), spAlgoExacto.MatchString(w):
			i++
			continue
		case structWord(w, spStruct):
			armed = armed && !have
			i++
			continue
		case structWord(w, spStructNum):
			armed = armed && !have
			i += 2
			continue
		}
		v := strings.Trim(toks[i], `"`)
		if !armed || !spValue(v) { // un número corto, una IP o una interfaz no es el valor: se sigue buscando
			i++
			continue
		}
		g := []string{v}
		j := i + 1
		for ; j < len(toks); j++ {
			t := strings.ToLower(toks[j])
			if spKeyword(t, false, spLogBlock, false) || localRemote(t) || spStruct[t] || spStructNum[t] || spNotSecret[t] || len(t) >= 3 && (structWord(t, spStruct) || structWord(t, spStructNum)) {
				break
			}
			g = append(g, strings.Trim(toks[j], `"`))
		}
		for len(g) > 1 && !spValue(g[len(g)-1]) && (spDigits.MatchString(g[len(g)-1]) || ipOnly.MatchString(g[len(g)-1])) { // «X 7», «X 10»: el tipo o el ACL que sigue no es del valor
			g = g[:len(g)-1]
		}
		groups = append(groups, g)
		have = true
		i = j
	}
	return groups
}

var pureLower = regexp.MustCompile(`^[a-z]+$`)

// SecretValuesV devuelve los valores de un tramo con sus marcas; firstOnly: solo el primero («snmp-server host IP … COMM
// config syslog…»: lo que sigue a la community son opciones, no secretos).
func SecretValuesV(span string, firstOnly bool) (out []SecretValue) {
	for gi, g := range secretGroups(span) {
		if firstOnly && gi > 0 {
			break
		}
		if firstOnly {
			g = g[:1] // solo la community, no las opciones que le siguen
		}
		if len(g) > 1 {
			out = append(out, SecretValue{Text: strings.Join(g, " "), Primary: true, Persist: gi == 0}) // solo la frase del primer valor: lo que sigue a una palabra de secreto en medio es otro valor
		}
		for k, w := range g {
			if spValue(w) {
				out = append(out, SecretValue{Text: w, Primary: k == 0, Persist: len(g) > 1 && !pureLower.MatchString(w)})
			}
		}
	}
	return out
}

// SecretValues son las palabras de SecretValuesV (sin la frase).
func SecretValues(span string) []string {
	var vals []string
	for _, g := range secretGroups(span) {
		for _, w := range g {
			if spValue(w) {
				vals = append(vals, w)
			}
		}
	}
	return vals
}

// onlyMasked: el valor ya viene tapado: el tramo empieza con un <MASKED:…> (a lo sumo tras un número de tipo de cifrado).
// Lo que siga lo dejó una pasada anterior; así una segunda pasada no cambia nada.
func onlyMasked(cmd string, toks [][]int) bool {
	w := func(i int) string { return cmd[toks[i][0]:toks[i][1]] }
	if len(toks) > 1 && len(w(0)) == 1 && spDigits.MatchString(w(0)) {
		return strings.HasPrefix(w(1), "<MASKED:")
	}
	return strings.HasPrefix(w(0), "<MASKED:")
}

// spValue: v sirve para tapar su repetición por contenido: 4 o más caracteres y no un número de menos de 8 dígitos,
// una IP ni una interfaz.
func spValue(v string) bool {
	if len(v) < 4 || strings.HasPrefix(v, "<MASKED:") || spDigits.MatchString(v) && len(v) < 8 || spIface.MatchString(v) {
		return false
	}
	_, err := netip.ParseAddr(v)
	return err != nil
}

// notKeyword: la palabra i parece de secreto pero en ese comando no lo es (route-map, prioridades, número de túnel o de
// llave de un key chain).
func notKeyword(low func(int) string, tok func(int) string, i, first, n int, block string) bool {
	lw := low(i)
	next := func() bool { return i+1 < n && spDigits.MatchString(tok(i+1)) }
	switch {
	case i > first && spPrefix("community", lw, 2) && (low(i-1) == "set" || spPrefix("match", low(i-1), 3)):
		return true // route-map: comunidad de BGP
	case spPrefix("priv", lw, 2) && next():
		return true // prioridad (stp, standby, vrrp, glbp) o «username u pri 15»: un número tras pri/priv no es secreto
	case i > first && spPrefix("key", lw, 1) && spPrefix("tunnel", low(i-1), 3) && next():
		return true // número de clave del túnel
	case i > first+1 && spPrefix("key", lw, 1) && next() && spPrefix("ntp", low(first), 2) && (spPrefix("server", low(first+1), 1) || spPrefix("peer", low(first+1), 1)):
		return true // «ntp server IP key N»: N es el número de llave, no el secreto
	case block == "keychain" && spPrefix("key", lw, 2) && next() && i+2 == n:
		return true // «key N» en un key chain: el número de llave; el secreto es key-string
	}
	return false
}

// notSecretValue: el token j, tras la palabra clave i, es parte del comando y no el valor.
func notSecretValue(low func(int) string, i, j, first, n int) bool {
	lv := low(j)
	switch {
	case spNotSecret[lv]:
		return true
	case lv == "encryption": // «password encryption aes»
		return j+1 < n && low(j+1) == "aes"
	case lv == "storage": // «crypto key storage nvram:»
		return i > first && spPrefix("crypto", low(i-1), 3)
	case spPrefix("config-key", lv, 3): // «key con password-e X»: el valor viene después
		return j+1 < n && strings.HasPrefix(low(j+1), "password-e")
	}
	return false
}

// localRemote: «local»/«remote» (o su abreviatura) separan las dos llaves de «pre-shared-key local X remote Y».
func localRemote(w string) bool {
	return len(w) >= 2 && (strings.HasPrefix("local", w) || strings.HasPrefix("remote", w))
}

// normSpaces devuelve una copia de s con cada espacio Unicode (NBSP, U+2000–U+200A, U+202F, U+205F, U+3000, U+1680,
// U+0085…) y cada carácter invisible de ancho cero (ZWSP, ZWNJ, ZWJ, U+2060, BOM) cambiado por tantos espacios ASCII
// como bytes ocupa: los índices del original siguen valiendo. \s y \S de RE2 solo conocen el espacio ASCII, y un
// valor pegado desde Word, Confluence o un correo trae NBSP entre la palabra clave y el valor. Solo para calcular
// tramos (M₂, que únicamente agrega cortes): lo que ve la cadena de la v0.6.5 no cambia.
func normSpaces(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		if r != utf8.RuneError && (unicode.IsSpace(r) || r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF) {
			b.WriteString(strings.Repeat(" ", w))
		} else {
			b.WriteString(s[i : i+w])
		}
		i += w
	}
	return b.String()
}

// normOne es normSpaces con un solo espacio ASCII por cada espacio Unicode (las reglas de la v0.6.5 piden uno): la copia ya
// no tiene el largo del original, así que devuelve también el desplazamiento en s de cada byte de la copia (con uno más al
// final, el largo de s).
func normOne(s string) (string, []int) {
	var b strings.Builder
	idx := make([]int, 0, len(s)+1)
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		if r != utf8.RuneError && (unicode.IsSpace(r) || r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF) {
			b.WriteByte(' ')
			idx = append(idx, i)
		} else {
			b.WriteString(s[i : i+w])
			for k := 0; k < w; k++ {
				idx = append(idx, i+k)
			}
		}
		i += w
	}
	return b.String(), append(idx, len(s))
}

// twinSpans: los tramos de orig que la cadena de reglas taparía si vieran los espacios Unicode como un espacio ASCII: corre
// chain sobre la copia (normOne) y lleva lo que cambió de vuelta a las coordenadas de orig.
func twinSpans(orig string, chain func(string) string) [][2]int {
	if !hasHigh(orig) {
		return nil
	}
	n, idx := normOne(orig)
	if n == orig {
		return nil
	}
	sp := diffSpans(n, chain(n))
	for i := range sp {
		// Hasta los bordes de la palabra: el desescape de «\"» en la cadena también cuenta como cambio, y un tramo a
		// media palabra dejaba que la 2.ª pasada tapara la palabra entera (fuzz). Así se tapa de más, nunca de menos.
		a, b := idx[sp[i][0]], idx[sp[i][1]]
		for a > 0 {
			r, n := utf8.DecodeLastRuneInString(orig[:a])
			if unicode.IsSpace(r) {
				break
			}
			a -= n
		}
		for b < len(orig) {
			r, n := utf8.DecodeRuneInString(orig[b:])
			if unicode.IsSpace(r) {
				break
			}
			b += n
		}
		sp[i] = [2]int{a, b}
	}
	return sp
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return strings.Trim(f[0], `"'`)
	}
	return ""
}
