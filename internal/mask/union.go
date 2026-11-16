package mask

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Corte sobre la v0.6.5 (docs/plans/2026-11-15-enmascarado-union.md). La salida de la cadena de reglas (S1) nunca se
// toca: lo que ve Command en el texto original (los tramos) se resuelve reemplazando por un <MASKED:secret> la región
// de S1 que corresponde. Todo lo que S1 tapa sigue tapado; solo se tapa más. La combinación vive aquí y solo aquí.

const spSep = " ; "

var (
	maskedMarker = regexp.MustCompile(`<MASKED:[^>]*>`)
	cutCard      = "<MASKED:secret>"
)

// lcp y lcs: largo del prefijo y del sufijo común de a y b.
func lcp(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

func lcs(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	return i
}

// cut devuelve s1 con la región que corresponde a los tramos (en orig) cambiada por un <MASKED:secret>, y cuántos
// cortes hizo (los que no estaban ya tapados del todo). Con la misma cantidad de « ; » en orig y s1 se corta por
// segmento; si no, un solo corte del primer tramo al último.
func cut(orig, s1 string, spans [][2]int) (string, int) {
	if len(spans) == 0 {
		return s1, 0
	}
	spans = mergeSpans(spans)
	if k := strings.Count(orig, spSep); k > 0 && k == strings.Count(s1, spSep) {
		os, ss := strings.Split(orig, spSep), strings.Split(s1, spSep)
		pos, total, j := 0, 0, 0
		for i := range os {
			lo, hi, toEOL := -1, -1, false
			end := pos + len(os[i])
			// Los tramos vienen ordenados y sin cruzarse (mergeSpans): los que terminaron antes de este segmento ya no sirven.
			for j < len(spans) && spans[j][1] <= pos {
				j++
			}
			for k := j; k < len(spans) && spans[k][0] < end; k++ {
				sp := spans[k]
				if a, b := max(sp[0], pos), min(sp[1], end); a < b {
					if lo < 0 || a-pos < lo {
						lo = a - pos
					}
					hi = max(hi, b-pos)
					toEOL = toEOL || sp[1] > end && sp[1] == len(orig)
				}
			}
			if lo >= 0 && toEOL { // el tramo llega al fin de la línea: lo que sigue a un « ; » es el resto del secreto
				tail, n := cutOne(strings.Join(os[i:], spSep), strings.Join(ss[i:], spSep), lo, len(orig)-pos)
				return strings.Join(append(ss[:i:i], tail), spSep), total + n
			}
			if lo >= 0 {
				var n int
				ss[i], n = cutOne(os[i], ss[i], lo, hi)
				total += n
			}
			pos += len(os[i]) + len(spSep)
		}
		return strings.Join(ss, spSep), total
	}
	lo, hi := spans[0][0], spans[0][1]
	for _, sp := range spans {
		lo, hi = min(lo, sp[0]), max(hi, sp[1])
	}
	return cutOne(orig, s1, lo, hi)
}

// cutOne corta s (la salida de las reglas sobre o) donde estaba o[a:b].
func cutOne(o, s string, a, b int) (string, int) {
	c := min(a, lcp(o, s))
	e := min(len(s), max(len(s)-(len(o)-b), len(s)-lcs(o, s)))
	e = max(e, c)
	// Primero UTF-8 y después marcadores: el ajuste de marcadores solo mueve a bordes ASCII («<», «>»), que ya son inicio de runa;
	// al revés, un byte de continuación pegado a un marcador devolvía c al «>» y lo partía.
	for c > 0 && c < len(s) && !utf8.RuneStart(s[c]) {
		c--
	}
	for e < len(s) && !utf8.RuneStart(s[e]) {
		e++
	}
	for _, m := range maskedMarker.FindAllStringIndex(s, -1) { // no se parte un <MASKED:…>
		if m[0] < c && c < m[1] {
			c = m[0]
		}
		if m[0] < e && e < m[1] {
			e = m[1]
		}
	}
	if tapado(s[c:e]) {
		return s, 0
	}
	return s[:c] + cutCard + s[e:], 1
}

// tapado: la región ya es solo marcadores (y a lo sumo el número de tipo de cifrado de un solo dígito).
func tapado(region string) bool {
	for _, w := range strings.Fields(maskedMarker.ReplaceAllString(region, "")) {
		if len(w) != 1 || w[0] < '0' || w[0] > '9' {
			return false
		}
	}
	return true
}

// shiftSpans mueve los tramos de un trozo a las coordenadas del texto completo.
func shiftSpans(sp [][2]int, by int) [][2]int {
	for i := range sp {
		sp[i][0] += by
		sp[i][1] += by
	}
	return sp
}

// mergeSpans ordena los tramos y junta los que se tocan.
func mergeSpans(sp [][2]int) [][2]int {
	sort.Slice(sp, func(i, j int) bool { return sp[i][0] < sp[j][0] })
	out := sp[:0]
	for _, x := range sp {
		if n := len(out); n > 0 && x[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], x[1])
		} else {
			out = append(out, x)
		}
	}
	return out
}

// loggedSpans: los tramos de line que son un comando citado por un log. Usa las mismas expresiones y el mismo orden que
// maskLine, pero sobre el original, sin tocar nada.
func loggedSpans(line, platform string) [][2]int {
	if m := negada.FindStringSubmatchIndex(line); m != nil {
		ind := line[m[2]:m[3]]
		ind = ind[:len(ind)-len(strings.TrimLeft(ind, " \t"))]
		return shiftSpans(loggedSpans(ind+line[m[4]:], platform), m[4]-len(ind))
	}
	at := func(m []int) [][2]int {
		return shiftSpans(spansIn(spLogBlock, line[m[4]:m[5]], false), m[4])
	}
	if m := loggedCmd.FindStringSubmatchIndex(line); m != nil {
		return at(m)
	}
	if strings.Contains(line, "-1110") {
		for _, re := range cmdSyslog {
			if m := re.FindStringSubmatchIndex(line); m != nil {
				return at(m)
			}
		}
		// Sin el cierre «' command.» (mensaje truncado o mal formado) el comando citado llega hasta el fin de la línea.
		for _, re := range cmdSyslogOpen {
			if m := re.FindStringSubmatchIndex(line); m != nil {
				return at(m)
			}
		}
	}
	if m := archiveLog.FindStringSubmatchIndex(line); m != nil && !strings.HasSuffix(strings.TrimRight(line, " \t"), "|") {
		return at(m)
	}
	if m := cliHistory.FindStringSubmatchIndex(line); m != nil && platform == "nx-os" {
		return at(m)
	}
	for _, re := range []*regexp.Regexp{histCmd, acctCmd, diffLine, diffLineM2} {
		if m := re.FindStringSubmatchIndex(line); m != nil {
			return at(m)
		}
	}
	return nil
}

// quotedSpans: los tramos de line que son texto citado entre comillas (ver Stream.quoted): cada tramo de dentro y, con
// un total impar de comillas, todo lo que sigue a la primera.
func quotedSpans(line string) [][2]int { return quotedSpansQ(line, '"') }

var apostrophe = regexp.MustCompile(`[A-Za-z0-9]'[A-Za-z0-9]`)

// quotedSpansQ es quotedSpans con la comilla q (la simple también cita: «% Ambiguous command: 'tac k X'»).
func quotedSpansQ(line string, q byte) (spans [][2]int) {
	if q == '\'' { // un apóstrofo entre dos letras («Don't», «user's») es parte de la palabra, no una comilla
		line = apostrophe.ReplaceAllStringFunc(line, func(m string) string { return m[:1] + "_" + m[2:] })
	}
	first := strings.IndexByte(line, q)
	if first < 0 || notQuotedCfg.MatchString(line) {
		return nil
	}
	qs := string(q)
	if strings.Count(line, qs)%2 == 1 {
		return shiftSpans(spansIn("", line[first+1:], true), first+1)
	}
	pos := first + 1
	for k := 0; pos <= len(line); k++ {
		end := len(line)
		if j := strings.IndexByte(line[pos:], q); j >= 0 {
			end = pos + j
		}
		if seg := line[pos:end]; k%2 == 0 {
			sp := spansIn("", seg, true)
			reach := len(sp) > 0 && sp[len(sp)-1][1] == len(seg) // antes de mover los tramos
			spans = append(spans, shiftSpans(sp, pos)...)
			// El valor trae comillas propias («enable secret "x y"», «secret x"y»): la comilla que cierra el tramo lo abre.
			if end+1 < len(line) && (len(sp) > 0 && (strings.HasSuffix(seg, " ") || reach && !strings.ContainsRune(" \t,;)}]:.", rune(line[end+1]))) ||
				len(sp) == 0 && strings.HasSuffix(seg, " ") && endsInKeyword(seg)) {
				spans = append(spans, [2]int{end, len(line)})
			}
		}
		pos = end + 1
	}
	return spans
}

// lineSpans: el texto original de una línea de salida (con las comillas escapadas como las deja Stream.quoted) y los
// tramos de comando que contiene.
func lineSpans(line, platform string) (string, [][2]int) {
	if strings.Contains(line, `\"`) {
		line = strings.ReplaceAll(line, `\"`, `"`)
	}
	// Los tramos salen del original y de la copia con los espacios Unicode normalizados (mismos índices): IOS toma el NBSP
	// como parte del token, así que un valor puede llevarlo adentro. Se juntan; el corte es sobre el original.
	spansOf := func(t string) [][2]int {
		sp := loggedSpans(t, platform)
		if quotedCmdLine.MatchString(t) { // M₂ solo actúa sobre comandos: las demás comillas de un show quedan como en la v0.6.5
			sp = append(sp, quotedSpans(t)...)
			sp = append(sp, quotedSpansQ(t, '\'')...)
		}
		return sp
	}
	sp := spansOf(line)
	if n := normSpaces(line); n != line {
		sp = append(sp, spansOf(n)...)
	}
	return line, mergeSpans(sp)
}

// quotedCmdLine: las líneas de salida cuyo texto entre comillas cita un comando: el aviso de show tech del ASA
// («*** Output from config line N, "…"») y los ERROR:/WARNING:/INFO:. Los syslog 1110xx y las demás vías de log ya
// los resuelve loggedSpans.
var quotedCmdLine = regexp.MustCompile(`Output from config line|(?i:\b(?:error|warning|info):)|% (?:Ambiguous command|Invalid input detected|Unknown command)`)

// CutCommand es el corte para un comando tecleado (con el bloque del prompt): s1 es lo que la cadena de reglas dejó de
// orig; devuelve s1 con lo que Command tapa y los valores tapados (para tapar su repetición por contenido).
func CutCommand(block, orig, s1 string) (string, []string) {
	out, vs := CutCommandV(block, orig, s1)
	vals := make([]string, len(vs))
	for i, v := range vs {
		vals[i] = v.Text
	}
	return out, vals
}

// hostCmd: «snmp-server host IP …»: tras la community van opciones, no más secretos.
var hostCmd = regexp.MustCompile(`(?i)^\s*(?:do\s+)?(?:(?:no|default)\s+)*snmp-s\S*\s+ho`)

// CutCommandV es CutCommand con las marcas de cada valor (SecretValue).
func CutCommandV(block, orig, s1 string) (string, []SecretValue) {
	if strings.Contains(orig, `\"`) {
		orig = strings.ReplaceAll(orig, `\"`, `"`)
	}
	n := normSpaces(orig) // mismos índices que orig: los tramos y los valores salen de los dos textos
	spans := append(commandSpans(block, orig), quotedSpans(orig)...)
	if n != orig {
		spans = append(spans, quotedSpans(n)...) // commandSpans ya probó la copia
	}
	// las reglas solo ven el espacio ASCII (api-key NBSP X): lo que tapan sobre la copia normalizada se corta aquí
	spans = append(spans, twinSpans(orig, func(n string) string { var st Stream; return st.Prompted(n, block) })...)
	spans = mergeSpans(spans)
	var vals []SecretValue
	for _, sp := range spans {
		host := hostCmd.MatchString(orig[:sp[0]])
		for _, v := range append(SecretValuesV(orig[sp[0]:sp[1]], host), SecretValuesV(n[sp[0]:sp[1]], host)...) {
			vals = append(vals, v)
			// un valor con forma de URL («ftp://u:CLAVE@host/f»): también sus partes, que un eco partido deja sueltas
			for _, p := range strings.FieldsFunc(v.Text, func(r rune) bool { return r == '/' || r == '@' || r == ':' }) {
				if p != v.Text && spValue(p) {
					vals = append(vals, SecretValue{Text: p, Primary: true}) // main las recordaba: se desalojan como un valor primario
				}
			}
		}
	}
	out, _ := cut(orig, s1, spans)
	var uniq []SecretValue
	at := map[string]int{}
	for _, v := range vals {
		if k, ok := at[v.Text]; ok {
			uniq[k].Primary, uniq[k].Persist = uniq[k].Primary || v.Primary, uniq[k].Persist || v.Persist
			continue
		}
		at[v.Text] = len(uniq)
		uniq = append(uniq, v)
	}
	return out, uniq
}

// CutText es el corte para un texto de log (varias líneas ya unidas en una): s1 es la salida de la cadena de reglas
// sobre orig.
func CutText(platform, orig, s1 string) string {
	o, spans := lineSpans(orig, platform)
	spans = append(spans, twinSpans(o, func(n string) string { t, _ := ApplyPlain(platform, n); return t })...) // misma cadena sobre la copia sin espacios Unicode
	out, _ := cut(o, s1, mergeSpans(append(spans, quoteTail(o, s1)...)))
	return out
}

// endsInKeyword: el tramo termina en una palabra de secreto que aún no tiene valor.
func endsInKeyword(seg string) bool {
	d := spansIn("", seg+" X", true)
	return len(d) > 0 && d[len(d)-1][0] == len(seg)+1
}

// SecretStart devuelve dónde empieza, en cmd (tecleado, con el bloque del prompt), lo que Command tapa; -1 si no tapa nada.
// Sirve para saber qué parte de un eco partido por un syslog cae dentro del secreto.
func SecretStart(block, cmd string) int {
	cmd = strings.ReplaceAll(cmd, `\"`, `"`)
	spans := append(commandSpans(block, cmd), quotedSpans(cmd)...)
	if n := normSpaces(cmd); n != cmd {
		spans = append(spans, quotedSpans(n)...)
	}
	if len(spans) == 0 {
		return -1
	}
	return mergeSpans(spans)[0][0]
}

// CutFrom es el corte de s1 (la salida de la cadena de reglas sobre orig) de orig[from:] hasta el fin de la línea.
func CutFrom(orig, s1 string, from int) string {
	out, _ := cut(orig, s1, [][2]int{{min(from, len(orig)), len(orig)}})
	return out
}

// quoteTail: en una línea que cita un comando entre comillas (quotedCmdLine), si la cadena de reglas tapó algo dentro de la
// cita, el valor puede traer comillas propias («3des Zq1"Zq2»): las reglas paran en la primera y lo que sigue queda a la
// vista. La cita termina en la última comilla de la línea: se tapa desde donde s1 empezó a cambiar hasta ahí.
func quoteTail(orig, s1 string) [][2]int {
	if !quotedCmdLine.MatchString(orig) {
		return nil
	}
	f := strings.IndexByte(orig, '"')
	p := lcp(orig, s1)
	if f < 0 || f >= p || p >= len(orig) {
		return nil
	}
	// Las comillas tras el cambio: la primera que cierra (seguida de espacio, puntuación o el fin) deja la cita como está, que
	// es lo normal. Una pegada a texto («Zq1"Zq2») es del valor: el tramo sigue hasta la siguiente que cierra, o al fin.
	for i := p; i < len(orig); i++ {
		if orig[i] != '"' {
			continue
		}
		if i+1 >= len(orig) || strings.ContainsRune(" \t,;)}]:.", rune(orig[i+1])) {
			if i > p && strings.Contains(orig[p:i], `"`) {
				return [][2]int{{p, i}}
			}
			return nil
		}
	}
	if strings.Contains(orig[p:], `"`) {
		return [][2]int{{p, len(orig)}}
	}
	return nil
}

// cmdSyslogOpen: los syslog de ASA/FTD 111008 y 111010 sin el cierre del comando citado.
var cmdSyslogOpen = []*regexp.Regexp{
	regexp.MustCompile(`^(.*%(?:ASA|FTD)-\d-111008: User '.*?' executed the ')(.*)()$`),
	regexp.MustCompile(`^(.*%(?:ASA|FTD)-\d-111010: User '.*?', running '.*?' from IP \S+, executed ')(.*)()$`),
}

// diffLineM2: el diff de show archive config differences, como diffLine pero sin exigir minúscula tras el signo: acepta
// la palabra clave entera en mayúsculas («+NO snmp-server…», «+ENABLE SECRET…», que IOS acepta; no «+Password aging…») y con un BOM delante. Solo lo usa M₂: diffLine es de la v0.6.5.
var diffLineM2 = regexp.MustCompile(`^(\x{FEFF}? ?[+-])((?:\s*(?i:no|default)\s+)*(?:[a-z]|[A-Z][A-Z0-9-]*(?:\s|$)).*)$`)

func hasHigh(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// diffSpans: la región de n que la cadena de reglas cambió para dar t (entre el prefijo y el sufijo comunes), en
// coordenadas de n; nil si no cambió nada.
func diffSpans(n, t string) [][2]int {
	if n == t {
		return nil
	}
	p := lcp(n, t)
	q := min(lcs(n, t), len(t)-p, len(n)-p)
	return [][2]int{{p, len(n) - q}}
}
