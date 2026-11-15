package ref065

import (
	"regexp"
	"strings"
)

// Command enmascara un comando tal como se teclea: IOS acepta abreviaturas («cry isa key X», «snmp-s comm X»,
// «ena sec X»), así que no se buscan las palabras enteras sino cualquier token que sea prefijo (2 o más letras, sin
// distinguir mayúsculas) de una palabra de secreto. Se tapa el valor: el siguiente token que no sea estructural (tipo
// de cifrado 0-9, algoritmo, hex/ascii, número de llave en las familias auth/priv/message-digest-key…). Si el valor es
// de tipo 0 se tapa también lo que siga hasta la palabra que cierra ese comando. Tapa de más a propósito.
//
// No toca lo que va tras un «|» (un filtro de salida no es un secreto), los comandos show ni el texto libre
// (description, remark, banner). Es para comandos tecleados o citados (terminal en modo config, CFGLOG, archive log,
// accounting); la configuración tal como la imprime el equipo la cubren las reglas de Apply.
//
// Devuelve el comando enmascarado y los valores que tapó (solo valores de 4 o más caracteres: nunca palabras clave ni
// estructurales), para quien quiera tapar su repetición por contenido.
func Command(cmd string) (string, []string) { return maskCommand(cmd, map[string]int{}, false) }

// cmdKeys: palabras de secreto; keyed: tras ellas el valor va después de números y algoritmos.
var cmdKeys = []struct {
	word  string
	keyed bool
}{
	{"secret", false}, {"password", false}, {"key", false}, {"key-string", false}, {"community", false}, {"token", false},
	{"pre-shared-key", false}, {"psk", false}, {"idtoken", false}, {"text", false},
	{"authentication-key", true}, {"message-digest-key", true}, {"auth", true}, {"priv", true},
}

var (
	cmdToken  = regexp.MustCompile(`"[^"]*"|\S+`)
	cmdAlgo   = regexp.MustCompile(`(?i)^(?:md5|sha[\w-]*|hmac[\w-]*|aes[\w-]*|3?des|\d{3})$`)
	cmdPlain  = regexp.MustCompile(`(?i)^\s*(?:(?:no|default)\s+)*(?:(?:\d+\s+)?(?:description|remark)|banner|alias)\s`)
	cmdDigits = regexp.MustCompile(`^\d+$`)
	// Palabras que siguen a key/password pero son parte del comando, no el valor.
	cmdNotSecret = map[string]bool{"chain": true, "generate": true, "zeroize": true, "config-key": true, "export": true, "import": true, "exchange": true, "add": true, "delete": true, "keywrap": true}
)

// cmdKeyword dice si w es una palabra de secreto o su abreviatura (2 o más letras); keyed: de las familias auth/priv.
func cmdKeyword(w string, noToken bool) (ok, keyed bool) {
	w = strings.ToLower(w)
	if len(w) < 2 || w == "authentication" || w == "message-digest" { // palabras del comando, no del secreto
		return false, false
	}
	for _, k := range cmdKeys {
		if (strings.HasPrefix(k.word, w) || hyphenPrefix(k.word, w)) && !(noToken && k.word == "token") {
			ok, keyed = true, keyed || k.keyed
		}
	}
	return
}

// noToken: en un texto citado cualquiera «token X» no es un secreto (solo lo es en un log de comandos o dentro de license smart).
func maskCommand(cmd string, counts map[string]int, noToken bool) (string, []string) {
	toks, lim := cmdToken.FindAllStringIndex(cmd, -1), len(cmd)
	for i, t := range toks {
		if cmd[t[0]:t[1]] == "|" { // lo que sigue a la barra es un filtro, no un secreto
			toks, lim = toks[:i], t[0]
			break
		}
	}
	tok := func(i int) string { return cmd[toks[i][0]:toks[i][1]] }
	first := 0
	if len(toks) > 0 && strings.EqualFold(tok(0), "do") {
		first = 1
	}
	if first < len(toks) && len(tok(first)) >= 2 && strings.HasPrefix("show", strings.ToLower(tok(first))) || cmdPlain.MatchString(cmd) {
		return cmd, nil
	}
	var b strings.Builder
	var vals []string
	last := 0
	for i := first; i < len(toks); i++ {
		ok, keyed := cmdKeyword(tok(i), noToken)
		if !ok {
			continue
		}
		j, zero := i+1, false
		for ; j < len(toks); j++ {
			w, lw := tok(j), strings.ToLower(tok(j))
			switch {
			case len(w) == 1 && w[0] >= '0' && w[0] <= '9':
				zero = w == "0"
			case cmdAlgo.MatchString(w), lw == "hex", lw == "ascii", lw == "encrypted", lw == "hash", lw == "plain", lw == "local", lw == "remote", lw == "create":
			case lw == "level" || lw == "address" || lw == "hostname" || lw == "ipv6": // lleva su operando
				j++
			case keyed && cmdDigits.MatchString(w) && j < len(toks)-1:
			default:
				goto value
			}
		}
	value:
		if j >= len(toks) {
			continue
		}
		v := tok(j)
		if k, _ := cmdKeyword(v, noToken); k || strings.HasPrefix(v, "<MASKED:") || isGuard(v) || cmdNotSecret[strings.ToLower(v)] {
			continue
		}
		end := toks[j][1]
		if zero && v[0] != '"' {
			more, _ := tail(cmd[end:lim])
			end += len(more)
		}
		b.WriteString(cmd[last:toks[j][0]] + "<MASKED:secret>")
		last, counts["secret"] = end, counts["secret"]+1
		if v = strings.Trim(v, `"`); len(v) >= 4 {
			vals = append(vals, v)
		}
		for i = j; i+1 < len(toks) && toks[i+1][0] < end; i++ {
		}
	}
	if last == 0 {
		return cmd, nil
	}
	return b.String() + cmd[last:], vals
}

// hyphenPrefix: w abrevia cada segmento de word por separado («auth-key» de «authentication-key»).
func hyphenPrefix(word, w string) bool {
	a, b := strings.Split(word, "-"), strings.Split(w, "-")
	if len(a) != len(b) || len(a) == 1 {
		return false
	}
	for i := range a {
		if b[i] == "" || !strings.HasPrefix(a[i], b[i]) {
			return false
		}
	}
	return true
}
