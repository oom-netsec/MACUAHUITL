// Package logintel es el syslog inteligente de la Fase 17: lee mensajes de syslog o de
// show logging, los agrupa por patrón, marca ráfagas e inestabilidad, detecta interfaces
// con flapping, filtra el ruido de los debugs y busca fugas de memoria entre rondas de
// Patrol. Todo es de solo lectura, sin red ni disco; la entrada no es confiable, así que
// cada línea y cada total tienen tope y las expresiones son de Go (tiempo lineal).
package logintel

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/msgkb"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

const (
	// MaxLines es lo más que se lee de una entrada; el resto se descarta y se avisa.
	MaxLines = 200000
	// MaxLine recorta cada línea cruda antes de analizarla.
	MaxLine = 4096
	// MaxText es lo que se conserva del mensaje de cada entrada.
	MaxText = 1024
)

// Entry es un mensaje de syslog ya leído. At es cero si el mensaje no trae hora.
type Entry struct {
	At       time.Time `json:"at,omitzero"`
	Host     string    `json:"host,omitempty"`
	Mnemonic string    `json:"mnemonic,omitempty"`
	Severity int       `json:"severity"` // 0-7; -1 si no se sabe
	Text     string    `json:"text"`
	local    bool      // la hora era la del reloj del equipo (marca sin UTC/GMT)
}

// ParseOptions: Host es el origen cuando la línea no lo trae (show logging de un equipo);
// Now el reloj de referencia (por defecto, ahora): da el año de las marcas sin año y, si una
// marca queda más de un día adelante, se toma del año anterior (31 de diciembre en una ronda de
// enero). Con HasOffset, Offset es el desfase del reloj del equipo contra UTC (show clock detail)
// y se resta a las marcas que no dicen UTC/GMT; sin él esas marcas se toman como UTC.
type ParseOptions struct {
	Host      string
	Now       time.Time
	Offset    time.Duration
	HasOffset bool
}

// Stats cuenta lo leído: Skipped son las líneas que no son un mensaje (cabeceras, basura).
type Stats struct {
	Lines     int  `json:"lines"`
	Parsed    int  `json:"parsed"`
	WithTime  int  `json:"with_time"`
	Skipped   int  `json:"skipped"`
	Local     int  `json:"local_time,omitempty"` // con hora del reloj del equipo (marca sin zona UTC/GMT)
	Truncated bool `json:"truncated,omitempty"`
}

var priRe = regexp.MustCompile(`^<(\d{1,3})>`)

// ParseLines lee tres formas de línea: la del receptor syslog ("<RFC3339> <origen:puerto> <crudo>",
// con la hora del colector), la de show logging ("*Nov  4 09:58:12.345: %LINK-...") y el mensaje
// suelto con mnemónico. Las horas de show logging se toman como UTC (no traen zona fiable).
func ParseLines(text string, o ParseOptions) ([]Entry, Stats) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	var st Stats
	var out []Entry
	for len(text) > 0 {
		var ln string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			ln, text = text[:i], text[i+1:]
		} else {
			ln, text = text, ""
		}
		if st.Lines == MaxLines {
			st.Truncated = true
			break
		}
		st.Lines++
		if len(ln) > MaxLine {
			ln = ln[:MaxLine]
		}
		ln = strings.TrimSpace(strings.ToValidUTF8(ln, "?"))
		if ln == "" {
			st.Skipped++
			continue
		}
		e, ok := parseLine(ln, o)
		if !ok {
			st.Skipped++
			continue
		}
		st.Parsed++
		if !e.At.IsZero() {
			st.WithTime++
			if e.local {
				st.Local++
			}
		}
		out = append(out, e)
	}
	return out, st
}

func parseLine(ln string, o ParseOptions) (Entry, bool) {
	e := Entry{Host: o.Host, Severity: -1}
	if f := strings.SplitN(ln, " ", 3); len(f) == 3 {
		if t, err := time.Parse(time.RFC3339Nano, f[0]); err == nil && strings.Contains(f[1], ":") || err == nil && strings.Contains(f[1], ".") {
			e.At, e.Host = t.UTC(), hostOf(f[1])
			rest := f[2]
			pri := -1
			if m := priRe.FindStringSubmatch(rest); m != nil {
				pri, _ = strconv.Atoi(m[1])
				rest = rest[len(m[0]):]
			}
			if l, ok := iosxe.ParseLogLine(rest); ok {
				rest = l.Text
			}
			fill(&e, rest)
			if e.Severity < 0 && pri >= 0 {
				e.Severity = pri % 8
			}
			return e, true
		}
	}
	if l, ok := iosxe.ParseLogLine(ln); ok {
		e.local = l.Zone != "UTC" && l.Zone != "GMT"
		var off time.Duration
		if e.local && o.HasOffset {
			off = o.Offset
		}
		year := l.Year
		if year == 0 {
			year = o.Now.Add(off).Year()
		}
		if at, err := l.At(year); err == nil {
			if l.Year == 0 && at.After(o.Now.Add(off).Add(24*time.Hour)) {
				at = at.AddDate(-1, 0, 0)
			}
			e.At = at.Add(-off).UTC()
		}
		fill(&e, l.Text)
		return e, true
	}
	if msgkb.Mnemonic(ln) == "" {
		return Entry{}, false
	}
	fill(&e, ln)
	return e, true
}

func fill(e *Entry, text string) {
	if len(text) > MaxText {
		text = strings.ToValidUTF8(text[:MaxText], "")
	}
	e.Text = strings.TrimSpace(text)
	if m := msgkb.Mnemonic(e.Text); m != "" {
		e.Mnemonic = m
		e.Severity = int(m[strings.Index(m[1:], "-")+2] - '0')
	}
}

// hostOf quita el puerto del origen del receptor ("192.0.2.1:514", "[2001:db8::5]:514").
func hostOf(s string) string {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i]
		}
	}
	if strings.Count(s, ":") == 1 {
		return s[:strings.IndexByte(s, ':')]
	}
	return s
}

// ---- normalización ----

// ifNames son los prefijos de interfaz que se normalizan. La expresión toma cualquier palabra
// seguida de números y de ahí se descartan las que no son interfaz: una alternación de 28
// prefijos tardaba 5-13 µs por mensaje y dominaba la lectura de un log grande.
var ifNames = map[string]bool{}

func init() {
	for _, n := range strings.Fields("GigabitEthernet FastEthernet TenGigabitEthernet TwentyFiveGigE HundredGigE FortyGigabitEthernet Port-channel Ethernet Loopback Vlan Tunnel Serial Management mgmt Gi Fa Te Twe Tw Hu Fo Eth Po Vl Lo Tu Se Mg") {
		ifNames[n] = true
	}
}

// ifWordRe: nombre y número de interfaz ("Gi0/1", "Vlan10", "Po1.100", "Port-channel2").
var ifWordRe = regexp.MustCompile(`\b(Port-channel|[A-Za-z]+)\d+(?:/\d+)*(?:\.\d+)?`)

// normRes: cada sustitución lleva un filtro barato (maybe) que descarta sin ejecutar la
// expresión los mensajes que no pueden coincidir; si keep no es nil, solo se sustituyen las
// coincidencias que acepta.
var normRes = []struct {
	re    *regexp.Regexp
	rep   string
	maybe func(string) bool
	keep  func(match string) bool
}{
	{regexp.MustCompile(`\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b`), "<mac>", func(s string) bool { return strings.Count(s, ".") >= 2 }, nil},
	{regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b`), "<mac>", func(s string) bool { return strings.ContainsAny(s, ":-") }, nil},
	{regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2}|:\d{1,5})?`), "<ip>", func(s string) bool { return strings.Count(s, ".") >= 3 }, nil},
	{regexp.MustCompile(`(?i)(?:\b[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b`), "<ip6>", func(s string) bool { return strings.Contains(s, ":") }, nil},
	{regexp.MustCompile(`\b0x[0-9A-Fa-f]+\b`), "<hex>", func(s string) bool { return strings.Contains(s, "0x") }, nil},
	{ifWordRe, "<if>", func(string) bool { return true }, func(m string) bool {
		i := strings.IndexAny(m, "0123456789")
		return ifNames[m[:i]]
	}},
}

// numRe toma los marcadores ya puestos (<ip6>) para no volver a normalizar sus dígitos.
var numRe = regexp.MustCompile(`<[a-z0-9]+>|\d+`)

// Normalize lleva un mensaje a su patrón: direcciones, interfaces, números y hexadecimales
// pasan a marcadores. El mnemónico (%FAC-SEV-NOMBRE) no se toca.
func Normalize(s string) string {
	if len(s) > MaxText {
		s = strings.ToValidUTF8(s[:MaxText], "")
	}
	// Lo que va antes del mnemónico (número de secuencia, uptime "1d02h") también se normaliza;
	// solo el mnemónico se conserva tal cual.
	pre, mn, post := "", "", s
	if loc := mnemonicLoc(s); loc != nil {
		pre, mn, post = s[:loc[0]], s[loc[0]:loc[1]], s[loc[1]:]
	}
	out := normPart(pre) + mn + normPart(post)
	if !utf8.ValidString(out) {
		return strings.ToValidUTF8(out, "?")
	}
	return out
}

func normPart(tail string) string {
	for _, n := range normRes {
		switch {
		case !n.maybe(tail):
		case n.keep == nil:
			tail = n.re.ReplaceAllString(tail, n.rep)
		default:
			tail = n.re.ReplaceAllStringFunc(tail, func(m string) string {
				if n.keep(m) {
					return n.rep
				}
				return m
			})
		}
	}
	return numRe.ReplaceAllStringFunc(tail, func(m string) string {
		if m[0] == '<' {
			return m
		}
		return "<n>"
	})
}

var mnemonicRe = regexp.MustCompile(`%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+`)

func mnemonicLoc(s string) []int { return mnemonicRe.FindStringIndex(s) }
