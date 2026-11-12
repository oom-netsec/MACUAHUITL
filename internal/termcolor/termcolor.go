// Package termcolor clasifica el texto de salidas tipo terminal (estados, severidades de
// syslog, direcciones, interfaces, prompts, errores) y lo pinta con ANSI. Las reglas y las
// paletas viven en JSON (rules.json, palettes.json) y la UI los importa tal cual, así Go y
// TypeScript clasifican igual. Sin red ni archivos.
package termcolor

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed rules.json
var rulesJSON []byte

//go:embed palettes.json
var palettesJSON []byte

// Span es un tramo [Start,End) en bytes de la línea con su categoría.
type Span struct {
	Start, End int
	Cat        string
}

// Palette: colores #rrggbb por categoría (más fg/bg para la UI).
type Palette struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Fg   string `json:"fg"`
	Bg   string `json:"bg"`
	Cats map[string]string
}

var (
	re       *regexp.Regexp
	cats     []string
	sevRe    = regexp.MustCompile(`-([0-7])-`)
	palettes []Palette
)

func init() {
	var rules []struct{ Cat, Re string }
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		panic(err)
	}
	parts := make([]string, len(rules))
	for i, r := range rules {
		parts[i] = "(" + r.Re + ")"
		cats = append(cats, r.Cat)
	}
	re = regexp.MustCompile("(?i)" + strings.Join(parts, "|"))
	if re.NumSubexp() != len(rules) {
		panic("termcolor: las reglas no deben tener grupos de captura propios")
	}
	var raw []map[string]string
	if err := json.Unmarshal(palettesJSON, &raw); err != nil {
		panic(err)
	}
	for _, m := range raw {
		p := Palette{ID: m["id"], Name: m["name"], Fg: m["fg"], Bg: m["bg"], Cats: map[string]string{}}
		for k, v := range m {
			switch k {
			case "id", "name", "fg", "bg":
			default:
				p.Cats[k] = v
			}
		}
		palettes = append(palettes, p)
	}
}

// DefaultPalette es la paleta de la UI cuando no hay preferencia.
const DefaultPalette = "classic"

// legacyIDs: ids con que se guardaron algunas paletas antes de renombrarlas; la preferencia vieja sigue valiendo.
var legacyIDs = map[string]string{"securecrt-dark": "consola-oscura", "securecrt-light": "consola-clara"}

// Lookup devuelve la paleta por id; si no existe, la predeterminada.
func Lookup(id string) Palette {
	if n, ok := legacyIDs[id]; ok {
		id = n
	}
	for _, p := range palettes {
		if p.ID == id {
			return p
		}
	}
	return Lookup(DefaultPalette)
}

// sevCat traduce la severidad syslog (0-7) del mnemónico a categoría.
func sevCat(s string) string {
	m := sevRe.FindStringSubmatch(s)
	switch {
	case m == nil:
		return "dim"
	case m[1] <= "3":
		return "bad"
	case m[1] == "4":
		return "warn"
	case m[1] == "5":
		return "info"
	}
	return "dim"
}

// Classify devuelve los tramos coloreables de una línea, sin solaparse y en orden.
func Classify(line string) []Span {
	var out []Span
	for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
		for g := range cats {
			if m[2*g+2] < 0 {
				continue
			}
			c := cats[g]
			if c == "mnem" {
				c = sevCat(line[m[0]:m[1]])
			}
			out = append(out, Span{m[0], m[1], c})
			break
		}
	}
	return out
}

// PrefsFromJSON lee el valor de la preferencia "terminal" ({"palette":"p1"}); ignora los demás campos.
// Si es inválido devuelve la paleta predeterminada.
func PrefsFromJSON(v string) string {
	var p struct {
		Palette string `json:"palette"`
	}
	if json.Unmarshal([]byte(v), &p) != nil {
		return DefaultPalette
	}
	return Lookup(p.Palette).ID
}

// Colorize pinta cada línea de text con ANSI. truecolor usa 24 bits; si no, el color
// ANSI de 16 más cercano. Sin tramos devuelve la línea intacta.
func Colorize(text string, pal Palette, truecolor bool) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		var b strings.Builder
		pos := 0
		for _, s := range Classify(l) {
			b.WriteString(l[pos:s.Start])
			b.WriteString(sgr(pal.Cats[s.Cat], truecolor))
			b.WriteString(l[s.Start:s.End])
			b.WriteString("\x1b[0m")
			pos = s.End
		}
		b.WriteString(l[pos:])
		lines[i] = b.String()
	}
	return strings.Join(lines, "\n")
}

var ansi16 = [16][3]int{{0, 0, 0}, {205, 0, 0}, {0, 205, 0}, {205, 205, 0}, {0, 0, 238}, {205, 0, 205}, {0, 205, 205}, {229, 229, 229},
	{127, 127, 127}, {255, 0, 0}, {0, 255, 0}, {255, 255, 0}, {92, 92, 255}, {255, 0, 255}, {0, 255, 255}, {255, 255, 255}}

func sgr(hex string, truecolor bool) string {
	var r, g, b int
	if _, err := fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b); err != nil {
		return ""
	}
	if truecolor {
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
	}
	best, bd := 7, 1<<30
	for i, c := range ansi16 {
		d := (r-c[0])*(r-c[0]) + (g-c[1])*(g-c[1]) + (b-c[2])*(b-c[2])
		if i != 0 && d < bd { // el negro no se usa: sería invisible en terminales oscuras
			best, bd = i, d
		}
	}
	if best < 8 {
		return fmt.Sprintf("\x1b[%dm", 30+best)
	}
	return fmt.Sprintf("\x1b[%dm", 90+best-8)
}

// Enabled decide si mctl pinta: solo con TTY, sin NO_COLOR ni --no-color ni --json.
func Enabled(isTTY, noColorFlag, asJSON bool, getenv func(string) string) bool {
	return isTTY && !noColorFlag && !asJSON && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}

// Truecolor informa si el terminal declara 24 bits (COLORTERM=truecolor|24bit).
func Truecolor(getenv func(string) string) bool {
	v := getenv("COLORTERM")
	return v == "truecolor" || v == "24bit"
}
