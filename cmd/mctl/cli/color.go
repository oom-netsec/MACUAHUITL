package cli

import (
	"context"
	"io"
	"regexp"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/termcolor"
)

// StripFlag quita todas las apariciones de name de args y dice si estaba.
func StripFlag(args []string, name string) ([]string, bool) {
	var out []string
	found := false
	for _, a := range args {
		if a == name {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

func HasJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "-json" || a == "--json=true" || a == "-json=true" {
			return true
		}
	}
	return false
}

// palette lee la paleta guardada por la UI; ante cualquier error, la predeterminada.
func (c *Env) Palette() string {
	r, err := v1.NewPrefsServiceClient(c.Conn).GetPreference(context.Background(), &v1.GetPreferenceRequest{Key: "terminal"})
	if err != nil || !r.Found {
		return termcolor.DefaultPalette
	}
	return termcolor.PrefsFromJSON(r.Value)
}

// controlSeq: OSC, DCS/APC/PM/SOS, CSI y ESC + un carácter; después cualquier C0 (menos \t \n \r), DEL y C1.
var controlSeq = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b\[[0-?]*[ -/]*[@-~]?|\x1b[@-_]?|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x{80}-\x{9f}]`)

// Sanitize es sanitize para quien escribe fuera de los writers de mctl (stderr).
func Sanitize(s string) string { return sanitize(s) }

// sanitize quita de un texto que viene del equipo todo lo que mueva o reescriba el terminal.
// shortcut: trabaja por escritura; una secuencia partida entre dos escrituras queda como texto inofensivo.
func sanitize(s string) string { return controlSeq.ReplaceAllString(s, "") }

// colorWriter sanea cada escritura (las salidas de mctl son líneas completas) y, si color, la pinta.
type colorWriter struct {
	w         io.Writer
	color     bool
	pal       termcolor.Palette
	truecolor bool
}

func NewOut(w io.Writer, color bool, pal termcolor.Palette, truecolor bool) io.Writer {
	return &colorWriter{w: w, color: color, pal: pal, truecolor: truecolor}
}

func (c *colorWriter) Write(p []byte) (int, error) {
	s := sanitize(string(p))
	if c.color {
		s = termcolor.Colorize(s, c.pal, c.truecolor)
	}
	if _, err := io.WriteString(c.w, s); err != nil {
		return 0, err
	}
	return len(p), nil
}
