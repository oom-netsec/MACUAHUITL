// Package terminal graba las sesiones SSH interactivas: lo que devuelve el equipo y lo que teclea
// el ingeniero, con hora por línea. Lo tecleado en un prompt de contraseña o secreto no se graba, y
// los secretos que el equipo muestra (eco de un comando, show running-config) salen enmascarados.
//
// No hace: red ni abrir sesiones (eso es del servicio); tampoco interpreta comandos.
//
// shortcut: el prompt de contraseña se reconoce por el texto que lo precede ("Password:", "Secret:",
// "passphrase"); un equipo que pida un secreto con otra palabra, o un secreto tecleado en un comando
// (se enmascaran los de IOS conocidos, ver internal/mask), podría grabarse. Ampliar la lista si hace falta.
// shortcut: las abreviaturas de IOS (`usern bob sec 0 X`) no las reconoce mask y quedan en claro; ampliar
// las reglas de internal/mask si hace falta.
// shortcut: la salida se graba por línea completa (con el prompt a medias retenido hasta el salto o el
// cierre); el modo del prompt solo cambia el bloque para line, tacacs y radius.
package terminal

import (
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

const stamp = "2006-01-02T15:04:05.000Z07:00"

// secretPrompt: la última línea de la salida pide una contraseña, secreto o frase.
var secretPrompt = regexp.MustCompile(`(?i)\b(pass(word|phrase|code)|secret)\b[^:\r\n]{0,30}:\s*$`)

var (
	ansi        = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b.`)
	promptRe    = regexp.MustCompile(`^\S+[#>]`)
	shellPrompt = regexp.MustCompile(`^\S+[#>]\s*$`)
)

const (
	tailMax  = 256
	lineMax  = 64 << 10 // una línea (de salida o tecleada) más larga se recorta
	heldMax  = 32       // líneas tecleadas retenidas a la espera de saber si eran una contraseña
	skipMax  = 4096     // líneas que se descartan dentro de una llave privada sin cierre
	totalMax = 256 << 20
)

// Recorder es seguro entre goroutines: la salida y el teclado llegan por separado.
type Recorder struct {
	mu      sync.Mutex
	w       io.Writer
	now     func() time.Time
	pend    []byte    // línea de salida sin terminar
	pendAt  time.Time // hora de su primer byte (cero = no hay línea abierta)
	drop    bool      // la línea de salida pasó el tope: se descarta hasta el salto
	stream  mask.Stream
	tail    []byte // últimos bytes de salida desde el último Enter, para reconocer el prompt
	fresh   bool   // llegó salida desde el último Enter
	held    []string
	hidden  bool   // lo tecleado es una contraseña: no se graba
	line    []byte // lo tecleado en la línea actual
	lastCR  bool
	max     int64 // tope de la grabación en bytes
	written int64
	cut     bool
}

func NewRecorder(w io.Writer, now func() time.Time) *Recorder {
	return &Recorder{w: w, now: now, fresh: true, max: totalMax, stream: mask.Stream{MaxSkip: skipMax}}
}

// emit escribe una línea ya formada, respetando el tope de la grabación. Requiere r.mu.
func (r *Recorder) emit(s string) {
	if r.cut {
		return
	}
	if r.written+int64(len(s)) > r.max {
		r.cut = true
		io.WriteString(r.w, r.now().Format(stamp)+" ### grabación recortada\n")
		return
	}
	r.written += int64(len(s))
	io.WriteString(r.w, s)
}

// Output graba lo que devuelve el equipo, una línea cada vez y con los secretos enmascarados.
func (r *Recorder) Output(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range p {
		if c == '\r' { // el log se lee mejor sin retornos de carro
			continue
		}
		if r.pendAt.IsZero() {
			r.pendAt = r.now()
		}
		switch {
		case c == '\n':
			r.outLine(string(r.pend))
			r.pend, r.pendAt, r.drop = r.pend[:0], time.Time{}, false
		case r.drop:
		case len(r.pend) >= lineMax:
			r.pend = append(r.pend, " [línea recortada]"...)
			r.drop = true
		default:
			r.pend = append(r.pend, c)
		}
	}
	r.tail = append(r.tail, p...)
	if len(r.tail) > tailMax {
		r.tail = r.tail[len(r.tail)-tailMax:]
	}
	r.fresh = true
	r.settle()
}

// outLine enmascara y escribe una línea de salida. El prompt (SW1(config)#) se conserva y se
// analiza lo que sigue, que es el eco de lo tecleado o una línea de configuración.
func (r *Recorder) outLine(l string) {
	l = ansi.ReplaceAllString(l, "")
	out, keep := "", true
	if pr := promptRe.FindString(l); pr != "" {
		out = pr + r.stream.Prompted(l[len(pr):], blockOfPrompt(pr))
	} else {
		out, keep = r.stream.Line(l)
	}
	if keep {
		r.emit(r.pendAt.Format(stamp) + " " + out + "\n")
	}
}

func blockOfPrompt(p string) string {
	switch {
	case strings.Contains(p, "(config-line)"):
		return "line"
	case strings.Contains(p, "(config-server-tacacs)"):
		return "tacacs"
	case strings.Contains(p, "(config-server-radius)"):
		return "radius"
	}
	return ""
}

// lastLine es la última línea de la salida reciente, sin secuencias de escape.
func (r *Recorder) lastLine() string {
	t := ansi.ReplaceAllString(string(r.tail), "")
	return t[strings.LastIndexAny(t, "\r\n")+1:]
}

// asksSecret dice si la salida termina pidiendo una contraseña.
func (r *Recorder) asksSecret() bool { return secretPrompt.MatchString(r.lastLine()) }

// settle decide sobre las líneas retenidas con la salida nueva: si pide un secreto, la primera era
// la contraseña; si es el prompt normal del equipo, eran comandos. Con otra cosa sigue esperando.
func (r *Recorder) settle() {
	switch {
	case len(r.held) == 0:
	case r.asksSecret():
		r.held = r.held[1:]
		r.input("[oculto]")
		r.tail = nil
	case shellPrompt.MatchString(r.lastLine()):
		r.commitHeld()
	}
}

// commitHeld graba como comandos las líneas retenidas. Requiere r.mu.
func (r *Recorder) commitHeld() {
	h := r.held
	r.held = nil
	for _, l := range h {
		r.input(maskTyped(l))
	}
}

// Input graba lo que teclea el ingeniero, una línea al pulsar Enter.
func (r *Recorder) Input(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range p {
		if !r.hidden && len(r.line) == 0 && r.asksSecret() {
			r.hidden = true
		}
		switch {
		case c == '\r' || c == '\n' && !r.lastCR:
			r.flush()
		case c == '\n':
		case r.hidden && c == 0x03: // Ctrl-C cancela el prompt
			r.hidden = false
		case r.hidden:
		case c == 0x7f || c == 0x08:
			if n := len(r.line); n > 0 {
				r.line = r.line[:n-1]
			}
		case len(r.line) >= lineMax:
		case c < 0x20:
			r.line = append(r.line, '^', c+0x40)
		default:
			r.line = append(r.line, c)
		}
		r.lastCR = c == '\r'
	}
}

func maskTyped(s string) string {
	text, _ := mask.Apply("ios-xe", s)
	return text
}

// flush trata la línea tecleada al pulsar Enter. Requiere r.mu.
func (r *Recorder) flush() {
	line, hidden, fresh := string(r.line), r.hidden, r.fresh
	// Un nuevo prompt de contraseña tiene que llegar en la salida: lo ya visto no vale para la línea siguiente.
	r.hidden, r.line, r.tail, r.fresh = false, r.line[:0], nil, false
	switch {
	case hidden:
		r.input("[oculto]")
	case line == "":
	case fresh && len(r.held) == 0:
		r.input(maskTyped(line)) // shortcut: ver la nota del paquete sobre abreviaturas
	default:
		// Sin salida nueva desde el Enter anterior: el equipo aún no mostró su prompt y esta línea
		// podría ser la contraseña que el prompt de secreto va a pedir. Se decide al llegar la salida.
		if r.held = append(r.held, line); len(r.held) > heldMax {
			r.input(maskTyped(r.held[0]))
			r.held = r.held[1:]
		}
	}
}

func (r *Recorder) input(text string) { r.emit(r.now().Format(stamp) + " >>> " + text + "\n") }

// Mark anota un evento propio (apertura, cierre) en una línea aparte.
func (r *Recorder) Mark(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.emit(r.now().Format(stamp) + " ### " + text + "\n")
}

// Close guarda lo que quedó a medias (salida, líneas retenidas y la línea tecleada), salvo una contraseña.
func (r *Recorder) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pend) > 0 {
		r.outLine(string(r.pend))
		r.pend = nil
	}
	r.commitHeld()
	if !r.hidden && len(r.line) > 0 {
		r.input(maskTyped(string(r.line)))
	}
	r.hidden, r.line = false, nil
}
