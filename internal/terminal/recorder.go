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
	tailMax    = 256
	lineMax    = 64 << 10 // una línea (de salida o tecleada) más larga se recorta
	heldMax    = 32       // líneas tecleadas retenidas a la espera de saber si eran una contraseña
	secretsMax = 16
	secretsWin = 50   // líneas de salida que dura la red por contenido
	sentMax    = 32   // líneas enviadas que esperan su eco
	skipMax    = 4096 // líneas que se descartan dentro de una llave privada sin cierre
	totalMax   = 256 << 20
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
	lastBlk string      // último bloque que dio un prompt: vale para lo tecleado sin prompt propio (pegado, log intercalado, cierre)
	typed   mask.Stream // lleva el bloque entre las líneas tecleadas
	sent    []string    // líneas tecleadas y enviadas cuyo eco aún no llegó completo (solo en memoria, con tope)
	pi      int         // índice en sent de la línea cuyo eco quedó partido
	secrets []string    // valores tapados en lo tecleado, en memoria, mientras dure su ventana
	win     int         // líneas de salida que le quedan a la ventana
	acc     string      // lo recibido del eco partido hasta ahora
	cont    bool        // el eco enmascarado quedó partido (se sigue tecleando): lo que siga hasta el prompt es su resto
	hidden  bool        // lo tecleado es una contraseña: no se graba
	line    []byte      // lo tecleado en la línea actual
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
	// Se borra la secuencia de borrado de --More-- antes de quitar los retornos de carro: no deja sangría falsa.
	l = erase.ReplaceAllString(ansi.ReplaceAllString(l, ""), "")
	l = applyBackspaces(strings.ReplaceAll(l, "\r", "")) // el log se lee mejor sin retornos de carro
	if r.win > 0 {
		if r.win--; r.win == 0 {
			r.secrets = nil
		}
	}
	out, keep := "", true
	if pr := promptRe.FindString(l); pr != "" {
		r.setPromptBlock(blockOfPrompt(pr))
		echo := r.stream.Prompted(l[len(pr):], r.lastBlk)
		// Eco partido: se sigue tecleando, o el texto recibido es un prefijo estricto de la primera línea enviada
		// que aún espera su eco. Un eco completo la saca de la cola; lo que no cuadra la vacía.
		text := strings.TrimLeft(l[len(pr):], " \t") // tras el prompt va un espacio antes del eco
		partial := false
		if len(r.sent) == 0 {
			r.secrets, r.win = nil, 0 // prompt sin pendientes: la ventana de la red por contenido vence
		} else if text != "" { // un Enter vacío no saca nada
			if i := indexOf(r.sent, text); i >= 0 {
				r.sent = r.sent[i+1:] // lo anterior se perdió en el eco (p. ej. tabulador completado)
			} else {
				for i, s := range r.sent {
					if strings.HasPrefix(s, text) {
						partial, r.pi = true, i
						break
					}
				}
			}
		}
		r.cont = echo != l[len(pr):] && (len(r.line) > 0 || partial)
		r.acc = text
		out = pr + echo
	} else if r.cont && !equipoMsg(l) {
		// Desde un eco enmascarado hasta el siguiente prompt, lo que no es syslog ni aviso del equipo
		// es el resto del eco (partido por logs asíncronos): se tapa entero.
		out = "<MASKED:secret>"
		if r.pi < len(r.sent) {
			// El eco ya completó la línea enviada: lo que siga es salida normal.
			if r.acc += l; r.acc == r.sent[r.pi] {
				r.cont, r.sent = false, r.sent[r.pi+1:]
			} else if !strings.HasPrefix(r.sent[r.pi], r.acc) {
				r.cont = false
			}
		}
	} else {
		if !equipoMsg(l) {
			l = r.scrub(l, len(r.sent) > 0)
		}
		out, keep = r.stream.Line(l)
	}
	if keep {
		r.emit(r.pendAt.Format(stamp) + " " + out + "\n")
	}
}

var syslogLine = regexp.MustCompile(`%[A-Z][A-Z0-9_]*-\d-`)

// equipoMsg: línea vacía, syslog (con fecha delante o no) o aviso propio del equipo; no es resto de un eco.
func equipoMsg(l string) bool {
	if l == "" || strings.HasPrefix(l, "%") || syslogLine.MatchString(l) {
		return true
	}
	for _, p := range []string{"WARNING:", "ERROR:", "INFO:"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

var erase = regexp.MustCompile(`(?: ?--More-- ?)?(?:\r +\r|\x08+ +\x08+)`)

func indexOf(l []string, s string) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
}

var maskedTok = regexp.MustCompile(`<MASKED:[^>]*>`)

// typedLine enmascara lo tecleado y guarda en memoria los valores tapados (red por contenido).
func (r *Recorder) typedLine(line string) string {
	m := r.typed.Typed(line)
	if m == line {
		return m
	}
	pieces := maskedTok.Split(m, -1)
	if !strings.HasPrefix(line, pieces[0]) {
		return m
	}
	pos := len(pieces[0])
	for _, p := range pieces[1:] {
		end := len(line)
		if p != "" {
			i := strings.Index(line[pos:], p)
			if i < 0 {
				return m
			}
			end = pos + i
		}
		if v := line[pos:end]; len(v) >= 2 && !strings.HasPrefix(v, "<MASKED:") && indexOf(r.secrets, v) < 0 {
			if r.secrets = append(r.secrets, v); len(r.secrets) > secretsMax {
				r.secrets = r.secrets[1:]
			}
			r.win = secretsWin
		}
		pos = end + len(p)
	}
	return m
}

// scrub tapa en una línea de salida los valores tapados antes: el valor completo solo como palabra entera y
// de 4 o más caracteres; y, mientras algún eco siga pendiente (frag), trozos de 2 o más caracteres: un sufijo
// del valor al inicio de la línea o un prefijo al final, que es lo que deja un eco partido.
func (r *Recorder) scrub(l string, frag bool) string {
	for _, v := range r.secrets {
		if len(v) >= 4 {
			l = replaceWord(l, v)
		}
		if !frag {
			continue
		}
		for k := len(v) - 1; k >= 2; k-- {
			if strings.HasPrefix(l, v[len(v)-k:]) {
				l = "<MASKED:secret>" + l[k:]
				break
			}
		}
		for k := len(v) - 1; k >= 2; k-- {
			if strings.HasSuffix(l, v[:k]) {
				l = l[:len(l)-k] + "<MASKED:secret>"
				break
			}
		}
	}
	return l
}

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// replaceWord tapa v donde aparece como palabra entera (límites: inicio o fin de línea, espacio o puntuación).
func replaceWord(l, v string) string {
	var out strings.Builder
	for {
		i := strings.Index(l, v)
		if i < 0 {
			break
		}
		end := i + len(v)
		if (i == 0 || !isWordByte(l[i-1])) && (end == len(l) || !isWordByte(l[end])) {
			out.WriteString(l[:i] + "<MASKED:secret>")
		} else {
			out.WriteString(l[:end])
		}
		l = l[end:]
	}
	return out.String() + l
}

// setPromptBlock recuerda el bloque del prompt; solo si cambia reinicia el de lo tecleado (un prompt
// viejo que llega tarde no debe borrar el bloque que abrió una línea pegada).
func (r *Recorder) setPromptBlock(b string) {
	if b != r.lastBlk {
		r.typed.SetBlock(b)
	}
	r.lastBlk = b
}

func blockOfPrompt(p string) string {
	switch {
	case strings.Contains(p, "(config-line)"):
		return "line"
	case strings.Contains(p, "(config-server-tacacs)"):
		return "tacacs"
	case strings.Contains(p, "(config-server-radius)"):
		return "radius"
	case strings.Contains(p, "(config-aaa-server-host)"):
		return "aaaserver"
	case strings.Contains(p, "(config-smart-lic)"), strings.Contains(p, "(config-license)"):
		return "licsmart"
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
		r.input(l)
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

// flush trata la línea tecleada al pulsar Enter. Requiere r.mu.
func (r *Recorder) flush() {
	line, hidden, fresh := string(r.line), r.hidden, r.fresh
	if pr := promptRe.FindString(r.lastLine()); pr != "" {
		r.setPromptBlock(blockOfPrompt(pr))
	}
	// Un nuevo prompt de contraseña tiene que llegar en la salida: lo ya visto no vale para la línea siguiente.
	r.hidden, r.line, r.tail, r.fresh = false, r.line[:0], nil, false
	if !hidden && line != "" {
		if r.sent = append(r.sent, line); len(r.sent) > sentMax {
			r.sent = r.sent[1:]
		}
	}
	switch {
	case hidden:
		r.input("[oculto]")
	case line == "":
	case fresh && len(r.held) == 0:
		r.input(r.typedLine(line)) // shortcut: ver la nota del paquete sobre abreviaturas
	default:
		// Sin salida nueva desde el Enter anterior: el equipo aún no mostró su prompt y esta línea
		// podría ser la contraseña que el prompt de secreto va a pedir. Se decide al llegar la salida.
		r.held = append(r.held, r.typedLine(line)) // ya enmascarada: los valores entran a la red por contenido al teclear
		if len(r.held) > heldMax {
			r.input(r.held[0])
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
		r.input(r.typedLine(string(r.line)))
	}
	r.hidden, r.line = false, nil
}

// applyBackspaces aplica los retrocesos (\b, 0x7f y la secuencia «\b \b») que el equipo devuelve en el eco.
func applyBackspaces(s string) string {
	if !strings.ContainsAny(s, "\b\x7f") {
		return s
	}
	out := make([]rune, 0, len(s))
	for _, c := range s {
		if c != '\b' && c != 0x7f {
			out = append(out, c)
		} else if len(out) > 0 {
			out = out[:len(out)-1]
		}
	}
	return string(out)
}
