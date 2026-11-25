// Package terminal graba las sesiones SSH interactivas: lo que devuelve el equipo y lo que teclea
// el ingeniero, con hora por línea. Lo tecleado en un prompt de contraseña o secreto no se graba, y
// los secretos que el equipo muestra (eco de un comando, show running-config) salen enmascarados.
//
// No hace: red ni abrir sesiones (eso es del servicio); tampoco interpreta comandos.
//
// shortcut: el prompt de contraseña se reconoce por el texto que lo precede ("Password:", "Secret:",
// "passphrase"); un equipo que pida un secreto con otra palabra, o un secreto tecleado en un comando
// (se enmascaran los de IOS conocidos, ver internal/mask), podría grabarse. Ampliar la lista si hace falta.
// Las formas que IOS acepta y mask no ve (abreviaturas, doble espacio, comandos de NX-OS separados por « ; ») se
// tapan aquí con una regla conservadora: ver maskTyped. Se prefiere tapar de más en la terminal que filtrar.
// shortcut: la edición de línea con el cursor (Ctrl-A, Ctrl-B, Ctrl-F, flechas) no se sigue; solo Ctrl-U, Ctrl-W y
// el retroceso. Si hace falta, seguir la posición del cursor.
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

// secretPrompt: la última línea de la salida pide un secreto: termina en «:» y trae key, password, pass phrase,
// secret, psk, token, pin o community string poco antes («New key:», «Enter TACACS+ key:», «PIN:»…). «Press any key
// to continue:» no cuenta (anyKey).
var (
	// Lo que sigue a la palabra puede ser largo y traer «:» («Password for 'https://u@git.example.com':», «Enter
	// passphrase for key '/home/u/.ssh/id_ed25519':»): hasta 120 caracteres.
	secretPrompt = regexp.MustCompile(`(?i)\b(?:pass(?:word|phrase|code)|pass phrase|secret|psk|token|pin|key|community string)\b[^\r\n]{0,120}:\s*$`)
	anyKey       = regexp.MustCompile(`(?i)\bany key\b`)
	// pwPrompt: una línea completa que pedía contraseña («Password:», «[sudo] password for bob:»). Más estrecho que
	// secretPrompt, que también ve «Key Data:» en la salida de un show.
	pwPrompt = regexp.MustCompile(`(?i)\bpass(?:word|phrase|code| phrase)\b[^:\r\n]{0,30}:\s*$`)
)

var (
	// OSC entera (título de ventana: ConPTY de Windows pone ahí la orden que corre, quizá con un secreto), hasta BEL o ST;
	// luego CSI y el resto de escapes de dos bytes.
	ansi = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b.`)
	// Prompt del equipo: «SW1(config)#», el de ISE con espacio «ise/admin(config-Policy List)#», el de AireOS
	// «(Cisco Controller) >» / «(Cisco Controller) config>» y el «> » de FTD (solo si sigue un espacio o el fin).
	promptRe    = regexp.MustCompile(`^(?:\S+[#>]|\S+\([^()\r\n]*\)[#>]|\([^()\r\n]+\) (?:config)?>|>(?: |$))`)
	shellPrompt = regexp.MustCompile(`^(?:\S+[#>]|\S+\([^()\r\n]*\)[#>]|\([^()\r\n]+\) (?:config)?>|>)\s*$`)
)

const (
	tailMax     = 256
	lineMax     = 64 << 10 // una línea (de salida o tecleada) más larga se recorta
	heldMax     = 32       // líneas tecleadas retenidas a la espera de saber si eran una contraseña
	secretsMax  = 16
	secrets2Max = 64   // tope de la lista M₂ (secretsMax sigue siendo el de la v0.6.5)
	secretsWin  = 50   // líneas de salida que dura la red por contenido
	sentMax     = 32   // líneas enviadas que esperan su eco
	skipMax     = 4096 // líneas que se descartan dentro de una llave privada sin cierre
	totalMax    = 256 << 20
)

// Recorder es seguro entre goroutines: la salida y el teclado llegan por separado.
type Recorder struct {
	mu         sync.Mutex
	w          io.Writer
	now        func() time.Time
	pend       []byte    // línea de salida sin terminar
	pendAt     time.Time // hora de su primer byte (cero = no hay línea abierta)
	drop       bool      // la línea de salida pasó el tope: se descarta hasta el salto
	stream     mask.Stream
	tail       []byte      // últimos bytes de salida desde el último Enter, para reconocer el prompt
	fresh      bool        // llegó salida desde el último Enter
	eco        []ecoPend   // lo tecleado (sin las contraseñas en su prompt) que espera su eco para grabarse: ver matchEcho
	lastOut    string      // la última línea de salida tal como se grabó (enmascarada)
	answered   bool        // flush grabó [hidden] la respuesta al prompt de contraseña que la salida aún no termina
	secretRest string      // lo que falta del eco de un secreto tras su prompt, partido por un mensaje del equipo: se tapa
	lastBlk    string      // último bloque que dio un prompt: vale para lo tecleado sin prompt propio (pegado, log intercalado, cierre)
	typed      mask.Stream // lleva el bloque entre las líneas tecleadas
	sent       []string    // líneas tecleadas y enviadas cuyo eco aún no llegó completo (solo en memoria, con tope)
	pi         int         // índice en sent de la línea cuyo eco quedó partido
	secrets    []string    // valores tapados en lo tecleado, en memoria, mientras dure su ventana
	win        int         // líneas de salida que le quedan a la ventana
	secrets2   []string    // lo mismo para los valores que tapa mask.CutCommand (lista y ventana aparte: no tocan el estado de las reglas)
	win2       int
	prim2      map[string]bool // valores de secrets2 que son el primer valor de un secreto (se desalojan al final)
	multi2     map[string]bool // valores de secrets2 que vienen de un secreto de varias palabras: pasan el prompt sin pendientes
	blk2       string          // bloque del prompt para mask.CutCommand («keychain» además de los de lastBlk)
	acc        string          // lo recibido del eco partido hasta ahora
	esent      []string        // copia aparte de las líneas enviadas, solo para reconocer el resto de un eco (no la leen ni escriben las decisiones de la v0.6.5)
	eacc       string          // lo recibido del eco pendiente hasta ahora (estado aparte de acc)
	epart      bool            // hay un eco pendiente: lo que lo continúe, aunque parezca un prompt, es su resto
	eshift     bool            // el eco empezó con «$» (IOS lo desplaza): su texto es un trozo de la línea, no su comienzo
	cont       bool            // el eco enmascarado quedó partido (se sigue tecleando): lo que siga hasta el prompt es su resto
	cfg        bool            // el último prompt visto es de modo config (lo tecleado ahí lleva abreviaturas: mask.Command)
	cfgOK      bool            // hay prompt conocido para lo que se teclea; si no, se tapa como en config
	hidden     bool            // lo tecleado es una contraseña: no se graba
	echoPr     string          // prompt de secreto que se contestó (tecleando o SecretSent): lo que el equipo devuelva tras él en esa línea es el secreto
	noTyped    bool            // SkipTyped: lo tecleado no se graba (solo sirve para tapar su eco)
	line       []byte          // lo tecleado en la línea actual
	lastCR     bool
	max        int64 // tope de la grabación en bytes
	written    int64
	cut        bool
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
}

// outLine enmascara y escribe una línea de salida. El prompt (SW1(config)#) se conserva y se
// analiza lo que sigue, que es el eco de lo tecleado o una línea de configuración.
func (r *Recorder) outLine(l string) {
	// Para reconocer el eco de lo tecleado: la salida cruda, sin escapes ni retornos y con los retrocesos aplicados.
	raw := applyBackspaces(strings.ReplaceAll(ansi.ReplaceAllString(l, ""), "\r", ""))
	l = cleanLine(l)
	masked := ""
	if pr := r.echoPr; pr != "" {
		r.echoPr = ""
		if strings.HasPrefix(l, pr) && strings.TrimSpace(l[len(pr):]) != "" {
			masked = pr + "<MASKED:secret>"
		}
	}
	if r.win > 0 {
		if r.win--; r.win == 0 {
			r.secrets = nil
		}
	}
	if r.win2 > 0 {
		if r.win2--; r.win2 == 0 {
			r.secrets2, r.multi2, r.prim2 = nil, nil, nil
		}
	}
	if masked != "" { // el eco de un secreto contestado: se emite tapado y no pasa por el análisis (con «Password:» sin espacio parecería un prompt)
		r.emit(r.pendAt.Format(stamp) + " " + masked + "\n")
		r.answered = false // esta es la línea del prompt que ya tenía respuesta
		return
	}
	out, keep := "", true
	// Un eco partido por un syslog sigue en la línea siguiente aunque esta lleve «#» o «>» del secreto («Pa55#Xq7») y parezca
	// un prompt. Estado aparte (eacc/epart/esent): las decisiones de la v0.6.5 no cambian y lo único que se agrega es tapar
	// la línea emitida. La línea sigue su camino normal.
	rest := false
	cover := -1 // desde dónde la línea cae dentro del secreto de lo tecleado (eco partido); solo agrega tapado
	if r.epart && l != "" && !equipoMsg(l) {
		if match, done := r.echoMatch(r.eacc + l); match {
			cover = r.echoCover(r.eacc, l)
			rest, r.eacc, r.epart = promptRe.MatchString(l), r.eacc+l, !done
		} else {
			r.epart = false
		}
	}
	pr := promptRe.FindString(l)
	weak := ""
	if pr != "" && weakPrompt(pr) && !r.echoOf(strings.TrimLeft(l[len(pr):], " \t")) {
		weak, pr = pr, "" // «> x», «*> 10.0.0.0/8»: parece prompt, pero lo que sigue no es el eco de nada tecleado
	}
	if pr != "" {
		r.setPrompt(pr)
		// El eco también pasa por scrub: lo que ya se tapó al teclear se tapa en el eco aunque la línea se haya
		// desplazado («R1(config)#$min GRP v3 auth sha X …») y las reglas no la reconozcan.
		src, echo := maskTyped(l[len(pr):], func(x string) string { return r.stream.Prompted(x, r.lastBlk) }, isConfigPrompt(pr))
		echo = r.scrub(echo, len(r.sent) > 0) // S1: de aquí salen las decisiones; el corte solo cambia lo que se escribe
		shown, vis := echo, pr
		if isConfigPrompt(pr) {
			// Un eco desplazado con «#» o «>» se lee como un prompt largo: lo que sobra del primero es eco.
			sh := ""
			if i := strings.IndexAny(pr, "#>"); i >= 0 && i < len(pr)-1 {
				vis, sh = pr[:i+1], pr[i+1:]
			}
			shown = r.hide(sh+src, sh+echo)
		}
		// Eco partido: se sigue tecleando, o el texto recibido es un prefijo estricto de la primera línea enviada
		// que aún espera su eco. Un eco completo la saca de la cola; lo que no cuadra la vacía.
		text := strings.TrimLeft(l[len(pr):], " \t") // tras el prompt va un espacio antes del eco
		partial := false
		if len(r.sent) == 0 {
			// prompt sin pendientes: la ventana de la red M₁ vence (la v0.6.5). La M₂ solo conserva los valores de varias palabras
			// («Pa55w0rd Xq7z9»), que el equipo puede repetir más tarde; vencen por las líneas de la ventana.
			r.secrets = nil
			r.win = 0
			keep := r.secrets2[:0:0]
			for _, v := range r.secrets2 {
				if r.multi2[v] {
					keep = append(keep, v)
				}
			}
			if r.secrets2 = keep; len(keep) == 0 {
				r.win2 = 0
			}
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
		if !rest {
			r.eshift = strings.HasPrefix(text, "$")
			r.eacc = strings.TrimPrefix(text, "$")
			match, done := false, false
			if r.eacc != "" {
				match, done = r.echoMatch(r.eacc)
			}
			r.epart = match && !done
			if match && isConfigPrompt(pr) {
				cover = r.echoCover("", r.eacc)
				if cover >= 0 {
					cover += len(l) - len(r.eacc)
				}
			}
		}
		out = vis + shown
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
		if weak != "" {
			// Puede ser el eco de FTD con un tabulador completado («> configure manager add …»): el texto tras «> » pasa por
			// las reglas sin tocar el bloque ni la red. Tapar de más está bien; si tapó y se sigue tecleando, el resto del eco también.
			text := l[len(weak):]
			if m := r.stream.Peek(text); m != text {
				l, r.cont, r.acc = weak+m, len(r.line) > 0, ""
			}
		}
		// Primero las reglas (reconocen el comando completo) y después la red por contenido, que no entra en lo ya tapado.
		// El orden es el de siempre: S1 → red por contenido M₁ (sobre S1 entero, para que la frase secreta se tape completa)
		// → corte M₂ → red M₂.
		out, keep = r.stream.LineS1(l)
		if keep {
			frag := len(r.sent) > 0
			if !equipoMsg(l) {
				out = r.scrub(out, frag)
			}
			out = r.stream.CutLine(l, out)
			if !equipoMsg(l) {
				out = r.scrub2(out, frag)
			}
		}
	}
	if rest {
		out = "<MASKED:secret>"
	} else if cover >= 0 && keep {
		out = mask.CutFrom(l, out, cover)
	}
	if !keep {
		r.matchEcho(raw, "<MASKED:private-key>") // la salida no grabó esta línea: >>> tampoco muestra nada de ella
	} else {
		out = r.matchEcho(raw, out)
	}
	if keep {
		r.emit(r.pendAt.Format(stamp) + " " + out + "\n")
		r.lastOut = out
	}
}

// cleanLine quita escapes, la secuencia de borrado de --More-- (antes de los retornos de carro: no deja sangría falsa),
// los retornos de carro (el log se lee mejor sin ellos) y aplica los retrocesos.
func cleanLine(l string) string {
	l = erase.ReplaceAllString(ansi.ReplaceAllString(l, ""), "")
	return applyBackspaces(strings.ReplaceAll(l, "\r", ""))
}

// ecoPend: una línea tecleada, ya enmascarada (out), que espera su eco.
// got: lo que ya llegó del eco cuando un mensaje del equipo lo partió; seen: esos trozos como se grabaron.
type ecoPend struct{ text, out, got, seen string }

// matchEcho graba lo tecleado cuyo eco llegó: la primera línea pendiente con la que termina esta línea de salida (tras
// el prompt, una pregunta o sola). Lo que se tecleó antes y nunca tuvo eco se graba [hidden]: una contraseña no hace
// eco, así que no se puede grabar en claro aunque se haya tecleado antes de su prompt. out es la línea de salida como se
// grabó: lo tecleado no muestra nada que ahí quedó tapado (visibleOnly). Requiere r.mu.
func (r *Recorder) matchEcho(raw, out string) string {
	t := strings.TrimRight(raw, " \t")
	answered := r.answered
	r.answered = false
	if t == "" || equipoMsg(strings.TrimSpace(t)) {
		return out
	}
	if rest := r.secretRest; rest != "" {
		r.secretRest = ""
		if s, rr := strings.TrimLeft(t, " \t"), strings.TrimLeft(rest, " \t"); strings.HasPrefix(rr, s) {
			r.secretRest = rr[len(s):]
			return "<MASKED:secret>" // el resto del eco de un secreto, partido por un mensaje del equipo
		}
	}
	if len(r.eco) == 0 {
		return out
	}
	if !answered && pwPrompt.MatchString(raw) && promptRe.FindString(raw) == "" {
		// La línea que pide la contraseña se completa con el Enter de su respuesta: si se tecleó antes de que llegara
		// (flush no la vio), la primera pendiente es esa respuesta, que no hace eco. Si se quedara en la cola, una línea
		// posterior que terminara igual se tomaría por su eco.
		r.eco[0].got, r.eco[0].seen = "", ""
		r.input("[hidden]")
		r.eco = r.eco[1:]
		return out
	}
	// Eco partido por un syslog: «R1#show cl», el mensaje, «ock». Se recuerda el comienzo y el resto lo completa.
	if e := &r.eco[0]; e.got != "" {
		// got no lleva los espacios del final del trozo (la línea se recortó): el resto puede empezar con ellos.
		rest, t2 := e.text[len(e.got):], strings.TrimLeft(t, " \t")
		if r2 := strings.TrimLeft(rest, " \t"); strings.HasPrefix(rest, t) || strings.HasPrefix(r2, t2) {
			// >>> no muestra lo que algún trozo tapó; a media palabra («stp pr» + «i») los trozos se unen sin espacio.
			if strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t") {
				e.seen += " " + out
			} else {
				e.seen = strings.TrimRight(e.seen, " \t") + out
			}
			if strings.HasPrefix(rest, t) {
				e.got += t
			} else {
				e.got = e.text[:len(e.text)-len(r2)] + t2
			}
			if e.got == e.text { // el eco llegó entero, en trozos
				r.input(visibleOnly(e.out, e.seen))
				r.eco = r.eco[1:]
			}
			return out
		}
		e.got, e.seen = "", "" // la línea no continúa el eco: lo recibido no era su comienzo
	}
	for i, e := range r.eco {
		// El eco desplazado de IOS («R1(config)#$p RM …», una línea larga) no cuenta: sale [hidden] y el eco queda en la
		// salida. Reconocerlo metió fugas en cada revisión (lo cortado no se ve, pero se grababa en >>>).
		lead := t[:max(len(t)-len(e.text), 0)]
		if !strings.HasSuffix(t, e.text) || !echoLead(lead) {
			continue // «barfoo» no es el eco de «foo», ni «hostname cisco» el de «cisco»
		}
		for range r.eco[:i] {
			r.input("[hidden]")
		}
		r.eco = r.eco[i+1:]
		if asksSecretLine(lead) { // un prompt de secreto que devuelve lo tecleado (diálogo setup de IOS)
			r.input("[hidden]")
			return tapaFinal(out, e.text)
		}
		r.input(visibleOnly(e.out, out))
		return out
	}
	e := &r.eco[0]
	for k := len(e.text) - 1; k > 0; k-- {
		if !strings.HasSuffix(t, e.text[:k]) {
			continue
		}
		if lead := t[:len(t)-k]; echoLead(lead) {
			if asksSecretLine(lead) {
				r.input("[hidden]")
				r.eco, r.secretRest = r.eco[1:], e.text[k:]
				return tapaFinal(out, e.text[:k])
			}
			e.got, e.seen = e.text[:k], out
			return out
		}
	}
	return out
}

func asksSecretLine(l string) bool { return secretPrompt.MatchString(l) && !anyKey.MatchString(l) }

// tapaFinal tapa el final piece de la línea grabada out (el eco de un secreto tras su prompt); si out ya no termina así,
// la deja como está (las reglas la tocaron).
func tapaFinal(out, piece string) string {
	if o := strings.TrimRight(out, " \t"); strings.HasSuffix(o, piece) {
		return o[:len(o)-len(piece)] + "<MASKED:secret>"
	}
	return out
}

// echoLead: lo que precede a un eco en su línea es nada, un prompt o una pregunta («R1#», «$ », «Username: »,
// «[confirm]», «filename [x]? »); otro texto («hostname », «grep -c ») hace que la línea sea salida, no eco.
func echoLead(p string) bool {
	p = strings.TrimRight(p, " \t")
	return p == "" || strings.ContainsRune("#>$%:?]", rune(p[len(p)-1]))
}

var token = regexp.MustCompile(`\S+`)

// visibleOnly: si la salida grabada out tapó algo, tapa en typed toda palabra que no se ve en out: la línea >>> nunca
// muestra lo que la salida tapó. Si out no tapó nada, typed va tal cual (una palabra puede faltar en out solo por cómo
// se limpió el eco, p. ej. una corrección con retroceso).
func visibleOnly(typed, out string) string {
	if !strings.Contains(out, "<MASKED:") {
		return typed
	}
	return token.ReplaceAllStringFunc(typed, func(w string) string {
		if strings.Contains(w, "<MASKED:") || shownWord(out, w) {
			return w
		}
		return "<MASKED:secret>"
	})
}

// shownWord: w aparece en out como palabra del eco: tras el inicio, un espacio o el prompt, y antes de un espacio o del
// final. «cisco» dentro de «cisco-sw1(config)#» no cuenta.
func shownWord(out, w string) bool {
	for i := 0; ; {
		j := strings.Index(out[i:], w)
		if j < 0 {
			return false
		}
		a, b := i+j, i+j+len(w)
		if (a == 0 || strings.ContainsRune(" \t#>$%", rune(out[a-1]))) && (b == len(out) || out[b] == ' ' || out[b] == '\t') {
			return true
		}
		i = a + 1
	}
}

// echoMatch: x es (el comienzo de) alguna línea enviada o de la que se teclea, o, con el eco desplazado, un trozo de ella;
// done: x es la línea entera.
func (r *Recorder) echoMatch(x string) (match, done bool) {
	for _, s := range append(r.esent[:len(r.esent):len(r.esent)], string(r.line)) {
		if s == x {
			return true, true
		}
		if r.eshift && strings.Contains(s, x) || !r.eshift && strings.HasPrefix(s, x) {
			match = true
		}
	}
	return match, false
}

// echoCover: el trozo piece del eco (que sigue a prev, lo recibido antes) cae dentro del secreto de alguna línea enviada
// desde el desplazamiento que devuelve (0 = entero); -1 si no cae en ninguno. Con el eco desplazado el trozo es un
// pedazo cualquiera de la línea. Los cortes solo agregan tapado.
func (r *Recorder) echoCover(prev, piece string) int {
	if r.cfgOK && !r.cfg { // como lo tecleado: Command solo actúa en modo config
		return -1
	}
	best := -1
	for _, s := range append(r.esent[:len(r.esent):len(r.esent)], string(r.line)) {
		pos := -1
		if r.eshift {
			if i := strings.Index(s, prev+piece); i >= 0 {
				pos = i + len(prev)
			}
		} else if strings.HasPrefix(s, prev+piece) {
			pos = len(prev)
		}
		if pos < 0 {
			continue
		}
		a := mask.SecretStart(r.blk2, s)
		if a < 0 || a >= pos+len(piece) {
			continue
		}
		if off := max(a-pos, 0); best < 0 || off < best {
			best = off
		}
	}
	return best
}

// weakPrompt: el «prompt» no tiene letras ni dígitos («>», «*>»): lo mismo es una fila de salida que el de FTD.
func weakPrompt(pr string) bool {
	return !strings.ContainsFunc(pr, func(c rune) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' })
}

// echoOf dice si text es (el comienzo de) una línea enviada que espera su eco o de la que se está tecleando.
func (r *Recorder) echoOf(text string) bool {
	if text == "" {
		return false
	}
	if strings.HasPrefix(string(r.line), text) {
		return true
	}
	for _, s := range r.sent {
		if strings.HasPrefix(s, text) {
			return true
		}
	}
	return false
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
func (r *Recorder) typedLine(line string, loose bool) string {
	f := r.typed.Typed
	if loose {
		f = r.typed.TypedLoose
	}
	cfg := loose || !r.cfgOK || r.cfg
	line, m := maskTyped(line, f, cfg)
	// Un Tab (se graba como «^I») hace que el equipo complete palabras que las reglas no ven: desde el primero se tapa todo.
	if i := strings.Index(m, "^I"); i >= 0 {
		m = m[:i] + "<MASKED:secret>"
	}
	r.noteSecrets(line, m)
	if cfg { // el corte: S1 (m) con lo que Command tapa; no cambia ningún estado
		var vals []mask.SecretValue
		m, vals = mask.CutCommandV(r.blk2, line, m)
		r.note2(vals)
	}
	return m
}

// hide es el corte para el eco: s1 (ya con la red por contenido de las reglas) con lo que Command tapa y la lista M₂.
func (r *Recorder) hide(src, s1 string) string {
	pre := ""
	if strings.HasPrefix(src, "$") && strings.HasPrefix(s1, "$") { // eco desplazado de IOS («R1(config)#$cola…»): el «$» no es del comando
		pre, src, s1 = "$", src[1:], s1[1:]
	}
	out, vals := mask.CutCommandV(r.blk2, src, s1)
	r.note2(vals)
	frag := len(r.sent) > 0
	return pre + r.scrub2(r.scrub(out, frag), frag)
}

// note2 guarda en memoria los valores que tapó mask.CutCommandV (con su propio tope y ventana). Al pasar secrets2Max se
// desaloja la más antigua de las palabras que no son el primer valor de un secreto: un comando largo no saca de la lista
// el valor de otro anterior.
func (r *Recorder) note2(vals []mask.SecretValue) {
	for _, v := range vals {
		if len(v.Text) < 4 || strings.HasPrefix(v.Text, "<MASKED:") {
			continue
		}
		if v.Persist {
			if r.multi2 == nil {
				r.multi2 = map[string]bool{}
			}
			r.multi2[v.Text] = true
		}
		if v.Primary {
			if r.prim2 == nil {
				r.prim2 = map[string]bool{}
			}
			r.prim2[v.Text] = true
		}
		if indexOf(r.secrets2, v.Text) < 0 {
			r.secrets2 = append(r.secrets2, v.Text)
			if len(r.secrets2) > secrets2Max {
				k := 0
				for i, x := range r.secrets2 {
					if !r.prim2[x] {
						k = i
						break
					}
				}
				delete(r.multi2, r.secrets2[k])
				delete(r.prim2, r.secrets2[k])
				r.secrets2 = append(r.secrets2[:k], r.secrets2[k+1:]...)
			}
		}
		r.win2 = secretsWin
	}
}

// noteSecrets guarda en memoria los valores que la línea enmascarada m tapó en line.
func (r *Recorder) noteSecrets(line, m string) {
	if m == line {
		return
	}
	pieces := maskedTok.Split(m, -1)
	if !strings.HasPrefix(line, pieces[0]) {
		return
	}
	pos := len(pieces[0])
	for _, p := range pieces[1:] {
		end := len(line)
		if p != "" {
			i := strings.Index(line[pos:], p)
			if i < 0 {
				return
			}
			end = pos + i
		}
		if v := line[pos:end]; len(v) >= 4 && !strings.HasPrefix(v, "<MASKED:") && indexOf(r.secrets, v) < 0 {
			if r.secrets = append(r.secrets, v); len(r.secrets) > secretsMax {
				r.secrets = r.secrets[1:]
			}
			r.win = secretsWin
		}
		pos = end + len(p)
	}
}

// scrub tapa en una línea de salida los valores tapados antes: el valor completo solo como palabra entera y
// de 4 o más caracteres; y, mientras algún eco siga pendiente (frag), trozos de 2 o más caracteres: un sufijo
// del valor al inicio de la línea o un prefijo al final, que es lo que deja un eco partido. Nunca entra en un
// <MASKED:…> que ya está en la línea.
func (r *Recorder) scrub(l string, frag bool) string { return r.scrubIn(l, frag, r.secrets) }

// scrub2 es scrub con la lista M₂, un valor por pasada: así un valor corto («secret») no entra en el <MASKED:…> que dejó otro.
func (r *Recorder) scrub2(l string, frag bool) string {
	for _, v := range r.secrets2 {
		l = r.scrubIn(l, frag, []string{v})
	}
	return l
}

// scrubIn es scrub con la lista de valores que se le dé.
func (r *Recorder) scrubIn(l string, frag bool, list []string) string {
	var b strings.Builder
	pos := 0
	for _, loc := range maskedTok.FindAllStringIndex(l, -1) {
		b.WriteString(scrubSeg(list, l[pos:loc[0]], frag, pos == 0, false) + l[loc[0]:loc[1]])
		pos = loc[1]
	}
	return b.String() + scrubSeg(list, l[pos:], frag, pos == 0, true)
}

// scrubSeg: first/last dicen si el tramo toca el inicio/fin de la línea (solo ahí valen los trozos de un eco partido).
func scrubSeg(list []string, l string, frag, first, last bool) string {
	for _, v := range list {
		if len(v) >= 4 {
			l = replaceWord(l, v)
		}
		if !frag {
			continue
		}
		for k := len(v) - 1; first && k >= 2; k-- {
			if strings.HasPrefix(l, v[len(v)-k:]) {
				l = "<MASKED:secret>" + l[k:]
				break
			}
		}
		for k := len(v) - 1; last && k >= 2; k-- {
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

// setPrompt toma el bloque y el modo (config o no) de un prompt visto.
func (r *Recorder) setPrompt(pr string) {
	r.setPromptBlock(blockOfPrompt(pr))
	r.cfg, r.cfgOK = isConfigPrompt(pr), true
	if r.blk2 = r.lastBlk; strings.Contains(pr, "(config-keychain)") {
		r.blk2 = "keychain"
	}
}

// isConfigPrompt: el prompt es de modo config o de un submodo («R1(config-if)#», «(Cisco Controller) config>»).
func isConfigPrompt(pr string) bool {
	return strings.Contains(pr, "(") && !strings.HasPrefix(pr, "(") || strings.HasSuffix(strings.TrimSpace(pr), ") config>")
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
	case strings.HasSuffix(strings.TrimSpace(p), ") config>"): // AireOS: se teclea sin el prefijo «config»
		return "aireconfig"
	case strings.Contains(p, "(config-line)"):
		return "line"
	case strings.Contains(p, "(config-server-tacacs)"):
		return "tacacs"
	case strings.Contains(p, "(config-server-radius)"), strings.Contains(p, "(config-radius-server)"):
		return "radius"
	case strings.Contains(p, "(config-dot1x-cred"): // IOS-XE lo acorta: «(config-dot1x-creden)»
		return "dot1x"
	case strings.Contains(p, "(config-isakmp-group)"), strings.Contains(p, "(config-isakmp-client-group)"):
		return "ezvpn"
	case strings.Contains(p, "(config-profile)"), strings.Contains(p, "(config-umbrella"): // parameter-map type umbrella; otros profile tapan de más
		return "umbrella"
	case strings.Contains(p, "(config-username)"): // ASA: user-name X
		return "username"
	case strings.Contains(p, "(config-aaa-server-host)"):
		return "aaaserver"
	case strings.Contains(p, "(cfg-cluster)"):
		return "cluster"
	case strings.Contains(p, "ca-trustpoint)"): // ASA «(config-ca-trustpoint)» e IOS «(ca-trustpoint)»
		return "trustpoint"
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
func (r *Recorder) asksSecret() bool {
	l := r.lastLine()
	return secretPrompt.MatchString(l) && !anyKey.MatchString(l)
}

// Input graba lo que teclea el ingeniero, una línea al pulsar Enter.
func (r *Recorder) Input(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range p {
		if !r.hidden && len(r.line) == 0 && r.asksSecret() {
			r.hidden = true
			r.armEcho()
		}
		switch {
		case c == '\r' || c == '\n' && !r.lastCR:
			r.flush()
		case c == '\n':
		case r.hidden && c == 0x03: // Ctrl-C cancela el prompt
			r.hidden = false
		case r.hidden:
		case c == 0x15: // Ctrl-U: borra la línea (lo anterior no se ejecuta)
			r.line = r.line[:0]
		case c == 0x17: // Ctrl-W: borra la palabra anterior
			w := strings.TrimRight(string(r.line), " ")
			r.line = []byte(w[:strings.LastIndexByte(w, ' ')+1])
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
	// Un prompt con letras fija el bloque siempre; uno débil («>», «*>») solo si es el prompt solo o lo que sigue es el
	// eco (parcial, con los retrocesos aplicados) de lo tecleado.
	r.cfgOK = false
	if ll := applyBackspaces(r.lastLine()); promptRe.FindString(ll) != "" {
		pr := promptRe.FindString(ll)
		if text := strings.TrimLeft(ll[len(pr):], " \t"); !weakPrompt(pr) || text == "" || strings.HasPrefix(line, text) || r.echoOf(text) {
			r.setPrompt(pr)
		}
	}
	// Un nuevo prompt de contraseña tiene que llegar en la salida: lo ya visto no vale para la línea siguiente.
	r.hidden, r.line, r.tail, r.fresh = false, r.line[:0], nil, false
	if !hidden && line != "" {
		if r.esent = append(r.esent, line); len(r.esent) > sentMax {
			r.esent = r.esent[1:]
		}
		if r.sent = append(r.sent, line); len(r.sent) > sentMax {
			r.sent = r.sent[1:]
		}
	}
	switch {
	case hidden:
		r.input("[hidden]")
		r.answered = true // la línea del prompt, al completarse, ya tiene su respuesta
	case line == "":
	default:
		// Se enmascara ya (con el bloque del prompt de ahora; sus valores entran a la red por contenido para tapar el
		// eco) y se graba cuando llega su eco. Sin salida nueva desde el Enter anterior el prompt no se sabe: más estricto.
		// shortcut: ver la nota del paquete sobre abreviaturas.
		r.eco = append(r.eco, ecoPend{text: line, out: r.typedLine(line, !fresh)})
		if len(r.eco) > heldMax {
			r.eco = r.eco[1:]
			r.input("[hidden]") // sin eco en todo ese tiempo: no se sabe qué era
		}
	}
}

func (r *Recorder) input(text string) {
	if !r.noTyped {
		r.emit(r.now().Format(stamp) + " >>> " + text + "\n")
	}
}

// SkipTyped deja de grabar lo tecleado (la consola serie: ahí el login es parte de la sesión y una contraseña tecleada
// antes de su prompt no siempre se distingue de un comando). Input sigue sirviendo para tapar el eco. Antes de usarlo.
func (r *Recorder) SkipTyped() { r.noTyped = true }

// SecretSent: el núcleo contestó el prompt de secreto que está en pantalla (login automático de Telnet); si el equipo
// devuelve lo enviado en esa misma línea, se tapa.
func (r *Recorder) SecretSent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.armEcho()
}

// armEcho: la línea a medias es un prompt de secreto que se está contestando; lo que el equipo devuelva tras él en esa
// línea (diálogo setup de IOS, login de Telnet) es el secreto y outLine lo tapa. Solo al contestar: una salida que llega
// byte a byte y pasa por un «:» («Key name: …») no se toca. Requiere r.mu.
func (r *Recorder) armEcho() {
	if len(r.pend) > 0 && len(r.pend) <= 256 {
		if l := cleanLine(string(r.pend)); secretPrompt.MatchString(l) && !anyKey.MatchString(l) {
			r.echoPr = l
		}
	}
}

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
	for range r.eco {
		r.input("[hidden]") // nunca hizo eco: pudo ser una contraseña
	}
	r.eco = nil
	if !r.hidden && len(r.line) > 0 { // tecleado sin Enter: solo si su eco está en la última salida
		if line := string(r.line); strings.HasSuffix(strings.TrimRight(applyBackspaces(r.lastLine()), " \t"), line) {
			r.input(visibleOnly(r.typedLine(line, true), r.lastOut))
		} else {
			r.input("[hidden]")
		}
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

// maskTyped aplica base (las reglas de mask) a una línea tecleada o a su eco, con las formas que IOS acepta: espacios
// repetidos (se juntan; reglas de mask piden uno), comandos de NX-OS separados por « ; » (cada uno por separado) y,
// en modo config (cfg), abreviaturas y tabuladores (mask.Command). Devuelve la línea que se enmascaró (con los espacios
// juntos, para localizar los valores tapados) y el resultado; si nada se tapó, el resultado es la línea original.
// Command solo recibe lo que se teclea o su eco, nunca salida de un show.
func maskTyped(s string, base func(string) string, cfg bool) (src, out string) {
	sq := squeeze(s)
	parts := strings.Split(sq, " ; ")
	for i, p := range parts {
		p = base(p)
		if cfg {
			p, _ = mask.Command(p)
		}
		parts[i] = p
	}
	if m := strings.Join(parts, " ; "); m != sq {
		return sq, m
	}
	return s, s
}

// squeeze junta los espacios repetidos fuera de comillas (conserva la sangría).
func squeeze(s string) string {
	if !strings.Contains(s, "  ") {
		return s
	}
	var b strings.Builder
	q, lead := false, true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			q = !q
		case c != ' ':
			lead = false
		case !q && !lead && i > 0 && s[i-1] == ' ':
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
