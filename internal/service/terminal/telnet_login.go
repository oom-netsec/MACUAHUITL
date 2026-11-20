package terminal

import (
	"bytes"
	"io"
	"regexp"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// Fase 48-3: con una credencial guardada, el núcleo contesta el login de Telnet. Solo reconoce estas preguntas, y solo
// en la última línea cuando el equipo lleva loginQuiet sin mandar nada (un «Password:» a media línea de un banner no
// cuenta). Nada más: si no las ve a tiempo, o si el equipo rechaza la credencial, la persona sigue a mano.
var (
	telnetUserRe  = regexp.MustCompile(`(?i)^(username|user name|login)\s*:$`)
	telnetPassRe  = regexp.MustCompile(`(?i)^password\s*:$`)
	telnetShellRe = regexp.MustCompile(`^[A-Za-z0-9][\w.()/:-]*[>#]\s*$`) // prompt de exec de IOS: «SW1>», «SW1#»
)

const (
	loginWaitFirst = iota // ni usuario ni contraseña enviados
	loginWaitPass         // usuario enviado
	loginAfterPass        // contraseña enviada: una sola vez, nunca se reintenta
)

// telnetLogin es la máquina del login automático. La usa solo la goroutine que reparte la salida del equipo: ella le
// pasa cada salida (output), y le avisa cuando vence el silencio (stable) o el tope de tiempo (expired).
type telnetLogin struct {
	user          string
	pass          *secret.Secret
	w             io.Writer
	state         int
	tail          []byte // la última línea de la salida, sin el salto
	quietT, limit *time.Timer
	quiet, next   time.Duration
	finished      bool
	result        string // "auto" (el equipo aceptó), "manual" (sigue a mano) o "sent" (contraseña enviada, sin veredicto)
	notice        string // clave del aviso al terminar; vacía si no hace falta
}

func newTelnetLogin(user string, pass *secret.Secret, w io.Writer, quiet, first, next time.Duration) *telnetLogin {
	return &telnetLogin{user: user, pass: pass, w: w, quiet: quiet, next: next, limit: time.NewTimer(first)}
}

// timers devuelve los canales que la goroutine espera; nil (bloquea siempre) si no aplica.
func (l *telnetLogin) timers() (quiet, limit <-chan time.Time) {
	if l.quietT != nil {
		quiet = l.quietT.C
	}
	return quiet, l.limit.C
}

// output guarda la última línea (lo que sigue al último CR o LF, a lo más 256 bytes) y vuelve a contar el silencio.
func (l *telnetLogin) output(p []byte) {
	if i := bytes.LastIndexAny(p, "\r\n"); i >= 0 {
		l.tail = append(l.tail[:0], p[i+1:]...)
	} else {
		l.tail = append(l.tail, p...)
	}
	if len(l.tail) > 256 {
		l.tail = append(l.tail[:0], l.tail[len(l.tail)-256:]...)
	}
	if l.state == loginAfterPass && telnetShellRe.Match(l.tail) { // ya hay prompt de exec: entró, sin esperar al silencio
		l.finish("auto", "")
		return
	}
	if l.quietT == nil {
		l.quietT = time.NewTimer(l.quiet)
	} else {
		l.quietT.Reset(l.quiet)
	}
}

// stable mira la última línea cuando el equipo se calló.
func (l *telnetLogin) stable() {
	line := string(bytes.TrimRight(bytes.ReplaceAll(l.tail, []byte{0}, nil), " \t\r"))
	user, pass := telnetUserRe.MatchString(line), telnetPassRe.MatchString(line)
	switch {
	case l.state == loginWaitFirst && user:
		if l.send([]byte(l.user)) {
			l.state = loginWaitPass
			l.limit.Reset(l.next)
		}
	case (l.state == loginWaitFirst || l.state == loginWaitPass) && pass && l.pass.Empty(): // sin contraseña no se gasta un intento
		l.finish("manual", "terminal.telnet.manual_login")
	case (l.state == loginWaitFirst || l.state == loginWaitPass) && pass:
		buf := append(append([]byte(nil), l.pass.Bytes()...), '\r')
		ok := l.writeAll(buf)
		clear(buf)
		l.pass.Destroy()
		if ok {
			l.state = loginAfterPass
			l.limit.Reset(l.next)
		}
	case l.state == loginWaitPass && user: // volvió a pedir usuario sin pedir contraseña: no lo aceptó
		l.finish("manual", "terminal.telnet.login_rejected")
	case l.state == loginAfterPass && (user || pass): // rechazó la credencial: no se reintenta
		l.finish("manual", "terminal.telnet.login_rejected")
	case l.state == loginAfterPass && line != "": // un prompt que no es de login: entró (una línea vacía es un AAA que aún piensa)
		l.finish("auto", "")
	}
}

// expired: sin la pregunta esperada a tiempo, sigue a mano; tras la contraseña, sin veredicto («sent»): no se dice
// que entró si el equipo no lo mostró.
func (l *telnetLogin) expired() {
	if l.state == loginAfterPass {
		l.finish("sent", "")
		return
	}
	l.finish("manual", "terminal.telnet.manual_login")
}

func (l *telnetLogin) send(b []byte) bool { return l.writeAll(append(append([]byte(nil), b...), '\r')) }

func (l *telnetLogin) writeAll(b []byte) bool {
	l.tail = l.tail[:0]
	_, err := l.w.Write(b)
	if err != nil {
		l.finish("manual", "")
	}
	return err == nil
}

func (l *telnetLogin) finish(result, notice string) {
	l.finished, l.result, l.notice = true, result, notice
	l.limit.Stop()
	if l.quietT != nil {
		l.quietT.Stop()
	}
}
