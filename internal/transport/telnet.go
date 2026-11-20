package transport

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Telnet (RFC 854/855) solo para la terminal interactiva (fase 48): no hay autenticación en el protocolo; el login es
// texto que la terminal muestra. El cliente negocia lo mínimo: acepta ECHO y SGA del equipo, ofrece SGA, NAWS
// (RFC 1073, el tamaño de la ventana) y TTYPE (RFC 1091) cuando el equipo los pide, y rechaza lo demás. Nunca hace
// eco local: lo que se ve es lo que manda el equipo (sin WILL ECHO, una contraseña tecleada no aparece).
const (
	telIAC, telSB, telSE             = 255, 250, 240
	telWILL, telWONT, telDO, telDONT = 251, 252, 253, 254
	telEcho, telSGA, telTType        = 1, 3, 24
	telNAWS                          = 31
	telTTypeIs, telTTypeSend         = 0, 1
	telSBMax                         = 64 // lo que se guarda de una subnegociación; el resto se lee y se descarta
)

// TelnetOptions configura OpenTelnet.
type TelnetOptions struct {
	Timeout time.Duration // marcado; 0 = 15 s (el Guard corta antes, a los 10 s, igual que en SSH)
}

// TelnetSession es una conexión Telnet con la misma forma que Session para la terminal (ShellSize, Resize, Close).
type TelnetSession struct {
	conn    net.Conn
	r       *bufio.Reader
	out     chan telnetOut // una sola goroutine escribe: el lector nunca espera al teclado (ni al revés)
	quit    chan struct{}
	closing sync.Once
	mu      sync.Mutex // estado de las opciones y del tamaño
	term    string
	rows    int
	cols    int
	remote  map[byte]bool // opciones activas del lado del equipo (WILL ECHO, WILL SGA)
	local   map[byte]bool // opciones activas de este lado (NAWS, TTYPE, SGA)
	started bool
	inCR    bool // solo la goroutine lectora
}

type telnetOut struct {
	b    []byte
	done chan error // nil = respuesta de negociación: no se espera
}

// OpenTelnet marca host:port por el EgressGuard (jobID debe estar autorizado, como en OpenSSH).
// shortcut: sin keepalive de aplicación (Telnet no tiene uno estándar); un corte silencioso se nota al escribir.
func OpenTelnet(ctx context.Context, g *Guard, jobID, host string, port uint16, o TelnetOptions) (*TelnetSession, error) {
	if err := ctx.Err(); err != nil { // ya cancelado: ni se marca
		return nil, err
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, err := g.Dial(dctx, jobID, host, port)
	if err != nil {
		return nil, err
	}
	return newTelnetSession(conn), nil
}

func newTelnetSession(conn net.Conn) *TelnetSession {
	s := &TelnetSession{conn: conn, r: bufio.NewReader(conn), out: make(chan telnetOut, 64), quit: make(chan struct{}),
		remote: map[byte]bool{}, local: map[byte]bool{}}
	go s.writer()
	return s
}

func (s *TelnetSession) writer() {
	for {
		select {
		case o := <-s.out:
			_, err := s.conn.Write(o.b)
			if o.done != nil {
				o.done <- err
			}
		case <-s.quit:
			return
		}
	}
}

// send encola b; con wait espera a que salga y devuelve el error de la escritura.
func (s *TelnetSession) send(b []byte, wait bool) error {
	o := telnetOut{b: b}
	if wait {
		o.done = make(chan error, 1)
	}
	select {
	case s.out <- o:
	case <-s.quit:
		return net.ErrClosed
	}
	if !wait {
		return nil
	}
	select {
	case err := <-o.done:
		return err
	case <-s.quit:
		return net.ErrClosed
	}
}

// ShellSize empieza a leer y escribir con el tipo de terminal y el tamaño dados (los que se mandan si el equipo pide
// TTYPE y NAWS). Lo que devuelve el lector ya no trae la capa Telnet; el escritor la agrega.
func (s *TelnetSession) ShellSize(term string, rows, cols int) (io.Reader, io.Writer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil, nil, errors.New("transport: telnet: la sesión ya empezó")
	}
	s.started, s.term, s.rows, s.cols = true, term, rows, cols
	return telnetReader{s}, telnetWriter{s}, nil
}

// Resize avisa el tamaño nuevo por NAWS si el equipo lo tiene activo; si no, solo lo guarda.
func (s *TelnetSession) Resize(rows, cols int) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return i18n.New("transport.err.no_shell", nil)
	}
	s.rows, s.cols = rows, cols
	var b []byte
	if s.local[telNAWS] {
		b = s.nawsLocked()
	}
	s.mu.Unlock()
	if b == nil {
		return nil
	}
	return s.send(b, true)
}

func (s *TelnetSession) Close() error {
	s.closing.Do(func() { close(s.quit) })
	return s.conn.Close()
}

// nawsLocked arma IAC SB NAWS ancho alto IAC SE, con 0xFF duplicado dentro del SB.
func (s *TelnetSession) nawsLocked() []byte {
	b := []byte{telIAC, telSB, telNAWS}
	for _, v := range []int{min(max(s.cols, 0), 0xffff), min(max(s.rows, 0), 0xffff)} {
		for _, c := range []byte{byte(v >> 8), byte(v)} {
			if c == telIAC {
				b = append(b, telIAC)
			}
			b = append(b, c)
		}
	}
	return append(b, telIAC, telSE)
}

// negotiate contesta un WILL/WONT/DO/DONT del equipo siguiendo el estado de cada opción (RFC 854/1143): un pedido que
// no cambia nada no se contesta (sin bucles), un WONT/DONT sobre una opción activa se acusa y la apaga, y una opción
// apagada se puede volver a pedir. Las respuestas se encolan: el lector no espera a que salgan.
func (s *TelnetSession) negotiate(cmd, opt byte) error {
	s.mu.Lock()
	var reply []byte
	switch cmd {
	case telWILL:
		switch {
		case s.remote[opt]:
		case opt == telEcho || opt == telSGA:
			s.remote[opt] = true
			reply = []byte{telIAC, telDO, opt}
		default:
			reply = []byte{telIAC, telDONT, opt}
		}
	case telWONT:
		if s.remote[opt] {
			s.remote[opt] = false
			reply = []byte{telIAC, telDONT, opt}
		}
	case telDO:
		switch {
		case s.local[opt]:
		case opt == telNAWS:
			s.local[opt] = true
			reply = append([]byte{telIAC, telWILL, telNAWS}, s.nawsLocked()...)
		case opt == telTType || opt == telSGA:
			s.local[opt] = true
			reply = []byte{telIAC, telWILL, opt}
		default:
			reply = []byte{telIAC, telWONT, opt}
		}
	case telDONT:
		if s.local[opt] {
			s.local[opt] = false
			reply = []byte{telIAC, telWONT, opt}
		}
	}
	s.mu.Unlock()
	if reply == nil {
		return nil
	}
	return s.send(reply, false)
}

// sub lee una subnegociación hasta IAC SE y contesta TTYPE SEND con el tipo de terminal en mayúsculas. Pasado el tope
// sigue leyendo sin guardar: un SB largo de un equipo roto se descarta entero y no aparece en la terminal.
func (s *TelnetSession) sub() error {
	var b []byte
	for {
		c, err := s.r.ReadByte()
		if err != nil {
			return err
		}
		if c == telIAC {
			if c, err = s.r.ReadByte(); err != nil {
				return err
			}
			if c == telSE {
				break
			}
		}
		if len(b) < telSBMax {
			b = append(b, c)
		}
	}
	if len(b) != 2 || b[0] != telTType || b[1] != telTTypeSend {
		return nil
	}
	s.mu.Lock()
	reply := append([]byte{telIAC, telSB, telTType, telTTypeIs}, strings.ToUpper(s.term)...)
	s.mu.Unlock()
	return s.send(append(reply, telIAC, telSE), false)
}

type telnetReader struct{ s *TelnetSession }

// Read devuelve solo datos: IAC IAC es un 0xFF, el NUL tras un CR se quita y las negociaciones se contestan.
func (r telnetReader) Read(p []byte) (int, error) {
	s, n := r.s, 0
	for n < len(p) && (n == 0 || s.r.Buffered() > 0) {
		c, err := s.r.ReadByte()
		if err != nil {
			return n, err
		}
		if s.inCR && c == 0 {
			s.inCR = false
			continue
		}
		s.inCR = c == '\r'
		if c != telIAC {
			p[n] = c
			n++
			continue
		}
		if n > 0 { // lo ya leído sale ahora: la IAC (quizá partida) se atiende en la siguiente llamada
			s.r.UnreadByte()
			return n, nil
		}
		cmd, err := s.r.ReadByte()
		if err != nil {
			return n, err
		}
		switch cmd {
		case telIAC:
			p[n] = telIAC
			n++
		case telWILL, telWONT, telDO, telDONT:
			opt, err := s.r.ReadByte()
			if err != nil {
				return n, err
			}
			if err := s.negotiate(cmd, opt); err != nil {
				return n, err
			}
		case telSB:
			if err := s.sub(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

type telnetWriter struct{ s *TelnetSession }

// Write duplica 0xFF y manda un CR que no va seguido de LF como CR NUL (NVT): Enter en la terminal es un CR solo.
func (w telnetWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+4)
	for i, c := range p {
		switch {
		case c == telIAC:
			out = append(out, telIAC, telIAC)
		case c == '\r' && (i+1 == len(p) || p[i+1] != '\n'):
			out = append(out, '\r', 0)
		default:
			out = append(out, c)
		}
	}
	// shortcut: un Enter partido entre dos Write («\r» y luego «\n») sale como CR NUL LF; xterm.js manda «\r» solo.
	if err := w.s.send(out, true); err != nil {
		return 0, err
	}
	return len(p), nil
}
