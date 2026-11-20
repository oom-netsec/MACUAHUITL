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
	telSBMax                         = 64 // una subnegociación más larga es un equipo roto: se descarta y se vuelve a datos
)

// TelnetOptions configura OpenTelnet.
type TelnetOptions struct {
	Timeout time.Duration // marcado; 0 = 15 s
}

// TelnetSession es una conexión Telnet con la misma forma que Session para la terminal (ShellSize, Resize, Close).
type TelnetSession struct {
	conn     net.Conn
	r        *bufio.Reader
	mu       sync.Mutex // escrituras: el teclado y las respuestas de negociación comparten la conexión
	term     string
	rows     int
	cols     int
	naws     bool         // el equipo pidió NAWS y se aceptó: Resize lo avisa
	answered map[int]bool // cada pedido se contesta una vez (RFC 854: sin bucles de negociación)
	started  bool
	inCR     bool
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
	return &TelnetSession{conn: conn, r: bufio.NewReader(conn), answered: map[int]bool{}}
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

// Resize avisa el tamaño nuevo por NAWS si el equipo lo aceptó; si no, solo lo guarda.
func (s *TelnetSession) Resize(rows, cols int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return i18n.New("transport.err.no_shell", nil)
	}
	s.rows, s.cols = rows, cols
	if !s.naws {
		return nil
	}
	return s.writeLocked(s.nawsLocked())
}

func (s *TelnetSession) Close() error { return s.conn.Close() }

func (s *TelnetSession) writeLocked(b []byte) error {
	_, err := s.conn.Write(b)
	return err
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

// negotiate contesta un WILL/WONT/DO/DONT del equipo.
func (s *TelnetSession) negotiate(cmd, opt byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := int(cmd)<<8 | int(opt)
	if cmd == telDONT && opt == telNAWS {
		s.naws = false
	}
	if cmd == telWONT || cmd == telDONT || s.answered[key] {
		return nil
	}
	s.answered[key] = true
	switch {
	case cmd == telWILL && (opt == telEcho || opt == telSGA):
		return s.writeLocked([]byte{telIAC, telDO, opt})
	case cmd == telWILL:
		return s.writeLocked([]byte{telIAC, telDONT, opt})
	case opt == telNAWS:
		s.naws = true
		return s.writeLocked(append([]byte{telIAC, telWILL, telNAWS}, s.nawsLocked()...))
	case opt == telTType || opt == telSGA:
		return s.writeLocked([]byte{telIAC, telWILL, opt})
	default:
		return s.writeLocked([]byte{telIAC, telWONT, opt})
	}
}

// sub lee una subnegociación hasta IAC SE y contesta TTYPE SEND con el tipo de terminal en mayúsculas.
func (s *TelnetSession) sub() error {
	var b []byte
	for len(b) <= telSBMax {
		c, err := s.r.ReadByte()
		if err != nil {
			return err
		}
		if c == telIAC {
			if c, err = s.r.ReadByte(); err != nil {
				return err
			}
			if c == telSE {
				if len(b) == 2 && b[0] == telTType && b[1] == telTTypeSend {
					s.mu.Lock()
					defer s.mu.Unlock()
					reply := append([]byte{telIAC, telSB, telTType, telTTypeIs}, strings.ToUpper(s.term)...)
					return s.writeLocked(append(reply, telIAC, telSE))
				}
				return nil
			}
		}
		b = append(b, c)
	}
	return nil
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
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if err := w.s.writeLocked(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
