package simulator

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// Bytes de control de Telnet (RFC 854/855) y las opciones que entiende el simulador.
const (
	tIAC, tSB, tSE           = 255, 250, 240
	tWILL, tWONT, tDO, tDONT = 251, 252, 253, 254
	tEcho, tSGA, tTType      = 1, 3, 24
	tNAWS                    = 31
	tTTypeIs, tTTypeSend     = 0, 1
	sbMax                    = 64 // una subnegociación más larga es un cliente roto: se anota y se vuelve a datos
)

var negName = map[byte]string{tWILL: "WILL", tWONT: "WONT", tDO: "DO", tDONT: "DONT"}

// StartTelnet levanta el mismo equipo que Start, pero por Telnet: el login es texto («Username:»/«Password:», o solo
// «Password:» con TelnetLinePassword) y la sesión que sigue es la misma. Conns, Attempts, Recorder y Hangup valen igual
// (Hangup corta también durante el login). En el Recorder quedan las negociaciones que manda el cliente («!neg DO 3»),
// el tamaño de NAWS («!naws COLSxFILAS»), el tipo de terminal («!ttype XTERM») y «!sb-sin-cerrar».
func StartTelnet(t testing.TB, c Config) string {
	t.Helper()
	outputs, dev := prepare(t, c)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			if c.Conns != nil {
				c.Conns.Add(1)
			}
			go serveTelnet(&telnetConn{conn: conn, r: bufio.NewReader(conn), c: c, done: make(chan struct{})}, c, outputs, dev)
		}
	}()
	return l.Addr().String()
}

func serveTelnet(tc *telnetConn, c Config, outputs map[string]string, dev *device) {
	ended := c.Hangup.add(tc)
	defer func() {
		tc.Close()
		c.Hangup.done(tc, ended)
	}()
	var neg []byte
	if !c.TelnetNoEcho {
		neg = append(neg, tIAC, tWILL, tEcho) // el equipo hace el eco: no se repite lo tecleado en «Password:»
	}
	neg = append(neg, tIAC, tWILL, tSGA, tIAC, tDO, tNAWS, tIAC, tDO, tTType)
	if c.TelnetUnknownOption {
		neg = append(neg, tIAC, tWILL, 200)
	}
	if err := tc.raw(neg...); err != nil {
		return
	}
	s := &session{ch: tc, c: c, outputs: outputs, dev: dev, priv: c.StartPrivileged, paging: true, noEcho: c.TelnetNoEcho}
	if c.TelnetBanner != "" {
		s.write(c.TelnetBanner)
	}
	if c.TelnetLoginDelay > 0 {
		select { // un corte (Hangup) o un cliente que se va no esperan al fin del retraso
		case <-time.After(c.TelnetLoginDelay):
		case <-tc.done:
			return
		}
	}
	if s.telnetLogin() {
		s.run()
	}
}

// telnetLogin pide usuario y contraseña como IOS (tres intentos); con TelnetLinePassword, solo la contraseña de línea.
func (s *session) telnetLogin() bool {
	for range 3 {
		user := ""
		if !s.c.TelnetLinePassword {
			s.write("Username: ")
			u, err := s.readLine(true)
			if err != nil {
				return false
			}
			user = u
		}
		s.write("Password: ")
		pw, err := s.readLine(false)
		if err != nil {
			return false
		}
		if s.c.Attempts != nil {
			s.c.Attempts.Add(1)
		}
		if s.c.TelnetLinePassword && pw == s.c.Password || !s.c.TelnetLinePassword && s.dev.checkLogin(user, pw) {
			return true
		}
		if s.c.TelnetLinePassword {
			s.write("% Bad passwords\n\n")
		} else {
			s.write("% Login invalid\n\n")
		}
	}
	return false
}

// telnetConn quita la capa Telnet: Read devuelve solo datos (IAC IAC → 0xFF, CR NUL y CR LF → CR) y contesta las
// negociaciones; Write duplica 0xFF y manda un CR suelto como CR NUL (NVT, RFC 854).
type telnetConn struct {
	conn  net.Conn
	r     *bufio.Reader
	c     Config
	mu    sync.Mutex
	inCR  bool
	close sync.Once
	done  chan struct{} // se cierra con Close
}

func (tc *telnetConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		b, err := tc.r.ReadByte()
		if err != nil {
			return 0, err
		}
		if tc.inCR && (b == 0 || b == '\n') {
			tc.inCR = false
			continue
		}
		tc.inCR = b == '\r'
		if b != tIAC {
			p[0] = b
			return 1, nil
		}
		cmd, err := tc.r.ReadByte()
		if err != nil {
			return 0, err
		}
		switch cmd {
		case tIAC:
			p[0] = tIAC
			return 1, nil
		case tWILL, tWONT, tDO, tDONT:
			opt, err := tc.r.ReadByte()
			if err != nil {
				return 0, err
			}
			if err := tc.negotiate(cmd, opt); err != nil {
				return 0, err
			}
		case tSB:
			if err := tc.sub(); err != nil {
				return 0, err
			}
		}
	}
}

// negotiate anota lo que pide el cliente y contesta: rechaza lo que el simulador no ofreció y, si el cliente acepta
// TTYPE, le pide el tipo de terminal.
func (tc *telnetConn) negotiate(cmd, opt byte) error {
	tc.c.Recorder.add(fmt.Sprintf("!neg %s %d", negName[cmd], opt))
	switch {
	case cmd == tDO && !(opt == tSGA || opt == tEcho && !tc.c.TelnetNoEcho):
		return tc.raw(tIAC, tWONT, opt)
	case cmd == tWILL && opt == tTType:
		return tc.raw(tIAC, tSB, tTType, tTTypeSend, tIAC, tSE)
	case cmd == tWILL && opt != tNAWS:
		return tc.raw(tIAC, tDONT, opt)
	}
	return nil
}

// sub lee una subnegociación hasta IAC SE (IAC IAC adentro es un 0xFF); NAWS y TTYPE IS van al Recorder.
func (tc *telnetConn) sub() error {
	var b []byte
	for len(b) <= sbMax {
		c, err := tc.r.ReadByte()
		if err != nil {
			return err
		}
		if c == tIAC {
			if c, err = tc.r.ReadByte(); err != nil {
				return err
			}
			if c == tSE {
				switch {
				case len(b) == 5 && b[0] == tNAWS:
					tc.c.Recorder.add(fmt.Sprintf("!naws %dx%d", int(b[1])<<8|int(b[2]), int(b[3])<<8|int(b[4])))
				case len(b) > 2 && b[0] == tTType && b[1] == tTTypeIs:
					tc.c.Recorder.add("!ttype " + string(b[2:]))
				}
				return nil
			}
		}
		b = append(b, c)
	}
	tc.c.Recorder.add("!sb-sin-cerrar")
	return nil
}

func (tc *telnetConn) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+8)
	for i, c := range p {
		switch {
		case c == tIAC:
			out = append(out, tIAC, tIAC)
		case c == '\r' && (i+1 == len(p) || p[i+1] != '\n'):
			out = append(out, '\r', 0)
		default:
			out = append(out, c)
		}
	}
	if err := tc.raw(out...); err != nil {
		return 0, err
	}
	return len(p), nil
}

// raw escribe tal cual: la sesión y las respuestas de negociación comparten la conexión.
func (tc *telnetConn) raw(b ...byte) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	_, err := tc.conn.Write(b)
	return err
}

func (tc *telnetConn) Close() error {
	tc.close.Do(func() { tc.conn.Close(); close(tc.done) })
	return nil
}
