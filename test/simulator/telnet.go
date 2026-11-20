package simulator

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"testing"
)

// Bytes de control de Telnet (RFC 854) y las opciones que entiende el simulador.
const (
	tIAC, tSB, tSE           = 255, 250, 240
	tWILL, tWONT, tDO, tDONT = 251, 252, 253, 254
	tEcho, tSGA, tNAWS       = 1, 3, 31
)

// StartTelnet levanta el mismo equipo que Start, pero por Telnet: el login es texto («Username:»/«Password:», o solo
// «Password:» con TelnetLinePassword) y la sesión que sigue es la misma. Conns, Attempts, Recorder y Hangup valen igual;
// el tamaño que el cliente manda por NAWS queda en el Recorder como «!naws COLSxFILAS».
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
			go serveTelnet(&telnetConn{conn: conn, r: bufio.NewReader(conn), rec: c.Recorder}, c, outputs, dev)
		}
	}()
	return l.Addr().String()
}

func serveTelnet(tc *telnetConn, c Config, outputs map[string]string, dev *device) {
	defer tc.Close()
	var neg []byte
	if !c.TelnetNoEcho {
		neg = append(neg, tIAC, tWILL, tEcho) // el equipo hace el eco: no se repite lo tecleado en «Password:»
	}
	neg = append(neg, tIAC, tWILL, tSGA, tIAC, tDO, tNAWS)
	if _, err := tc.conn.Write(neg); err != nil {
		return
	}
	s := &session{ch: tc, c: c, outputs: outputs, dev: dev, priv: c.StartPrivileged, paging: true}
	if c.TelnetBanner != "" {
		s.write(c.TelnetBanner)
	}
	if !s.telnetLogin() {
		return
	}
	ended := c.Hangup.add(tc)
	s.run()
	tc.Close()
	c.Hangup.done(tc, ended)
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

// telnetConn quita la capa Telnet: Read devuelve solo datos (IAC IAC → 0xFF, CR NUL y CR LF → CR) y atiende
// las negociaciones; Write duplica 0xFF.
type telnetConn struct {
	conn  net.Conn
	r     *bufio.Reader
	rec   *Recorder
	mu    sync.Mutex
	inCR  bool
	close sync.Once
}

func (tc *telnetConn) Read(p []byte) (int, error) {
	n := 0
	for n == 0 {
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
			p[n] = b
			n++
			continue
		}
		cmd, err := tc.r.ReadByte()
		if err != nil {
			return 0, err
		}
		switch cmd {
		case tIAC:
			p[n] = tIAC
			n++
		case tWILL, tWONT, tDO, tDONT:
			if _, err := tc.r.ReadByte(); err != nil { // opción: el simulador ya ofreció lo suyo y no negocia más
				return 0, err
			}
		case tSB:
			if err := tc.sub(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

// sub lee una subnegociación hasta IAC SE; NAWS (ancho y alto, 16 bits cada uno) va al Recorder.
func (tc *telnetConn) sub() error {
	var b []byte
	for {
		c, err := tc.r.ReadByte()
		if err != nil {
			return err
		}
		if c == tIAC {
			if c, err = tc.r.ReadByte(); err != nil {
				return err
			}
			if c == tSE {
				break
			}
		}
		b = append(b, c)
	}
	if len(b) == 5 && b[0] == tNAWS {
		tc.rec.add(fmt.Sprintf("!naws %dx%d", int(b[1])<<8|int(b[2]), int(b[3])<<8|int(b[4])))
	}
	return nil
}

func (tc *telnetConn) Write(p []byte) (int, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	out := make([]byte, 0, len(p))
	for _, c := range p {
		if c == tIAC {
			out = append(out, tIAC)
		}
		out = append(out, c)
	}
	if _, err := tc.conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (tc *telnetConn) Close() error {
	tc.close.Do(func() { tc.conn.Close() })
	return nil
}
