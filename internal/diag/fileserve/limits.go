package fileserve

import (
	"crypto/subtle"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Topes de las conexiones de FTP y SSH.
const (
	maxConns     = 16 // simultáneas en total
	perClientTCP = 4  // simultáneas por IP de origen
	maxAuthFails = 5  // contraseñas erróneas por IP antes de cerrarle la puerta
	idleTimeout  = 2 * time.Minute
)

// authWindow es el plazo absoluto para autenticarse en FTP y SSH: lo que se haga antes (NOOP,
// USER, bytes sueltos del handshake) no lo renueva. Variable solo para las pruebas.
var authWindow = 30 * time.Second

// limiter acota conexiones y reintentos de contraseña: nadie acapara cupos ni adivina la
// contraseña a fuerza bruta (aun con 80 bits, el servidor no regala intentos).
type limiter struct {
	mu    sync.Mutex
	n     int
	perIP map[string]int
	fails map[string]int
}

func newLimiter() *limiter { return &limiter{perIP: map[string]int{}, fails: map[string]int{}} }

// acquire reserva un cupo para ip; release lo devuelve.
func (l *limiter) acquire(ip string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n >= maxConns || l.perIP[ip] >= perClientTCP || l.fails[ip] >= maxAuthFails {
		return nil, false
	}
	l.n++
	l.perIP[ip]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.n--
		if l.perIP[ip]--; l.perIP[ip] == 0 {
			delete(l.perIP, ip)
		}
	}, true
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	l.fails[ip]++
	l.mu.Unlock()
}

func (l *limiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fails[ip] >= maxAuthFails
}

// credsOK compara usuario y contraseña en tiempo constante, sin cortocircuito.
func credsOK(user, pass, wantUser, wantPass string) bool {
	u := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser))
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(wantPass))
	return u&p == 1
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// idleConn renueva el plazo en cada lectura y escritura: una conexión callada se cierra.
// until es un tope absoluto (0 = sin tope) que la actividad no renueva: el plazo para autenticarse.
type idleConn struct {
	net.Conn
	d, until atomic.Int64
}

// setUntil fija el plazo absoluto (cero lo quita).
func (c *idleConn) setUntil(t time.Time) {
	if t.IsZero() {
		c.until.Store(0)
		return
	}
	c.until.Store(t.UnixNano())
}

func (c *idleConn) deadline() time.Time {
	dl := time.Now().Add(time.Duration(c.d.Load()))
	if u := c.until.Load(); u != 0 && u < dl.UnixNano() {
		return time.Unix(0, u)
	}
	return dl
}

func newIdleConn(c net.Conn, d time.Duration) *idleConn {
	ic := &idleConn{Conn: c}
	ic.setIdle(d)
	return ic
}

func (c *idleConn) setIdle(d time.Duration) { c.d.Store(int64(d)) }

func (c *idleConn) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(c.deadline())
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	c.Conn.SetWriteDeadline(c.deadline())
	return c.Conn.Write(p)
}
