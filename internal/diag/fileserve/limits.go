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

// httpWriteIdle es el plazo sin avanzar una escritura HTTP (se renueva en cada Write): un cliente que no lee
// suelta su cupo, y una imagen grande por un enlace lento sigue mientras avance. Variable solo para las pruebas.
var httpWriteIdle = 2 * time.Minute

// lockoutFor es lo que dura el bloqueo de un origen por contraseñas erróneas, contado desde su último fallo.
const lockoutFor = 5 * time.Minute

// limiter acota conexiones y reintentos de contraseña: nadie acapara cupos ni adivina la
// contraseña a fuerza bruta (aun con 80 bits, el servidor no regala intentos).
type limiter struct {
	mu    sync.Mutex
	n     int
	perIP map[string]int
	fails map[string]failState
	now   func() time.Time // reloj del núcleo
}

type failState struct {
	n    int
	last time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{perIP: map[string]int{}, fails: map[string]failState{}, now: now}
}

// acquire reserva un cupo para ip; release lo devuelve.
func (l *limiter) acquire(ip string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n >= maxConns || l.perIP[ip] >= perClientTCP || l.blockedLocked(ip) {
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
	defer l.mu.Unlock()
	l.blockedLocked(ip) // si el bloqueo ya venció, vuelve a contar desde cero
	f := l.fails[ip]
	l.fails[ip] = failState{f.n + 1, l.now()}
}

func (l *limiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.blockedLocked(ip)
}

// blockedLocked dice si ip sigue bloqueada; un bloqueo vencido se borra. Con l.mu tomado.
func (l *limiter) blockedLocked(ip string) bool {
	f, ok := l.fails[ip]
	if ok && l.now().Sub(f.last) >= lockoutFor { // los fallos también vencen, no solo el bloqueo
		delete(l.fails, ip)
		return false
	}
	return f.n >= maxAuthFails
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

// Cupo de auditoría de HTTP: por IP y ventana, auditPerWindow respuestas se auditan (la primera siempre); el resto
// solo se cuenta como rechazo, salvo cuerpos de bigBody o más, que siempre se auditan.
const (
	auditPerWindow = 5
	auditWindow    = time.Minute
	bigBody        = 1 << 20
	maxSeenIPs     = 4096
)

// auditQuota lleva el cupo de auditoría por IP y ventana. El mapa se acota a maxSeenIPs: lleno y sin ventanas
// vencidas que podar, una IP nueva no entra y se cuenta como rechazo (solo las grandes se auditan).
type auditQuota struct {
	mu    sync.Mutex
	m     map[string]*auditWin
	now   func() time.Time
	prune time.Time // última poda de ventanas vencidas (a lo más una por ventana)
}

type auditWin struct {
	start time.Time
	n     int
}

func newAuditQuota(now func() time.Time) *auditQuota {
	return &auditQuota{m: map[string]*auditWin{}, now: now}
}

// take dice si esta respuesta de ip entra al cupo de auditoría.
func (q *auditQuota) take(ip string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	w := q.m[ip]
	if w == nil {
		if len(q.m) >= maxSeenIPs && now.Sub(q.prune) >= auditWindow {
			q.prune = now
			for k, v := range q.m {
				if now.Sub(v.start) >= auditWindow {
					delete(q.m, k)
				}
			}
		}
		if len(q.m) >= maxSeenIPs {
			return false
		}
		q.m[ip] = &auditWin{start: now, n: 1}
		return true
	}
	if now.Sub(w.start) >= auditWindow {
		w.start, w.n = now, 1
		return true
	}
	if w.n < auditPerWindow {
		w.n++
		return true
	}
	return false
}

// ipBusy dice si ip llegó a su tope de conexiones simultáneas (y no solo el global).
func (l *limiter) ipBusy(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perIP[ip] >= perClientTCP
}
