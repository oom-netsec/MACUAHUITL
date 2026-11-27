package fileserve

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/netip"
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
	over  failState        // fallos de los orígenes que no caben en fails (mapa lleno): cuentan juntos
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
	ip = ipKey(ip)
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
	ip = ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.blockedLocked(ip) // si el bloqueo ya venció, vuelve a contar desde cero
	f, ok := l.fails[ip]
	if !ok && len(l.fails) >= maxSeenIPs {
		now := l.now()
		for k, v := range l.fails { // poda los vencidos
			if now.Sub(v.last) >= lockoutFor {
				delete(l.fails, k)
			}
		}
		if len(l.fails) >= maxSeenIPs { // lleno: los orígenes nuevos cuentan juntos en el desborde
			l.blockedLocked(ip)
			l.over = failState{l.over.n + 1, now}
			return
		}
	}
	l.fails[ip] = failState{f.n + 1, l.now()}
}

func (l *limiter) blocked(ip string) bool {
	ip = ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.blockedLocked(ip)
}

// blockedLocked dice si ip sigue bloqueada; un bloqueo vencido se borra. Con l.mu tomado. Un origen sin entrada
// propia con el mapa lleno responde por el desborde común.
func (l *limiter) blockedLocked(ip string) bool {
	f, ok := l.fails[ip]
	if !ok && len(l.fails) >= maxSeenIPs {
		if l.now().Sub(l.over.last) >= lockoutFor {
			l.over = failState{}
		}
		return l.over.n >= maxAuthFails
	}
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

// Cupo de auditoría de HTTP. Una descarga completa (GET 200 con todo el cuerpo) se audita siempre, con su sesión.
// Lo que no entrega el archivo (HEAD, 304, Range parcial, GET cortado, 416) comparte un cupo por IP: las primeras
// auditPerWindow de cada ventana se auditan y el resto se cuenta y sale en un resumen. Es por IP y no por archivo,
// así los alias del nombre (mayúsculas, 8.3, //x) no lo esquivan.
const (
	auditWindow    = time.Minute
	auditPerWindow = 5
	maxSeenIPs     = 4096
)

// liveAfter son los bytes enviados a partir de los cuales una descarga abre su sesión en vivo (antes de eso, una descarga
// que se corta aún cuenta contra el cupo); una completa la abre siempre. Las pruebas lo cambian por Config.liveAfter, y
// summaryTick (cada cuánto se vacían los resúmenes de las ventanas vencidas, auditWindow) por Config.summaryTick: el
// servidor no lee variables de paquete que una prueba cambie mientras otro servidor sigue vivo.
const liveAfter = int64(64 << 10)

// Repeats resume lo que una IP repitió dentro de una ventana sin que se auditara una por una.
type Repeats struct {
	Client      string
	N           int
	First, Last time.Time
}

// auditQuota lleva el cupo de auditoría por IP. El mapa se acota a maxSeenIPs: lleno y sin ventanas vencidas que
// podar, una IP nueva no se guarda y se audita (más seguro auditar de más que perder la primera).
type auditQuota struct {
	mu    sync.Mutex
	m     map[string]*auditWin
	now   func() time.Time
	prune time.Time // última poda en take (a lo más una por ventana)
	over  auditWin  // cupo común de los orígenes que no caben en m (mapa lleno)
}

type auditWin struct {
	start       time.Time
	n           int // respuestas de la ventana (auditadas y contadas)
	reps        int // las contadas
	first, last time.Time
}

func newAuditQuota(now func() time.Time) *auditQuota {
	return &auditQuota{m: map[string]*auditWin{}, now: now}
}

func (w *auditWin) summary(ip string) Repeats {
	return Repeats{Client: ip, N: w.reps, First: w.first, Last: w.last}
}

// take dice si esta respuesta de ip se audita; closed trae los resúmenes de las ventanas que cerró.
func (q *auditQuota) take(ip string) (allowed bool, closed []Repeats) {
	ip = ipKey(ip)
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	w := q.m[ip]
	name := ip
	if w == nil {
		if len(q.m) >= maxSeenIPs && now.Sub(q.prune) >= auditWindow {
			q.prune = now
			closed = q.expireLocked(now)
		}
		if len(q.m) < maxSeenIPs {
			w = &auditWin{}
			q.m[ip] = w
		} else {
			w, name = &q.over, overflowName
		}
	}
	if w.start.IsZero() || now.Sub(w.start) >= auditWindow {
		if w.reps > 0 {
			closed = append(closed, w.summary(name))
		}
		*w = auditWin{start: now, n: 1}
		return true, closed
	}
	if w.n < auditPerWindow {
		w.n++
		return true, closed
	}
	w.n++
	if w.reps == 0 {
		w.first = now
	}
	w.reps++
	w.last = now
	return false, closed
}

func (q *auditQuota) expireLocked(now time.Time) (out []Repeats) {
	for ip, w := range q.m {
		if now.Sub(w.start) >= auditWindow {
			if w.reps > 0 {
				out = append(out, w.summary(ip))
			}
			delete(q.m, ip)
		}
	}
	if q.over.reps > 0 && now.Sub(q.over.start) >= auditWindow {
		out = append(out, q.over.summary(overflowName))
		q.over = auditWin{}
	}
	return out
}

// overflowName es el «cliente» del resumen del cupo común de desborde.
const overflowName = "(overflow)"

// expire cierra las ventanas vencidas y devuelve sus resúmenes (vaciado periódico).
func (q *auditQuota) expire() []Repeats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.expireLocked(q.now())
}

// flush devuelve los resúmenes pendientes y vacía el cupo.
func (q *auditQuota) flush() (out []Repeats) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for ip, w := range q.m {
		if w.reps > 0 {
			out = append(out, w.summary(ip))
		}
	}
	if q.over.reps > 0 {
		out = append(out, q.over.summary(overflowName))
	}
	q.m, q.over = map[string]*auditWin{}, auditWin{}
	return out
}

// ipBusy dice si ip llegó a su tope de conexiones simultáneas (y no solo el global).
func (l *limiter) ipBusy(ip string) bool {
	ip = ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perIP[ip] >= perClientTCP
}

// ipKey es la clave de origen de los cupos: IPv4 por dirección (también la IPv4-mapped) e IPv6 por /64, sin zona,
// porque un atacante en su /64 tiene 2^64 direcciones. Lo que no es una IP queda tal cual.
func ipKey(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	a = a.WithZone("").Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// Text es el detalle de auditoría del resumen: cuántas, y desde cuándo hasta cuándo (RFC 3339).
func (r Repeats) Text() string {
	return fmt.Sprintf("repeats=%d first=%s last=%s", r.N, r.First.UTC().Format(time.RFC3339), r.Last.UTC().Format(time.RFC3339))
}
