package service

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/transfer"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Registro de sesiones de transferencia en vivo (fase 45b). Lo comparten TransferService (StartServer) y
// FieldService.ServeFiles, y por eso vive aquí: archcheck no deja que un servicio importe el de otra área, y
// service es lo único que ambos pueden importar. Hay una sola instancia, armada en core y entregada por Deps.
//
// Candados: reg.mu y srv.mu nunca se toman a la vez, y reg.mu es hoja (no se toma nada con él tomado). Open corre con
// el candado del servicio (svc.mu) tomado: por eso solo toma reg.mu. El bucle de datos no pasa por aquí (solo atómicos de Live).
const (
	sessionRing   = 100              // terminadas que se conservan por servidor
	closedKeep    = 10 * time.Minute // vida de un servidor cerrado
	closedMax     = 8                // servidores cerrados que se conservan
	rejectionCap  = 32               // grupos de rechazos por servidor
	rejectionName = 128              // caracteres del último nombre rechazado
	rateWindow    = time.Second
)

// progress es lo que el registro lee de una transferencia en curso (*fileserve.Live; las pruebas ponen otra).
type progress interface {
	Bytes() int64
	Total() int64
}

type liveMeta struct{ proto, client, name, dir string }

type session struct {
	id, serverID, proto, client, name, dir string
	p                                      progress
	started, ended                         time.Time
	state                                  string // active | done | failed
	bytes, total                           int64
	err                                    string
	reason                                 i18n.Text
	sampleBytes                            int64 // muestra de la tasa
	sampleAt                               time.Time
	rate                                   float64
	sampled                                bool
}

type rejKey struct{ ip, cause string }

type rejection struct {
	proto, name, err string
	reason           i18n.Text
	count            int64
	first, last      time.Time
}

// TransferSessions es el registro: servidores abiertos y los cerrados que aún se conservan.
type TransferSessions struct {
	now    func() time.Time
	mu     sync.Mutex
	open   map[*SessionServer]struct{}
	closed []*SessionServer // el más viejo primero
}

func NewTransferSessions(now func() time.Time) *TransferSessions {
	return &TransferSessions{now: now, open: map[*SessionServer]struct{}{}}
}

// SessionServer son las sesiones y rechazos de un servidor. Todos los métodos son seguros con nil.
type SessionServer struct {
	reg      *TransferSessions
	id       string
	mu       sync.Mutex
	active   map[progress]*session
	recent   []*session // la más vieja primero
	rej      map[rejKey]*rejection
	closedAt time.Time
}

// Open registra un servidor abierto con su id.
func (r *TransferSessions) Open(id string) *SessionServer {
	s := &SessionServer{reg: r, id: id, active: map[progress]*session{}, rej: map[rejKey]*rejection{}}
	r.mu.Lock()
	r.open[s] = struct{}{}
	r.mu.Unlock()
	return s
}

// purge quita los cerrados vencidos y los que pasen del tope. Con r.mu tomado.
func (r *TransferSessions) purge(now time.Time) {
	i := 0
	for i < len(r.closed) && now.Sub(r.closed[i].closedAt) >= closedKeep {
		i++
	}
	r.closed = r.closed[i:]
	if len(r.closed) > closedMax {
		r.closed = r.closed[len(r.closed)-closedMax:]
	}
}

// close marca el servidor como cerrado. Uno sin sesiones ni rechazos (p. ej. un bind fallido) no se conserva:
// no debe ocupar uno de los cupos de cerrados.
func (s *SessionServer) close() {
	now := s.reg.now()
	s.mu.Lock()
	s.closedAt = now
	empty := len(s.active) == 0 && len(s.recent) == 0 && len(s.rej) == 0
	s.mu.Unlock()
	s.reg.mu.Lock()
	delete(s.reg.open, s)
	if !empty {
		s.reg.closed = append(s.reg.closed, s)
	}
	s.reg.purge(now)
	s.reg.mu.Unlock()
}

// Start es OnStart: abre la sesión de l.
func (s *SessionServer) Start(l *fileserve.Live) {
	if s == nil || l == nil {
		return
	}
	s.start(liveMeta{l.Proto, l.Client, l.File, l.Dir}, l)
}

func (s *SessionServer) start(m liveMeta, p progress) {
	name, _ := transfer.SanitizeName(m.name)
	x := &session{id: NewID(), serverID: s.id, proto: m.proto, client: m.client, name: name, dir: m.dir, p: p, started: s.reg.now(), state: "active"}
	s.mu.Lock()
	s.active[p] = x
	s.mu.Unlock()
}

// Finish es OnTransfer de una transferencia que empezó: cierra su sesión y da su id y su total (para la auditoría).
// Sin sesión (HEAD, 304…) devuelve "".
func (s *SessionServer) Finish(t fileserve.Transfer) (id string, total int64) {
	if s == nil || t.Live == nil {
		return "", 0
	}
	return s.finish(t.Live, t)
}

func (s *SessionServer) finish(p progress, t fileserve.Transfer) (string, int64) {
	now := s.reg.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.active[p]
	if x == nil {
		return "", 0
	}
	delete(s.active, p)
	x.ended, x.bytes, x.total = now, p.Bytes(), p.Total()
	x.state = "done"
	if t.Result != "ok" {
		x.state, x.err, x.reason = "failed", shown(t.Error), shownText(t.ReasonT)
	}
	x.p = nil
	s.addRecent(x)
	return x.id, x.total
}

// Stranded es una sesión cerrada por el cierre de seguridad, con lo necesario para auditarla.
type Stranded struct {
	ID    string
	Total int64
	T     fileserve.Transfer // fallida «stopped», con su Live
}

// Shutdown es el cierre de seguridad cuando fileserve.Serve ya volvió: pasa a failed «stopped» (de una vez, bajo el
// candado: un OnTransfer tardío ya no las encuentra y no se auditan dos veces) toda sesión que siga activa, llama a
// each con cada una (para auditarla) y cierra el servidor en el registro.
func (s *SessionServer) Shutdown(each func(Stranded)) {
	if s == nil {
		return
	}
	for _, x := range s.stranded() {
		each(x)
	}
	s.close()
}

func (s *SessionServer) stranded() []Stranded {
	now := s.reg.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Stranded
	for p, x := range s.active {
		t := fileserve.Transfer{Proto: x.proto, Client: x.client, File: x.name, Dir: x.dir, Bytes: p.Bytes(), Duration: now.Sub(x.started),
			Result: "error", Error: i18n.Msg(i18n.Es, "fileserve.reason.stopped", nil), ReasonT: i18n.Tx("fileserve.reason.stopped")}
		if l, ok := p.(*fileserve.Live); ok {
			t.Live = l
		}
		delete(s.active, p)
		x.ended, x.bytes, x.total = now, p.Bytes(), p.Total()
		x.state, x.err, x.reason, x.p = "failed", t.Error, t.ReasonT, nil
		s.addRecent(x)
		out = append(out, Stranded{ID: x.id, Total: x.total, T: t})
	}
	return out
}

func (s *SessionServer) addRecent(x *session) {
	s.recent = append(s.recent, x)
	if len(s.recent) > sessionRing {
		s.recent = s.recent[len(s.recent)-sessionRing:]
	}
}

// Reject cuenta un rechazo en su grupo (IP sin puerto, causa).
func (s *SessionServer) Reject(t fileserve.Transfer) {
	if s == nil {
		return
	}
	ip := t.Client
	if ap, err := netip.ParseAddrPort(t.Client); err == nil {
		ip = ap.Addr().Unmap().String()
	} else if a, err := netip.ParseAddr(t.Client); err == nil {
		ip = a.Unmap().String()
	}
	name := shown(t.File)
	now := s.reg.now()
	k := rejKey{ip, t.Cause}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.rej[k]
	if g == nil {
		if len(s.rej) >= rejectionCap {
			var old rejKey
			var oldAt time.Time
			for kk, v := range s.rej {
				if oldAt.IsZero() || v.last.Before(oldAt) {
					old, oldAt = kk, v.last
				}
			}
			delete(s.rej, old)
		}
		g = &rejection{first: now}
		s.rej[k] = g
	}
	g.count++
	g.last, g.proto, g.name, g.err, g.reason = now, t.Proto, name, shown(t.Error), shownText(t.ReasonT)
}

// List arma la respuesta para serverID ("" = todos) en el idioma loc. found=false: id desconocido o vencido.
func (r *TransferSessions) List(serverID, loc string) (sess []*v1.TransferSession, rej []*v1.TransferRejection, found bool) {
	now := r.now()
	r.mu.Lock()
	r.purge(now)
	var servers []*SessionServer
	for s := range r.open {
		servers = append(servers, s)
	}
	servers = append(servers, r.closed...)
	r.mu.Unlock()
	if serverID != "" {
		keep := servers[:0]
		for _, s := range servers {
			if s.id == serverID {
				keep = append(keep, s)
			}
		}
		if servers = keep; len(servers) == 0 {
			return nil, nil, false
		}
	}
	for _, s := range servers {
		a, b := s.snapshot(now, loc)
		sess, rej = append(sess, a...), append(rej, b...)
	}
	// Activas primero (la más antigua arriba); luego las terminadas, la más reciente arriba.
	sort.SliceStable(sess, func(i, j int) bool {
		a, b := sess[i], sess[j]
		if (a.Ended == 0) != (b.Ended == 0) {
			return a.Ended == 0
		}
		if a.Ended == 0 {
			return a.Started < b.Started
		}
		return a.Ended > b.Ended
	})
	sort.SliceStable(rej, func(i, j int) bool { return rej[i].Last > rej[j].Last })
	return sess, rej, true
}

func (s *SessionServer) snapshot(now time.Time, loc string) (sess []*v1.TransferSession, rej []*v1.TransferRejection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.active {
		sess = append(sess, s.view(x, now, loc))
	}
	for _, x := range s.recent {
		sess = append(sess, s.view(x, now, loc))
	}
	for k, g := range s.rej {
		t := fileserve.Transfer{Error: g.err, ReasonT: g.reason}
		rej = append(rej, &v1.TransferRejection{ServerId: s.id, Ip: k.ip, Protocol: g.proto, Cause: k.cause, Name: g.name, Count: g.count,
			First: g.first.UnixMilli(), Last: g.last.UnixMilli(), Reason: fileserve.ReasonIn(loc, t), ReasonCode: g.reason.Key})
	}
	return sess, rej
}

// view arma la sesión para el cliente; con s.mu tomado (renueva la muestra de la tasa).
func (s *SessionServer) view(x *session, now time.Time, loc string) *v1.TransferSession {
	dir := "out"
	if x.dir == "escritura" || x.dir == "write" {
		dir = "in"
	}
	v := &v1.TransferSession{Id: x.id, ServerId: x.serverID, Client: x.client, Name: x.name, Direction: dir, Protocol: x.proto,
		Bytes: x.bytes, Total: x.total, Started: x.started.UnixMilli(), State: x.state}
	if x.state == "active" {
		v.Bytes, v.Total = x.p.Bytes(), x.p.Total()
		switch dt := now.Sub(x.sampleAt); {
		case !x.sampled:
			x.rate = perSec(v.Bytes, now.Sub(x.started))
			x.sampleBytes, x.sampleAt, x.sampled = v.Bytes, now, true
		case dt >= rateWindow:
			x.rate = perSec(v.Bytes-x.sampleBytes, dt)
			x.sampleBytes, x.sampleAt = v.Bytes, now
		}
		v.BytesPerSec = x.rate
		return v
	}
	v.Ended = x.ended.UnixMilli()
	v.BytesPerSec = perSec(x.bytes, x.ended.Sub(x.started))
	if x.state == "failed" {
		v.Error, v.ErrorCode = fileserve.ReasonIn(loc, fileserve.Transfer{Error: x.err, ReasonT: x.reason}), x.reason.Key
	}
	return v
}

// shown deja un texto que pudo venir del par listo para guardar y mostrar: saneado y de a lo más 128 runas.
func shown(s string) string {
	if len(s) > 4*rejectionName {
		s = s[:4*rejectionName]
	}
	s, _ = transfer.SanitizeName(s)
	if r := []rune(s); len(r) > rejectionName {
		s = string(r[:rejectionName])
	}
	return s
}

// shownText es t con los argumentos saneados y cortos (copia: el mapa original no se toca).
func shownText(t i18n.Text) i18n.Text {
	if len(t.Args) == 0 {
		return t
	}
	a := make(i18n.Args, len(t.Args))
	for k, v := range t.Args {
		a[k] = shown(v)
	}
	t.Args = a
	return t
}

func perSec(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / d.Seconds()
}
