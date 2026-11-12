package core

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/core/power"
	"github.com/oom-netsec/MACUAHUITL/internal/engine"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

// Options ajusta el núcleo; los ceros toman los valores de la spec.
type Options struct {
	Inhibitor      power.Inhibitor // nil = power.Noop
	Now            func() time.Time
	MaxSessions    int           // 50 (spec §6)
	IdleLock       time.Duration // 15 min (spec §10.3)
	VaultParams    *vault.Params // nil = calibrar Argon2id a ~1 s
	HardenWarnings []string
	Actor          string                       // usuario de Linux; vacío = el actual
	RetryBackoff   []time.Duration              // nil = 1 s, 2 s, 4 s
	DiagLookPath   func(string) (string, error) // nil = exec.LookPath; las pruebas apuntan a dobles
	ErrOut         io.Writer                    // dónde avisar una entrada de auditoría perdida; nil = os.Stderr
}

type job struct {
	jobHistory
	id        string
	spec      patrol.Spec
	state     string // created, arming, armed, completed, cancelled, failed (núcleo caído con el trabajo armado)
	creds     []string
	verified  map[string]bool
	changes   []patrol.HostKeyChange
	writer    *patrol.Writer
	results   map[int][]patrol.DeviceResult
	release   func()
	paused    bool
	rounds    int        // rondas terminadas, para el manifest
	persistMu sync.Mutex // serializa foto y escritura de persistJob: la última foto es la última en llegar a la base
}

// jobHistory es lo que se guarda del trabajo además del Spec (columna history_json).
type jobHistory struct {
	ArmedAt   time.Time `json:"armedAt"`
	Until     time.Time `json:"until"`
	OutputDir string    `json:"outputDir,omitempty"` // carpeta de la corrida, al armar
	Round     int       `json:"round,omitempty"`     // ronda en curso o la última
	OK        int       `json:"ok,omitempty"`        // equipos de esa ronda que terminaron bien
	Failed    int       `json:"failed,omitempty"`
	Phases    []phase   `json:"phases,omitempty"`
	FinishErr string    `json:"finishErr,omitempty"` // por qué no cerró el manifest o el zip; sobrevive al reinicio
}

type phase struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // nombre de v1.JobPhaseKind: sobrevive a reordenar el enum
	Round  int       `json:"round,omitempty"`
	Detail string    `json:"detail,omitempty"` // en es
	// Reason es el código phase.* del catálogo y Args sus argumentos; vacíos en las fases guardadas antes del catálogo.
	Reason string            `json:"reason,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

const maxPhases = 200

// enterRound reinicia los conteos al empezar una ronda nueva. Requiere c.mu.
func (j *job) enterRound(round int) {
	if round > j.Round {
		j.Round, j.OK, j.Failed = round, 0, 0
	}
}

// Core es el núcleo: dueño de la bóveda, el motor, la red y la auditoría.
type Core struct {
	p        Paths
	o        Options
	db       *sql.DB
	log      *audit.Log
	guard    *transport.Guard
	hosts    *transport.KnownHosts
	settings *service.CoreSettings // preferencias del núcleo; viven en preferences (core.*)
	pbs      []playbook.Playbook
	bus      *engine.Bus
	sched    *engine.Scheduler

	mu       sync.Mutex
	vault    *vault.Vault
	jobs     map[string]*job
	activity time.Time
	stop     chan struct{}
	watchers sync.WaitGroup
	closers  []func() // de los servicios (service.Deps.OnClose); corren antes de cerrar la base

	respaldos respaldoStore // vistas previas de import de respaldos de la bóveda (con credenciales descifradas)
}

func New(p Paths, o Options) (*Core, error) {
	if o.Inhibitor == nil {
		o.Inhibitor = power.Noop{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ErrOut == nil {
		o.ErrOut = os.Stderr
	}
	if o.MaxSessions == 0 {
		o.MaxSessions = 50
	}
	if o.IdleLock == 0 {
		o.IdleLock = 15 * time.Minute
	}
	if o.Actor == "" {
		if u, err := user.Current(); err == nil {
			o.Actor = u.Username
		}
	}
	for _, d := range []string{p.Config, p.Data, p.State} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("core: %w", err)
		}
	}
	db, err := store.Open(filepath.Join(p.Data, "macuahuitl.db"))
	if err != nil {
		return nil, err
	}
	c := &Core{p: p, o: o, db: db, jobs: map[string]*job{}, activity: o.Now(), stop: make(chan struct{})}
	c.settings = service.NewCoreSettings(p.Outputs, p.Home, p.Config, p.Data, p.State, p.Runtime)
	c.log = audit.New(db, o.Now)
	// Se revalida la carpeta de salidas guardada (dueño, 0700, ancestros): si ya no vale rige la de fábrica y queda en la auditoría.
	if err := c.settings.Load(db, func(dir string) error { _, err := service.CheckOutputs(dir, c.settings, false); return err }); err != nil {
		db.Close()
		return nil, fmt.Errorf("core: preferencias: %w", err)
	}
	if c.settings.Issue() != "" {
		c.audit("prefs.core", "core", c.settings.IssueAudit())
	}
	c.guard = transport.NewGuard(nil, func(e audit.Entry) { c.audit(e.Action, e.Target, e.Detail) })
	if c.hosts, err = transport.OpenKnownHosts(filepath.Join(p.Data, "known_hosts")); err != nil {
		return nil, err
	}
	if c.pbs, err = loadPlaybooks(p.Config); err != nil {
		return nil, err
	}
	if _, err := os.Stat(c.vaultPath()); err == nil {
		if c.vault, err = vault.Open(c.vaultPath()); err != nil {
			return nil, err
		}
		c.vault.SetClock(o.Now)
		c.vault.OnLock(c.respaldos.wipeAll)
	}
	c.bus = engine.NewBus(256)
	c.sched = engine.NewScheduler(engine.NewRunner(o.MaxSessions, c.bus), c.bus, o.Now)
	c.loadJobs()
	for _, w := range o.HardenWarnings {
		c.audit("harden.warning", "", w)
	}
	go c.idleLoop()
	return c, nil
}

func loadPlaybooks(config string) ([]playbook.Playbook, error) {
	pbs, err := playbook.Load(playbooks.FS)
	if err != nil {
		return nil, err
	}
	user := filepath.Join(config, "playbooks")
	if _, err := os.Stat(user); err == nil {
		extra, err := playbook.Load(os.DirFS(user))
		if err != nil {
			return nil, err
		}
		for _, e := range extra { // mismo id: el del usuario reemplaza al embebido (patrol corre el primero que coincide)
			if i := slices.IndexFunc(pbs, func(p playbook.Playbook) bool { return p.ID == e.ID }); i >= 0 {
				pbs[i] = e
			} else {
				pbs = append(pbs, e)
			}
		}
	}
	return pbs, nil
}

func (c *Core) vaultPath() string { return filepath.Join(c.p.Data, "vault.mcv") }

// audit reintenta una vez; si aun así falla, avisa con la acción perdida
// en vez de descartarla en silencio (la bitácora es de seguridad).
// shortcut: no falla la operación auditada, solo avisa; endurecer si se exige "sin auditoría no hay acción".
func (c *Core) audit(action, target, detail string) {
	e := audit.Entry{Actor: c.o.Actor, Action: action, Target: target, Detail: detail}
	_, err := c.log.Append(context.Background(), e)
	if err != nil {
		_, err = c.log.Append(context.Background(), e)
	}
	if err != nil {
		fmt.Fprintf(c.o.ErrOut, "macuahuitld: auditoría perdida accion=%q objetivo=%q: %v\n", action, target, err)
	}
}

// Serve atiende gRPC en l hasta que ctx termine.
func (c *Core) Serve(ctx context.Context, l ipc.Listener) error {
	return ipc.Serve(ctx, l, func(s ipc.Registrar) {
		d := coreDeps{c}
		for _, m := range modules(c) {
			m.Register(s, d)
		}
	}, ipc.LocaleOptions()...)
}

func (c *Core) Close() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	c.mu.Lock()
	for id := range c.jobs {
		c.sched.Cancel(id)
	}
	c.mu.Unlock()
	// Los servicios con trabajo en vuelo lo cancelan y lo esperan (auditándolo) mientras la base sigue abierta.
	c.mu.Lock()
	closers := c.closers
	c.closers = nil
	c.mu.Unlock()
	for i := len(closers) - 1; i >= 0; i-- {
		closers[i]()
	}
	// Esperar a que cada trabajo escriba su manifest y su auditoría antes de cerrar la base.
	done := make(chan struct{})
	go func() { c.watchers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	c.respaldos.wipeAll()
	c.db.Close()
}

// markActive registra uso. Solo lo llaman las acciones del ingeniero (abrir, guardar, crear,
// armar…), no las consultas: una UI que consulta el estado no debe mantener la bóveda abierta.
func (c *Core) markActive() {
	c.mu.Lock()
	c.activity = c.o.Now()
	c.mu.Unlock()
}

// idleLoop cierra la bóveda tras IdleLock sin actividad; las ventanas armadas siguen (spec §10.3).
func (c *Core) idleLoop() {
	t := time.NewTicker(c.o.IdleLock / 4)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		// Decidir y cerrar en la misma sección: un RPC que empieza espera aquí y no encuentra
		// la bóveda cerrada a medias.
		c.mu.Lock()
		locked := false
		if c.vault != nil && c.o.Now().Sub(c.activity) >= c.o.IdleLock && c.vault.Unlocked() {
			c.vault.Lock()
			locked = true
		}
		c.mu.Unlock()
		if locked {
			c.audit("vault.lock", "", "reason=idle")
		}
	}
}

func (c *Core) vaultState() v1.VaultState {
	c.mu.Lock()
	v := c.vault
	c.mu.Unlock()
	if v == nil {
		return v1.VaultState_VAULT_STATE_ABSENT
	}
	if !v.Unlocked() {
		return v1.VaultState_VAULT_STATE_LOCKED
	}
	return v1.VaultState_VAULT_STATE_UNLOCKED
}

// OnSleep: suspensión o apagado. Cierra todo y pausa los trabajos armados (spec §10.4).
func (c *Core) OnSleep() {
	c.mu.Lock()
	if c.vault != nil {
		c.vault.LockAll()
	}
	for _, j := range c.jobs {
		if j.state == "armed" {
			j.paused = true
			c.sched.Pause(j.id)
		}
	}
	c.mu.Unlock()
	c.audit("power.sleep", "", "vault locked and jobs paused")
}

// OnLock: pantalla bloqueada. Cierre interactivo; las ventanas armadas siguen.
func (c *Core) OnLock() {
	c.mu.Lock()
	v := c.vault
	c.mu.Unlock()
	if v != nil {
		v.Lock()
		c.audit("vault.lock", "", "reason=screen_locked")
	}
}

// resumePaused vuelve a abrir las ventanas de los trabajos pausados tras un Unlock.
func (c *Core) resumePaused() {
	c.mu.Lock()
	var paused []*job
	for _, j := range c.jobs {
		if j.paused && j.state == "armed" {
			paused = append(paused, j)
		}
	}
	v := c.vault
	c.mu.Unlock()
	for _, j := range paused {
		if err := v.Arm(j.id, j.Until, j.creds); err != nil {
			c.audit("job.resume_failed", j.id, i18n.English(err))
			continue
		}
		c.mu.Lock()
		j.paused = false
		c.mu.Unlock()
		c.sched.Resume(j.id)
		c.audit("job.resume", j.id, "")
	}
}

func (c *Core) deps(j *job) patrol.Deps {
	c.mu.Lock()
	v, verified := c.vault, j.verified
	c.mu.Unlock()
	return patrol.Deps{Guard: c.guard, Hosts: c.hosts, Vault: v, Audit: c.log, Now: c.o.Now, Playbooks: c.pbs,
		PrimaryVerified: verified, RetryBackoff: c.o.RetryBackoff}
}

func (c *Core) getJob(id string) (*job, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, ok := c.jobs[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "trabajo %s no existe", id)
	}
	return j, nil
}

func (c *Core) persistJob(j *job) {
	j.persistMu.Lock() // antes de c.mu; nadie toma persistMu con c.mu en la mano
	defer j.persistMu.Unlock()
	c.mu.Lock()
	b, _ := json.Marshal(j.spec) // el Spec no contiene secretos, solo IDs de credenciales
	h, _ := json.Marshal(j.jobHistory)
	name, state := j.spec.Name, j.state
	c.mu.Unlock()
	c.db.Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at,history_json) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET state=excluded.state, history_json=excluded.history_json`,
		j.id, name, string(b), state, c.o.Now().UTC().Format(time.RFC3339), string(h))
}

// loadJobs recupera los trabajos guardados. Uno que quedó armado o armándose es de un núcleo
// que cayó: su ventana y su motor ya no existen, así que se marca como fallido.
func (c *Core) loadJobs() {
	rows, err := c.db.Query(`SELECT id, spec_json, state, history_json FROM jobs`)
	if err != nil {
		c.audit("job.load_failed", "", i18n.English(err))
		return
	}
	var dead []*job
	for rows.Next() {
		var id, spec, state, hist string
		if err := rows.Scan(&id, &spec, &state, &hist); err != nil {
			c.audit("job.load_failed", "", i18n.English(err))
			continue
		}
		j := &job{id: id, state: state, results: map[int][]patrol.DeviceResult{}}
		if err := json.Unmarshal([]byte(spec), &j.spec); err != nil {
			c.audit("job.load_failed", id, i18n.English(err))
			continue
		}
		json.Unmarshal([]byte(hist), &j.jobHistory) // '{}' en trabajos guardados antes del historial
		if state == "armed" || state == "arming" {
			j.state = "failed"
			dead = append(dead, j)
		}
		c.jobs[id] = j
	}
	rows.Close()
	for _, j := range dead {
		c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, j.Round, "phase.core_stopped", nil)
	}
}

// addPhase agrega una fase al historial (acotado a maxPhases), la publica en vivo y guarda el trabajo.
// code es un código phase.* del catálogo (vacío = sin detalle): el detalle se guarda en es, con su motivo y argumentos
// para traducirlo al leerlo.
func (c *Core) addPhase(j *job, k v1.JobPhaseKind, round int, code string, args i18n.Args) {
	p := phase{At: c.o.Now(), Kind: k.String(), Round: round}
	if code != "" {
		p.Detail, p.Reason, p.Args = i18n.Msg(i18n.Es, code, args), code, i18n.Metadata(code, args)
	}
	c.mu.Lock()
	j.Phases = append(j.Phases, p)
	if n := len(j.Phases); n > maxPhases {
		j.Phases = j.Phases[n-maxPhases:]
	}
	c.mu.Unlock()
	c.bus.Publish(engine.Event{At: p.At, JobID: j.id, Kind: engine.Phase, State: p.Kind, Index: round, Detail: p.Detail, Reason: p.Reason, Args: p.Args})
	c.persistJob(j)
}

// phaseToProto da la fase con su detalle en el idioma loc; las guardadas antes del catálogo no traen motivo y salen en es.
func phaseToProto(loc string, p phase) *v1.JobPhase {
	detail := p.Detail
	if p.Reason != "" && loc != i18n.Es {
		detail = i18n.Msg(loc, p.Reason, p.Args)
	}
	return &v1.JobPhase{At: timestamppb.New(p.At), Kind: v1.JobPhaseKind(v1.JobPhaseKind_value[p.Kind]), Round: uint32(p.Round), Detail: detail, Reason: p.Reason, Args: p.Args}
}

func tsOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// summary arma el JobSummary. Requiere c.mu.
func (c *Core) summary(loc string, j *job) *v1.JobSummary {
	sc := j.spec.Schedule
	rounds := sc.Rounds
	if sc.IntervalSeconds == 0 && sc.Cron == "" {
		rounds = 1 // sin intervalo ni cron el motor corre una sola ronda
	}
	out := j.OutputDir
	if out == "" {
		out = j.spec.OutputDir
	}
	s := &v1.JobSummary{JobId: j.id, Name: j.spec.Name, State: j.state, NextRoundAt: tsOrNil(c.sched.NextRound(j.id)),
		ArmedAt: tsOrNil(j.ArmedAt), WindowEndsAt: tsOrNil(j.Until), Round: uint32(j.Round), Rounds: rounds,
		DevicesTotal: uint32(len(j.spec.Targets)), DevicesOk: uint32(j.OK), DevicesFailed: uint32(j.Failed), OutputDir: out, Kind: cmp.Or(j.spec.Kind, "patrol")}
	for _, p := range j.Phases {
		s.Phases = append(s.Phases, phaseToProto(loc, p))
	}
	return s
}
