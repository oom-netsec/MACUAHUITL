// Package bridge es la capa Go de la UI: un cliente gRPC del núcleo que expone
// métodos simples al frontend y reenvía eventos. No importa Wails para poder
// probarse sin WebKitGTK; ui/main.go lo conecta con la ventana.
//
// Las respuestas hacia el frontend nunca incluyen secretos: solo IDs, etiquetas e indicadores.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Emitter publica un evento al frontend (en Wails: app.Event.Emit).
type Emitter func(name string, data any)

type Bridge struct {
	Interval time.Duration // reintento de conexión; 1 s por defecto
	// Localize enciende el idioma del núcleo (core.localize): con true, las llamadas llevan accept-language con la
	// preferencia ui.language. Apagado por omisión: el núcleo contesta en español, como antes.
	Localize  bool
	lang      langCache
	dial      func() (*ipc.ClientConn, error)
	emit      Emitter
	mu        sync.Mutex
	conn      *ipc.ClientConn
	status    string
	ctx       context.Context               // vida del puente; los streams cuelgan de aquí, no de la llamada
	streams   map[string]*stream            // un stream de eventos por trabajo
	runs      map[string]context.CancelFunc // ejecuciones de diagnóstico en curso
	runSeq    int
	consoles  map[string]*consoleSess // consolas serie abiertas (field.go)
	terminals map[string]*termSess    // terminales SSH abiertas (terminal.go)
}

func New(dial func() (*ipc.ClientConn, error), emit Emitter) *Bridge {
	return &Bridge{Interval: time.Second, dial: dial, emit: emit, ctx: context.Background(), streams: map[string]*stream{}, runs: map[string]context.CancelFunc{}}
}

// stream es el stream de eventos de un trabajo. Su dirección es el token de generación:
// quien lo reemplaza deja otro puntero en el mapa. dead = sin goroutine leyendo; el trabajo
// sigue en el mapa para que resubscribe lo reabra al reconectar, pero Subscribe ya no lo salta.
type stream struct {
	cancel context.CancelFunc
	dead   bool
}

var ErrDisconnected = errors.New("core disconnected")

func (b *Bridge) client() (*ipc.ClientConn, error) {
	b.mu.Lock()
	if b.conn == nil {
		c, err := b.dial()
		if err != nil {
			b.mu.Unlock()
			return nil, b.disconnected()
		}
		b.conn = c
	}
	defer b.mu.Unlock()
	return b.conn, nil
}

// disconnected es ErrDisconnected en el idioma ya conocido de la app (sin núcleo no se puede leer la preferencia: si
// no se había leído, en). errors.Is(err, ErrDisconnected) sigue valiendo.
func (b *Bridge) disconnected() error {
	loc := i18n.Locale(context.Background())
	b.lang.mu.Lock()
	if b.Localize && b.lang.loaded {
		loc = b.lang.value
	}
	b.lang.mu.Unlock()
	return &Error{err: ErrDisconnected, msg: i18n.Msg(loc, "bridge.err.disconnected", nil)}
}

// Status es el último estado conocido; la UI lo pide al montar porque el primer
// core:status puede emitirse antes de que exista la ventana.
func (b *Bridge) Status() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.status == "" {
		return "disconnected"
	}
	return b.status
}

func (b *Bridge) setStatus(s string) (changed bool) {
	b.mu.Lock()
	changed = b.status != s
	b.status = s
	b.mu.Unlock()
	if changed {
		b.emit("core:status", s)
	}
	return changed
}

// Start lanza la vigilancia de la conexión. Es una función y no un método para
// que Wails no la exponga al frontend.
func Start(ctx context.Context, b *Bridge) {
	b.mu.Lock()
	b.ctx = ctx
	b.mu.Unlock()
	go b.run(ctx)
}

// run emite core:status (connected|disconnected). La verificación no cierra la conexión:
// gRPC reconecta solo, y cerrarla tumbaría las llamadas en curso.
func (b *Bridge) run(ctx context.Context) {
	t := time.NewTicker(b.Interval)
	defer t.Stop()
	for {
		c, err := b.client()
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, 5*b.Interval)
			_, err = v1.NewVaultServiceClient(c).Status(cctx, &v1.StatusRequest{})
			cancel()
		}
		if err != nil {
			b.setStatus("disconnected")
		} else if b.setStatus("connected") {
			b.resubscribe()
		}
		if err == nil {
			b.syncLanguage(c)
		}
		select {
		case <-ctx.Done():
			b.mu.Lock()
			for _, st := range b.streams {
				st.cancel()
			}
			if b.conn != nil {
				b.conn.Close()
			}
			b.mu.Unlock()
			return
		case <-t.C:
		}
	}
}

// syncLanguage manda al núcleo el idioma elegido mientras estaba caído.
func (b *Bridge) syncLanguage(c *ipc.ClientConn) {
	b.lang.mu.Lock()
	v := b.lang.pending
	b.lang.mu.Unlock()
	if v == "" {
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, 3*time.Second)
	defer cancel()
	if _, err := v1.NewPrefsServiceClient(c).SetPreference(ctx, &v1.SetPreferenceRequest{Key: langPref, Value: v}); err != nil {
		return
	}
	b.lang.mu.Lock()
	if b.lang.pending == v {
		b.lang.pending = ""
	}
	b.lang.mu.Unlock()
}

func call[T any](b *Bridge, f func(context.Context, *ipc.ClientConn) (T, error)) (T, error) {
	var zero T
	c, err := b.client()
	if err != nil {
		return zero, wrapErr(err)
	}
	// Sin plazo: el Login Test y el armado de muchos equipos pueden tardar minutos.
	r, err := f(b.callCtx(), c)
	return r, wrapErr(err)
}

// ---- Bóveda ----

type VaultStatusDTO struct {
	State     string   `json:"state"` // absent, locked, unlocked
	ArmedJobs []string `json:"armedJobs"`
}

func (b *Bridge) VaultStatus() (VaultStatusDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (VaultStatusDTO, error) {
		r, err := v1.NewVaultServiceClient(c).Status(ctx, &v1.StatusRequest{})
		if err != nil {
			return VaultStatusDTO{}, err
		}
		st := map[v1.VaultState]string{v1.VaultState_VAULT_STATE_ABSENT: "absent", v1.VaultState_VAULT_STATE_LOCKED: "locked", v1.VaultState_VAULT_STATE_UNLOCKED: "unlocked"}[r.State]
		return VaultStatusDTO{State: st, ArmedJobs: r.ArmedJobIds}, nil
	})
}

// Las contraseñas llegan del webview como string: límite declarado, no se pueden borrar.
func (b *Bridge) VaultCreate(master string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (any, error) {
		return v1.NewVaultServiceClient(c).Create(ctx, &v1.CreateRequest{MasterPassword: []byte(master)})
	})
	return err
}

func (b *Bridge) VaultUnlock(master string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (any, error) {
		return v1.NewVaultServiceClient(c).Unlock(ctx, &v1.UnlockRequest{MasterPassword: []byte(master)})
	})
	return err
}

func (b *Bridge) VaultLock() error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (any, error) {
		return v1.NewVaultServiceClient(c).Lock(ctx, &v1.LockRequest{})
	})
	return err
}

type CredentialDTO struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Username  string `json:"username"`
	HasEnable bool   `json:"hasEnable"`
	HasSSHKey bool   `json:"hasSshKey"`
}

func (b *Bridge) ListCredentials() ([]CredentialDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]CredentialDTO, error) {
		r, err := v1.NewVaultServiceClient(c).ListCredentials(ctx, &v1.ListCredentialsRequest{})
		if err != nil {
			return nil, err
		}
		out := []CredentialDTO{}
		for _, i := range r.Credentials {
			out = append(out, CredentialDTO{ID: i.Id, Label: i.Label, Username: i.Username, HasEnable: i.HasEnableSecret, HasSSHKey: i.HasSshKey})
		}
		return out, nil
	})
}

func (b *Bridge) PutCredential(label, username, password, enable string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewVaultServiceClient(c).PutCredential(ctx, &v1.PutCredentialRequest{Label: label, Username: username, Password: []byte(password), EnableSecret: []byte(enable)})
		if err != nil {
			return "", err
		}
		return r.Id, nil
	})
}

func (b *Bridge) DeleteCredential(id string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (any, error) {
		return v1.NewVaultServiceClient(c).DeleteCredential(ctx, &v1.DeleteCredentialRequest{Id: id})
	})
	return err
}

// ---- Patrol ----

// CreateJob recibe el JobSpec como JSON (mismos campos que patrol.proto).
func (b *Bridge) CreateJob(specJSON string) (string, error) {
	var spec v1.JobSpec
	if err := protojson.Unmarshal([]byte(specJSON), &spec); err != nil {
		return "", wrapErr(err)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewPatrolServiceClient(c).CreateJob(ctx, &v1.CreateJobRequest{Spec: &spec})
		if err != nil {
			return "", err
		}
		return r.JobId, nil
	})
}

type LoginDTO struct {
	Target      string `json:"target"`
	Passed      bool   `json:"passed"`
	FailedStep  string `json:"failedStep"`
	Detail      string `json:"detail"`
	Platform    string `json:"platform"`
	Fingerprint string `json:"fingerprint"`
	// Reason y Args son el código estable del error de Detail (transport.hostkey.unknown, ...) y sus argumentos; vacíos si es texto de sistema.
	Reason string            `json:"reason,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

func (b *Bridge) LoginTest(jobID string) ([]LoginDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]LoginDTO, error) {
		st, err := v1.NewPatrolServiceClient(c).LoginTest(ctx, &v1.LoginTestRequest{JobId: jobID})
		if err != nil {
			return nil, err
		}
		out := []LoginDTO{}
		for {
			r, err := st.Recv()
			if err == io.EOF {
				return out, nil
			}
			if err != nil {
				return out, err
			}
			out = append(out, LoginDTO{Target: r.Target.GetAddress(), Passed: r.Passed, FailedStep: r.FailedStep.String(), Detail: r.Detail, Platform: r.DetectedPlatform, Fingerprint: r.HostKeyFingerprint, Reason: r.Reason, Args: r.Args})
		}
	})
}

type ArmDTO struct {
	WindowEndsAt      time.Time `json:"windowEndsAt"`
	MissingInhibitors []string  `json:"missingInhibitors"`
}

func (b *Bridge) ArmJob(jobID string, accept, exclude []string) (ArmDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ArmDTO, error) {
		r, err := v1.NewPatrolServiceClient(c).ArmJob(ctx, &v1.ArmJobRequest{JobId: jobID, AcceptedHostKeyFingerprints: accept, ExcludedDeviceIds: exclude})
		if err != nil {
			return ArmDTO{}, err
		}
		return ArmDTO{WindowEndsAt: r.WindowEndsAt.AsTime(), MissingInhibitors: r.MissingInhibitors}, nil
	})
}

func (b *Bridge) CancelJob(jobID string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (any, error) {
		return v1.NewPatrolServiceClient(c).CancelJob(ctx, &v1.CancelJobRequest{JobId: jobID})
	})
	return err
}

// Las horas van en RFC 3339 (UTC); vacías si no aplican.
type JobDTO struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	State         string     `json:"state"`
	NextRoundAt   string     `json:"nextRoundAt"`
	ArmedAt       string     `json:"armedAt"`
	WindowEndsAt  string     `json:"windowEndsAt"`
	Round         uint32     `json:"round"`
	Rounds        uint32     `json:"rounds"` // 0 = hasta que termine la ventana
	DevicesTotal  uint32     `json:"devicesTotal"`
	DevicesOK     uint32     `json:"devicesOk"`
	DevicesFailed uint32     `json:"devicesFailed"`
	OutputDir     string     `json:"outputDir"`
	Kind          string     `json:"kind"` // patrol, adhoc, backup o change
	Phases        []PhaseDTO `json:"phases"`
}

type PhaseDTO struct {
	At     string `json:"at"`
	Kind   string `json:"kind"` // nombre del enum, p. ej. JOB_PHASE_KIND_ROUND_FINISHED
	Round  uint32 `json:"round"`
	Detail string `json:"detail"`
	// Reason y Args son el código estable del detalle (phase.devices, phase.ok_failed, ...) y sus argumentos; vacíos si la fase no lleva detalle.
	Reason string            `json:"reason,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

func rfc3339(t *timestamppb.Timestamp) string {
	if t == nil {
		return ""
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

func (b *Bridge) ListJobs() ([]JobDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]JobDTO, error) {
		r, err := v1.NewPatrolServiceClient(c).ListJobs(ctx, &v1.ListJobsRequest{})
		if err != nil {
			return nil, err
		}
		out := []JobDTO{}
		for _, j := range r.Jobs {
			d := JobDTO{ID: j.JobId, Name: j.Name, State: j.State, NextRoundAt: rfc3339(j.NextRoundAt), ArmedAt: rfc3339(j.ArmedAt),
				WindowEndsAt: rfc3339(j.WindowEndsAt), Round: j.Round, Rounds: j.Rounds, DevicesTotal: j.DevicesTotal, DevicesOK: j.DevicesOk,
				DevicesFailed: j.DevicesFailed, OutputDir: j.OutputDir, Kind: j.Kind, Phases: []PhaseDTO{}}
			for _, p := range j.Phases {
				d.Phases = append(d.Phases, PhaseDTO{At: rfc3339(p.At), Kind: p.Kind.String(), Round: p.Round, Detail: p.Detail, Reason: p.Reason, Args: p.Args})
			}
			out = append(out, d)
		}
		return out, nil
	})
}

// Subscribe reenvía los eventos de jobIDs como core:event (JSON de SubscribeResponse).
// El stream vive lo que viva el puente, no la llamada: Wails cancela el contexto de
// cada llamada al volver. Un trabajo ya suscrito no abre otro stream.
func (b *Bridge) Subscribe(_ context.Context, jobIDs []string) error {
	var errs []error
	for _, id := range jobIDs {
		b.mu.Lock()
		st, has := b.streams[id]
		dead := has && st.dead // se lee con el candado: markDead lo escribe con él
		b.mu.Unlock()
		if !has || dead {
			if err := b.open(id); err != nil {
				errs = append(errs, err) // se intentan todos los ids
			}
		}
	}
	if len(errs) == 1 {
		return wrapErr(errs[0])
	}
	return wrapErr(errors.Join(errs...))
}

// headerWait es cuánto espera open los encabezados del núcleo antes de seguir sin ellos (variable para las pruebas).
var headerWait = 10 * time.Second

func (b *Bridge) open(jobID string) error {
	c, err := b.client()
	if err != nil {
		return wrapErr(err)
	}
	base := b.callCtx() // antes del candado: puede leer la preferencia de idioma
	b.mu.Lock()
	ctx, cancel := context.WithCancel(base)
	if old, ok := b.streams[jobID]; ok {
		old.cancel()
	}
	me := &stream{cancel: cancel}
	b.streams[jobID] = me
	b.mu.Unlock()
	// markDead marca solo este stream (me): si otro open ya lo reemplazó, la entrada nueva no se toca.
	markDead := func() {
		b.mu.Lock()
		me.dead = true
		b.mu.Unlock()
	}
	st, err := v1.NewEventServiceClient(c).Subscribe(ctx, &v1.SubscribeRequest{JobIds: []string{jobID}})
	if err == nil {
		// El núcleo manda los encabezados ya suscrito al bus: esperarlos asegura que no se pierde un evento publicado
		// justo después (armed, la ronda 1). Un error del núcleo (NotFound) llega sin encabezados, en el primer Recv.
		// La espera tiene plazo: resubscribe corre en el bucle de reconexión y un núcleo atorado no debe pararlo.
		type header struct {
			md  metadata.MD
			err error
		}
		hc := make(chan header, 1)
		go func() { md, err := st.Header(); hc <- header{md, err} }()
		select {
		case h := <-hc:
			if err = h.err; err == nil && h.md == nil {
				if _, err = st.Recv(); err == nil || errors.Is(err, io.EOF) { // terminó sin error ni eventos
					markDead()
					return nil
				}
			}
		case <-time.After(headerWait):
		}
	}
	if err != nil {
		if ctx.Err() != nil { // otro open (resubscribe) lo reemplazó: el stream nuevo ya cubre el trabajo
			return nil
		}
		// Abrir falló: no se deja la entrada (resubscribe la reabriría y fallaría para siempre).
		b.mu.Lock()
		if b.streams[jobID] == me {
			delete(b.streams, jobID)
		}
		b.mu.Unlock()
		cancel()
		return wrapErr(err)
	}
	go func() {
		for {
			e, err := st.Recv()
			if err != nil {
				markDead() // al reconectar, resubscribe lo vuelve a abrir
				return
			}
			raw, _ := protojson.Marshal(e)
			b.emit("core:event", json.RawMessage(raw))
			switch e.GetJobStateChanged().GetState() {
			case "closed":
				// El trabajo cerró (manifest y zip hechos): no habrá más eventos. Los estados completed, cancelled
				// y failed NO cierran: tras ellos llegan las fases de empaquetado y el closed. Se cierra el stream y se
				// borra del mapa (si otro open no lo reemplazó) para que ni se acumulen ni resubscribe reabra un trabajo cerrado.
				b.mu.Lock()
				if b.streams[jobID] == me {
					delete(b.streams, jobID)
				}
				b.mu.Unlock()
				cancel()
				return
			}
		}
	}()
	return nil
}

func (b *Bridge) resubscribe() {
	b.mu.Lock()
	ids := make([]string, 0, len(b.streams))
	for id := range b.streams {
		ids = append(ids, id)
	}
	b.mu.Unlock()
	// En paralelo: un núcleo atorado cuesta un plazo de encabezados, no uno por trabajo.
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() { defer wg.Done(); b.open(id) }()
	}
	wg.Wait()
}

type RunDeviceDTO struct {
	Target string `json:"target"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	// Reason y Args son el código estable del error de Detail y sus argumentos; vacíos si es texto de sistema.
	Reason string            `json:"reason,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

// targetLabel es "dirección:puerto" igual que patrol.hostport en el núcleo (IPv6 entre corchetes): así la fila coincide con el deviceId de los eventos.
func targetLabel(addr string, port uint32) string {
	if a, err := netip.ParseAddr(addr); err == nil {
		return netip.AddrPortFrom(a, uint16(port)).String()
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// GetRun devuelve el estado por equipo de una ronda, para reconstruir la grilla al reabrir.
func (b *Bridge) GetRun(jobID string, round uint32) ([]RunDeviceDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]RunDeviceDTO, error) {
		r, err := v1.NewPatrolServiceClient(c).GetRun(ctx, &v1.GetRunRequest{JobId: jobID, Round: round})
		if err != nil {
			return nil, err
		}
		out := []RunDeviceDTO{}
		for _, d := range r.Devices {
			out = append(out, RunDeviceDTO{Target: targetLabel(d.Target.GetAddress(), d.Target.GetPort()), State: d.State.String(), Detail: d.Detail, Reason: d.Reason, Args: d.Args})
		}
		return out, nil
	})
}

// ---- Auditoría ----

type VerifyDTO struct {
	Intact      bool   `json:"intact"`
	FirstBroken uint64 `json:"firstBroken"`
	Head        string `json:"head"`
}

func (b *Bridge) AuditVerify() (VerifyDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (VerifyDTO, error) {
		r, err := v1.NewAuditServiceClient(c).Verify(ctx, &v1.VerifyRequest{})
		if err != nil {
			return VerifyDTO{}, err
		}
		return VerifyDTO{Intact: r.Intact, FirstBroken: r.FirstBrokenSeq, Head: r.HeadHash}, nil
	})
}

// ---- ACLs ----

type AclRuleDTO struct {
	Action           string `json:"action"`
	Protocol         string `json:"protocol"`
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	SourcePorts      string `json:"sourcePorts"`
	DestinationPorts string `json:"destinationPorts"`
	Log              bool   `json:"log"`
	Established      bool   `json:"established"`
	Remark           string `json:"remark"`
}

type AclDTO struct {
	Name  string       `json:"name"`
	Rules []AclRuleDTO `json:"rules"`
}

type AclFindingDTO struct {
	Index  int    `json:"index"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	// DetailKey y DetailArgs son el detalle como clave del catálogo (fase 30c).
	DetailKey  string            `json:"detailKey,omitempty"`
	DetailArgs map[string]string `json:"detailArgs,omitempty"`
}

func aclToDTO(a *v1.Acl) AclDTO {
	out := AclDTO{Name: a.GetName(), Rules: []AclRuleDTO{}}
	for _, r := range a.GetRules() {
		act := "permit"
		if r.Action == v1.AclAction_ACL_ACTION_DENY {
			act = "deny"
		}
		out.Rules = append(out.Rules, AclRuleDTO{Action: act, Protocol: r.Protocol, Source: r.Source, Destination: r.Destination,
			SourcePorts: r.SourcePorts, DestinationPorts: r.DestinationPorts, Log: r.Log, Established: r.Established, Remark: r.Remark})
	}
	return out
}

func aclFromDTO(a AclDTO) *v1.Acl {
	out := &v1.Acl{Name: a.Name}
	for _, r := range a.Rules {
		act := v1.AclAction_ACL_ACTION_PERMIT
		if r.Action == "deny" {
			act = v1.AclAction_ACL_ACTION_DENY
		}
		out.Rules = append(out.Rules, &v1.AclRule{Action: act, Protocol: r.Protocol, Source: r.Source, Destination: r.Destination,
			SourcePorts: r.SourcePorts, DestinationPorts: r.DestinationPorts, Log: r.Log, Established: r.Established, Remark: r.Remark})
	}
	return out
}

func (b *Bridge) AclImport(vendor, text string) (AclDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (AclDTO, error) {
		r, err := v1.NewAclServiceClient(c).Import(ctx, &v1.ImportRequest{Vendor: vendor, Text: text})
		if err != nil {
			return AclDTO{}, err
		}
		return aclToDTO(r.Acl), nil
	})
}

func (b *Bridge) AclAnalyze(a AclDTO) ([]AclFindingDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]AclFindingDTO, error) {
		r, err := v1.NewAclServiceClient(c).Analyze(ctx, &v1.AnalyzeRequest{Acl: aclFromDTO(a)})
		if err != nil {
			return nil, err
		}
		out := []AclFindingDTO{}
		for _, f := range r.Findings {
			out = append(out, AclFindingDTO{Index: int(f.RuleIndex), Kind: f.Kind, Detail: f.Detail, DetailKey: f.DetailKey, DetailArgs: f.DetailArgs})
		}
		return out, nil
	})
}

func (b *Bridge) AclGenerate(vendor string, a AclDTO) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAclServiceClient(c).Generate(ctx, &v1.GenerateRequest{Acl: aclFromDTO(a), Vendor: vendor})
		if err != nil {
			return "", err
		}
		return r.Script, nil
	})
}

// ---- Diagnóstico ----

// DiagRun lanza una herramienta y emite diag:line {runId, line} por cada línea y
// diag:done {runId, exitCode, outputPath} al terminar. Devuelve el ID para cancelar.
func (b *Bridge) DiagRun(tool string, targets []string, options map[string]string) (string, error) {
	enum, ok := map[string]v1.DiagTool{"ping": v1.DiagTool_DIAG_TOOL_PING, "traceroute": v1.DiagTool_DIAG_TOOL_TRACEROUTE,
		"nmap": v1.DiagTool_DIAG_TOOL_NMAP, "iperf3": v1.DiagTool_DIAG_TOOL_IPERF3, "pcap": v1.DiagTool_DIAG_TOOL_PCAP}[tool]
	if !ok {
		return "", b.bridgeErr(i18n.New("bridge.err.tool", i18n.A("tool", tool)))
	}
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	req := &v1.RunRequest{Tool: enum, Options: options}
	for _, t := range targets {
		req.Targets = append(req.Targets, &v1.Target{Address: t})
	}
	base := b.callCtx() // antes del candado: puede leer la preferencia de idioma
	b.mu.Lock()
	b.runSeq++
	id := fmt.Sprintf("run-%d", b.runSeq)
	ctx, cancel := context.WithCancel(base)
	b.runs[id] = cancel
	b.mu.Unlock()
	st, err := v1.NewDiagServiceClient(c).Run(ctx, req)
	if err != nil {
		b.mu.Lock()
		delete(b.runs, id)
		b.mu.Unlock()
		cancel()
		return "", wrapErr(err)
	}
	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.runs, id)
			b.mu.Unlock()
			cancel()
		}()
		for {
			r, err := st.Recv()
			if err != nil {
				if ctx.Err() != nil { // el usuario canceló: no es un fallo
					b.emit("diag:done", map[string]any{"runId": id, "exitCode": -1, "outputPath": "", "canceled": true})
					return
				}
				b.emit("diag:done", map[string]any{"runId": id, "exitCode": -1, "outputPath": "", "error": err.Error(), "errorInfo": errorInfo(err)})
				return
			}
			if r.Done {
				b.emit("diag:done", map[string]any{"runId": id, "exitCode": r.ExitCode, "outputPath": r.OutputPath})
				return
			}
			b.emit("diag:line", map[string]any{"runId": id, "line": r.OutputLine})
		}
	}()
	return id, nil
}

type InterfaceDTO struct {
	Name         string   `json:"name"`
	Up           bool     `json:"up"`
	Loopback     bool     `json:"loopback"`
	Addresses    []string `json:"addresses"` // CIDR
	HardwareAddr string   `json:"hardwareAddr"`
}

// ListInterfaces devuelve las interfaces locales ordenadas por nombre.
func (b *Bridge) ListInterfaces() ([]InterfaceDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]InterfaceDTO, error) {
		r, err := v1.NewDiagServiceClient(c).ListInterfaces(ctx, &v1.ListInterfacesRequest{})
		if err != nil {
			return nil, err
		}
		out := []InterfaceDTO{}
		for _, i := range r.Interfaces {
			out = append(out, InterfaceDTO{Name: i.Name, Up: i.Up, Loopback: i.Loopback, Addresses: append([]string{}, i.Addresses...), HardwareAddr: i.HardwareAddr})
		}
		return out, nil
	})
}

// DiagCancel detiene una ejecución; el núcleo termina el proceso al cerrarse el stream.
func (b *Bridge) DiagCancel(runID string) error {
	b.mu.Lock()
	cancel, ok := b.runs[runID]
	b.mu.Unlock()
	if !ok {
		return b.bridgeErr(i18n.New("bridge.err.run_gone", i18n.A("id", runID)))
	}
	cancel()
	return nil
}

// ---- Herramientas (pcap, DNS, TLS, syslog) ----

func (b *Bridge) ToolsPcap(path string, top int) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewToolsServiceClient(c).AnalyzePcap(ctx, &v1.AnalyzePcapRequest{Path: path, Top: int32(top)})
		return r.GetReport().GetText(), err
	})
}

type DnsDTO struct {
	Mode    string   `json:"mode"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Servers []string `json:"servers"`
	Deep    bool     `json:"deep"`
	Dnssec  bool     `json:"dnssec"`
}

var dnsModes = map[string]v1.DnsMode{
	"query": v1.DnsMode_DNS_MODE_QUERY, "transport": v1.DnsMode_DNS_MODE_TRANSPORT, "hygiene": v1.DnsMode_DNS_MODE_HYGIENE,
	"exposure": v1.DnsMode_DNS_MODE_EXPOSURE, "trace": v1.DnsMode_DNS_MODE_TRACE, "zone": v1.DnsMode_DNS_MODE_ZONE, "dnssec": v1.DnsMode_DNS_MODE_DNSSEC,
}

func (b *Bridge) ToolsDns(d DnsDTO) (string, error) {
	mode, ok := dnsModes[d.Mode]
	if !ok {
		return "", b.bridgeErr(i18n.New("bridge.err.dns_mode", i18n.A("mode", d.Mode)))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewToolsServiceClient(c).Dns(ctx, &v1.DnsRequest{Mode: mode, Name: d.Name, Type: d.Type, Servers: d.Servers, Deep: d.Deep, Dnssec: d.Dnssec})
		return r.GetReport().GetText(), err
	})
}

func (b *Bridge) ToolsTls(host string, port int, sni string) (string, error) {
	if port < 0 || port > 65535 {
		return "", b.bridgeErr(i18n.New("bridge.err.port", i18n.A("port", port)))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewToolsServiceClient(c).InspectTls(ctx, &v1.InspectTlsRequest{Host: host, Port: uint32(port), Sni: sni})
		return r.GetReport().GetText(), err
	})
}

// SyslogOptions son los topes y el archivo de la escucha (de syslog, traps y flujos); 0 o "" = default del núcleo.
type SyslogOptions struct {
	RatePerSource  int    `json:"ratePerSource"`
	BurstPerSource int    `json:"burstPerSource"`
	RateGlobal     int    `json:"rateGlobal"`
	BurstGlobal    int    `json:"burstGlobal"`
	QueueSize      int    `json:"queueSize"`
	RotateMB       int    `json:"rotateMb"`
	RotateMinutes  int    `json:"rotateMinutes"`
	NameTemplate   string `json:"nameTemplate"`
	MaxFiles       int    `json:"maxFiles"`
	Format         string `json:"format"`
}

// check rechaza lo que no cabe en el int32 del contrato, en vez de truncarlo en silencio.
func (o SyslogOptions) check() error {
	for name, v := range map[string]int{"ratePerSource": o.RatePerSource, "burstPerSource": o.BurstPerSource, "rateGlobal": o.RateGlobal, "burstGlobal": o.BurstGlobal,
		"queueSize": o.QueueSize, "rotateMb": o.RotateMB, "rotateMinutes": o.RotateMinutes, "maxFiles": o.MaxFiles} {
		if int(int32(v)) != v {
			return i18n.New("bridge.err.range", i18n.A("name", name, "value", v))
		}
	}
	return nil
}

type syslogSourceDTO struct {
	Source string `json:"source"`
	Count  uint64 `json:"count"`
}

type syslogDropsDTO struct {
	Total     uint64            `json:"total"`
	PorOrigen uint64            `json:"porOrigen"`
	Global    uint64            `json:"global"`
	ColaLlena uint64            `json:"colaLlena"`
	SinceMs   int64             `json:"sinceMs"`
	Top       []syslogSourceDTO `json:"top"`
}

func dropsDTO(d *v1.SyslogDrops) syslogDropsDTO {
	dto := syslogDropsDTO{Total: d.Total, PorOrigen: d.PorOrigen, Global: d.Global, ColaLlena: d.ColaLlena, SinceMs: d.SinceMs, Top: []syslogSourceDTO{}}
	for _, s := range d.Top {
		dto.Top = append(dto.Top, syslogSourceDTO{s.Source, s.Count})
	}
	return dto
}

// SyslogStart escucha y emite syslog:msg {runId, listening?, outputPath?, json?,
// rotatedPath?, drops?} por evento y syslog:done {runId, error?} al terminar.
// drops es el acumulado de descartes; rotatedPath, un archivo nuevo. Se detiene con DiagCancel(id).
func (b *Bridge) SyslogStart(addr, proto string, allowAny, save bool, o SyslogOptions) (string, error) {
	if err := o.check(); err != nil {
		return "", b.bridgeErr(err)
	}
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	base := b.callCtx() // antes del candado: puede leer la preferencia de idioma
	b.mu.Lock()
	b.runSeq++
	id := fmt.Sprintf("run-%d", b.runSeq)
	ctx, cancel := context.WithCancel(base)
	b.runs[id] = cancel
	b.mu.Unlock()
	st, err := v1.NewToolsServiceClient(c).Syslog(ctx, &v1.SyslogRequest{
		Addr: addr, Protocol: proto, AllowAny: allowAny, Save: save,
		RatePerSource: int32(o.RatePerSource), BurstPerSource: int32(o.BurstPerSource), RateGlobal: int32(o.RateGlobal), BurstGlobal: int32(o.BurstGlobal), QueueSize: int32(o.QueueSize),
		RotateMb: int32(o.RotateMB), RotateMinutes: int32(o.RotateMinutes), NameTemplate: o.NameTemplate, MaxFiles: int32(o.MaxFiles), Format: o.Format,
	})
	if err != nil {
		b.mu.Lock()
		delete(b.runs, id)
		b.mu.Unlock()
		cancel()
		return "", wrapErr(err)
	}
	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.runs, id)
			b.mu.Unlock()
			cancel()
		}()
		for {
			r, err := st.Recv()
			if err != nil {
				ev := map[string]any{"runId": id}
				if ctx.Err() == nil && err != io.EOF {
					ev["error"] = err.Error()
					ev["errorInfo"] = errorInfo(err)
				}
				b.emit("syslog:done", ev)
				return
			}
			ev := map[string]any{"runId": id, "listening": r.Listening, "outputPath": r.OutputPath, "json": r.Json, "rotatedPath": r.RotatedPath}
			if d := r.Drops; d != nil {
				ev["drops"] = dropsDTO(d)
			}
			b.emit("syslog:msg", ev)
		}
	}()
	return id, nil
}
