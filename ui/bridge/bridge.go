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
	"io/fs"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	Localize bool
	// Launcher arranca el núcleo si no corre (solo Windows; nil en Linux, donde lo arranca systemd).
	Launcher  *CoreLauncher
	lang      langCache
	dial      func() (*ipc.ClientConn, error)
	emit      Emitter
	mu        sync.Mutex
	conn      *ipc.ClientConn
	status    string
	ctx       context.Context               // vida del puente; los streams cuelgan de aquí, no de la llamada
	streams   map[string]*stream            // un stream de eventos por trabajo
	runs      map[string]context.CancelFunc // ejecuciones de diagnóstico en curso
	coreRun   map[string]string             // runId del puente → run_id del núcleo (primer evento), para StopRun (#200)
	assists   map[string]*stream            // un watch de asistente por ejecución (assist.go)
	runSeq    int
	consoles  map[string]*consoleSess // consolas serie abiertas (field.go)
	terminals map[string]*termSess    // terminales SSH abiertas (terminal.go)
}

func New(dial func() (*ipc.ClientConn, error), emit Emitter) *Bridge {
	return &Bridge{Interval: time.Second, dial: dial, emit: emit, ctx: context.Background(), streams: map[string]*stream{}, runs: map[string]context.CancelFunc{}, coreRun: map[string]string{}, assists: map[string]*stream{}}
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

// Start lanza la vigilancia de la conexión, una sola vez por puente. Es una función y no un método para
// que Wails no la exponga al frontend.
func Start(ctx context.Context, b *Bridge) {
	b.mu.Lock()
	b.ctx = ctx
	b.mu.Unlock()
	go b.run(ctx)
}

// run emite core:status (connected|disconnected). La verificación no cierra la conexión:
// gRPC reconecta solo, y cerrarla tumbaría las llamadas en curso.
// probeMin es el tope mínimo de la sonda de estado: con el intervalo de 1 s ya es 5 s; con intervalos cortos (pruebas)
// un núcleo lento por la carga no pasa por desconectado.
const probeMin = 5 * time.Second

func (b *Bridge) run(ctx context.Context) {
	t := time.NewTicker(b.Interval)
	defer t.Stop()
	defer func() {
		b.mu.Lock()
		for _, st := range b.streams {
			st.cancel()
		}
		if b.conn != nil {
			b.conn.Close()
		}
		b.mu.Unlock()
	}()
	for {
		c, err := b.client()
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, max(5*b.Interval, probeMin))
			_, err = v1.NewVaultServiceClient(c).Status(cctx, &v1.StatusRequest{})
			cancel()
		}
		if ctx.Err() != nil {
			return // cerrar el puente no es perder el núcleo: la sonda que cortó el cierre no cambia el estado ni lanza nada
		}
		if err != nil {
			b.setStatus("disconnected")
			if b.Launcher != nil && b.Launcher.check() && c != nil {
				c.ResetConnectBackoff() // gRPC esperaría su backoff (hasta 2 min) aunque el núcleo nuevo ya escuche
			}
		} else if b.setStatus("connected") {
			b.resubscribe()
		}
		if err == nil {
			b.syncLanguage(c)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncLanguage manda al núcleo el idioma elegido mientras estaba caído. Si la UI eligió otro mientras se mandaba,
// vuelve a mandar el vigente: el núcleo no se queda con el viejo.
func (b *Bridge) syncLanguage(c *ipc.ClientConn) {
	b.lang.mu.Lock()
	v := b.lang.pending
	b.lang.mu.Unlock()
	for v != "" {
		ctx, cancel := context.WithTimeout(b.ctx, 3*time.Second)
		_, err := v1.NewPrefsServiceClient(c).SetPreference(ctx, &v1.SetPreferenceRequest{Key: langPref, Value: v})
		cancel()
		if err != nil {
			return
		}
		b.lang.mu.Lock()
		if b.lang.pending == v {
			b.lang.pending = ""
		}
		cur := b.lang.value
		if !b.lang.loaded || cur == v {
			cur = ""
		}
		b.lang.mu.Unlock()
		v = cur
	}
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
	Kind      string `json:"kind"`   // password | key: lo calcula el núcleo al listar
	Origin    string `json:"origin"` // generated | imported; vacío en las de contraseña
}

// KeyCredentialDTO es la llave recién generada: solo la pública sale del núcleo (ADR 0013).
type KeyCredentialDTO struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"` // una línea de authorized_keys
}

// CreateKeyCredential pide al núcleo una llave ed25519 nueva; la privada queda en la bóveda y nunca viaja.
func (b *Bridge) CreateKeyCredential(label, username string) (KeyCredentialDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (KeyCredentialDTO, error) {
		r, err := v1.NewVaultServiceClient(c).GenerateKeyCredential(ctx, &v1.GenerateKeyCredentialRequest{Label: label, Username: username})
		return KeyCredentialDTO{ID: r.GetId(), PublicKey: r.GetPublicKey()}, err
	})
}

// ImportKeyDTO es la llave a importar: o PrivateKey (el contenido pegado) o Path (el puente lee el archivo); nunca los dos.
type ImportKeyDTO struct {
	Label      string `json:"label"`
	Username   string `json:"username"`
	PrivateKey string `json:"privateKey"`
	Path       string `json:"path"`
	Passphrase string `json:"passphrase"`
}

type ImportKeyResultDTO struct {
	ID          string `json:"id"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Bits        uint32 `json:"bits"`
	Weak        bool   `json:"weak"`
}

const maxKeyBytes = 64 << 10

// ImportKeyCredential importa una privada existente. El núcleo solo recibe el contenido, nunca la ruta. Un archivo de
// más de 64 KiB se manda recortado a 64 KiB + 1 para que el núcleo lo rechace con su propio error (field_too_long).
func (b *Bridge) ImportKeyCredential(d ImportKeyDTO) (ImportKeyResultDTO, error) {
	if (d.Path == "") == (d.PrivateKey == "") {
		err := b.bridgeErr(i18n.New("bridge.err.import_source", nil))
		err.(*Error).Code = "InvalidArgument"
		return ImportKeyResultDTO{}, err
	}
	pass := []byte(d.Passphrase)
	defer clear(pass)
	key := []byte(d.PrivateKey)
	if d.Path != "" {
		var err error
		if key, err = b.readKeyFile(d.Path); err != nil {
			return ImportKeyResultDTO{}, b.bridgeErr(err)
		}
	}
	defer clear(key) // best effort: el string pegado no se puede borrar
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ImportKeyResultDTO, error) {
		r, err := v1.NewVaultServiceClient(c).ImportKeyCredential(ctx, &v1.ImportKeyCredentialRequest{Label: d.Label, Username: d.Username, PrivateKey: key, Passphrase: pass})
		return ImportKeyResultDTO{ID: r.GetId(), PublicKey: r.GetPublicKey(), Fingerprint: r.GetFingerprint(), Algorithm: r.GetAlgorithm(), Bits: r.GetBits(), Weak: r.GetWeak()}, err
	})
}

// readKeyFile lee hasta 64 KiB + 1 de un archivo regular (se revisa antes y después de abrir). Los errores salen con
// código del catálogo y nunca con el texto de *PathError: trae la ruta y Wails lo registra.
func (b *Bridge) readKeyFile(path string) ([]byte, error) {
	notRegular := b.bridgeErr(i18n.New("bridge.err.import_not_regular", nil))
	readErr := func(err error) error {
		kind := "other"
		switch {
		case errors.Is(err, fs.ErrNotExist):
			kind = "not_found"
		case errors.Is(err, fs.ErrPermission):
			kind = "permission"
		}
		return b.bridgeErr(i18n.New("bridge.err.import_read", i18n.A("kind", kind)))
	}
	if fi, err := os.Stat(path); err != nil {
		return nil, readErr(err)
	} else if !fi.Mode().IsRegular() {
		return nil, notRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, readErr(err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, readErr(err)
	} else if !fi.Mode().IsRegular() {
		return nil, notRegular
	}
	buf := make([]byte, 0, maxKeyBytes+1)
	for len(buf) < cap(buf) {
		n, err := f.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			clear(buf)
			return nil, readErr(err)
		}
	}
	return buf, nil
}

// RegenerateKeyDTO es la pública nueva y de dónde venía la llave que se destruyó (generated | imported).
type RegenerateKeyDTO struct {
	PublicKey      string `json:"publicKey"`
	PreviousOrigin string `json:"previousOrigin"`
}

// RegenerateKeyCredential genera otra llave para la misma credencial (conserva el id) y devuelve la pública nueva.
// confirm es obligatorio: la pública vieja deja de servir en cada authorized_keys. Solo credenciales de tipo llave.
func (b *Bridge) RegenerateKeyCredential(id string, confirm bool) (RegenerateKeyDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (RegenerateKeyDTO, error) {
		r, err := v1.NewVaultServiceClient(c).RegenerateKeyCredential(ctx, &v1.RegenerateKeyCredentialRequest{Id: id, Confirm: confirm})
		return RegenerateKeyDTO{PublicKey: r.GetPublicKey(), PreviousOrigin: r.GetPreviousOrigin()}, err
	})
}

// CredentialPublicKey devuelve la línea authorized_keys de una credencial con llave.
func (b *Bridge) CredentialPublicKey(id string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewVaultServiceClient(c).GetCredentialPublicKey(ctx, &v1.GetCredentialPublicKeyRequest{Id: id})
		return r.GetPublicKey(), err
	})
}

func (b *Bridge) ListCredentials() ([]CredentialDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]CredentialDTO, error) {
		r, err := v1.NewVaultServiceClient(c).ListCredentials(ctx, &v1.ListCredentialsRequest{})
		if err != nil {
			return nil, err
		}
		out := []CredentialDTO{}
		for _, i := range r.Credentials {
			out = append(out, CredentialDTO{ID: i.Id, Label: i.Label, Username: i.Username, HasEnable: i.HasEnableSecret, HasSSHKey: i.HasSshKey, Kind: i.Kind, Origin: i.Origin})
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
	spec.Kind = "" // el tipo del trabajo lo pone cada servicio (adhoc, backup, change); un patrol desde la UI siempre es el vacío
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

func (b *Bridge) ArmJob(jobID string, accept []string, acceptedKeys []AcceptedHostKeyDTO, exclude []string) (ArmDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ArmDTO, error) {
		r, err := v1.NewPatrolServiceClient(c).ArmJob(ctx, &v1.ArmJobRequest{JobId: jobID, AcceptedHostKeyFingerprints: accept, AcceptedHostKeys: protoKeys(acceptedKeys), ExcludedDeviceIds: exclude})
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
	ID            string `json:"id"`
	Name          string `json:"name"`
	State         string `json:"state"`
	NextRoundAt   string `json:"nextRoundAt"`
	ArmedAt       string `json:"armedAt"`
	WindowEndsAt  string `json:"windowEndsAt"`
	Round         uint32 `json:"round"`
	Rounds        uint32 `json:"rounds"` // 0 = hasta que termine la ventana
	DevicesTotal  uint32 `json:"devicesTotal"`
	DevicesOK     uint32 `json:"devicesOk"`
	DevicesFailed uint32 `json:"devicesFailed"`
	// DevicesPartial: equipos con evidencia parcial (un comando se cortó y el núcleo reconectó); no cuentan en ok ni en fallidos.
	DevicesPartial uint32     `json:"devicesPartial"`
	OutputDir      string     `json:"outputDir"`
	Kind           string     `json:"kind"` // patrol, adhoc, backup o change
	Phases         []PhaseDTO `json:"phases"`
	FinishedAt     string     `json:"finishedAt"` // vacío mientras no termina
	Past           bool       `json:"past"`       // terminado un día anterior (lo calcula el núcleo con su hora local)
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

// ListJobsOpts: lo que la UI elige al listar. IncludePast suma los terminados de días anteriores (fase 46).
type ListJobsOpts struct {
	IncludePast bool `json:"includePast"`
}

func (b *Bridge) ListJobs(o ListJobsOpts) ([]JobDTO, error) {
	loc := b.locale() // fuera de call: language() puede hacer su propio RPC
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]JobDTO, error) {
		r, err := v1.NewPatrolServiceClient(c).ListJobs(ctx, &v1.ListJobsRequest{IncludePast: o.IncludePast})
		if err != nil {
			return nil, err
		}
		out := []JobDTO{}
		for _, j := range r.Jobs {
			d := JobDTO{ID: j.JobId, Name: j.Name, State: j.State, NextRoundAt: rfc3339(j.NextRoundAt), ArmedAt: rfc3339(j.ArmedAt),
				WindowEndsAt: rfc3339(j.WindowEndsAt), Round: j.Round, Rounds: j.Rounds, DevicesTotal: j.DevicesTotal, DevicesOK: j.DevicesOk,
				DevicesFailed: j.DevicesFailed, DevicesPartial: j.DevicesPartial, OutputDir: j.OutputDir, Kind: j.Kind, Phases: []PhaseDTO{},
				FinishedAt: rfc3339(j.FinishedAt), Past: j.Past}
			for _, p := range j.Phases {
				detail := p.Detail
				if p.Reason != "" && i18n.Has(p.Reason) { // reasons del catálogo del núcleo (p. ej. el de ARM_FAILED): la UI no los tiene
					detail = i18n.Msg(loc, p.Reason, i18n.Args(p.Args))
				}
				d.Phases = append(d.Phases, PhaseDTO{At: rfc3339(p.At), Kind: p.Kind.String(), Round: p.Round, Detail: detail, Reason: p.Reason, Args: p.Args})
			}
			out = append(out, d)
		}
		return out, nil
	})
}

// RemoveJobsSel: qué quitar del historial. Solo ids: la UI quita exactamente lo que el usuario confirmó (all_finished no se expone).
type RemoveJobsSel struct {
	JobIDs []string `json:"jobIds"`
}

type SkippedJobDTO struct {
	JobID  string `json:"jobId"`
	Reason string `json:"reason"` // active | change_pre | backup_import | adhoc_unread
}

type RemoveJobsDTO struct {
	Removed    int32           `json:"removed"`
	RemovedIDs []string        `json:"removedIds"`
	Skipped    []SkippedJobDTO `json:"skipped"`
}

// RemoveJobs quita trabajos del historial (la evidencia en disco no se toca); lo que no puede quitar vuelve en skipped.
func (b *Bridge) RemoveJobs(s RemoveJobsSel) (RemoveJobsDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (RemoveJobsDTO, error) {
		r, err := v1.NewPatrolServiceClient(c).RemoveJobs(ctx, &v1.RemoveJobsRequest{JobIds: s.JobIDs})
		if err != nil {
			return RemoveJobsDTO{}, err
		}
		out := RemoveJobsDTO{Removed: r.Removed, RemovedIDs: append([]string{}, r.RemovedIds...), Skipped: []SkippedJobDTO{}}
		for _, k := range r.Skipped {
			out.Skipped = append(out.Skipped, SkippedJobDTO{JobID: k.JobId, Reason: k.Reason})
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
	if len(errs) > 0 {
		return wrapErr(errs[0]) // el primero: un errors.Join no es *Error y la UI perdería code y reason
	}
	return nil
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
		// Error definitivo: no se deja la entrada (resubscribe la reabriría y fallaría para siempre). Uno transitorio
		// (Unavailable, un reset al reconectar) la deja muerta para que resubscribe la reabra.
		switch status.Code(err) {
		case codes.NotFound, codes.InvalidArgument, codes.PermissionDenied, codes.FailedPrecondition:
			b.mu.Lock()
			if b.streams[jobID] == me {
				delete(b.streams, jobID)
			}
			b.mu.Unlock()
		default:
			markDead()
		}
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
	// CutCommands y Reconnects solo son distintos de 0 con estado PARTIAL.
	CutCommands uint32 `json:"cutCommands,omitempty"`
	Reconnects  uint32 `json:"reconnects,omitempty"`
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
			out = append(out, RunDeviceDTO{Target: targetLabel(d.Target.GetAddress(), d.Target.GetPort()), State: d.State.String(), Detail: d.Detail, Reason: d.Reason, Args: d.Args, CutCommands: d.CutCommands, Reconnects: d.Reconnects})
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
			delete(b.coreRun, id)
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
			if r.RunId != "" { // el id del núcleo no sale a la UI: solo sirve para DiagStop
				b.mu.Lock()
				b.coreRun[id] = r.RunId
				b.mu.Unlock()
			}
			if r.Done {
				ev := map[string]any{"runId": id, "exitCode": r.ExitCode, "outputPath": r.OutputPath}
				if s := r.GetPingSummary(); s != nil {
					ev["pingSummary"] = map[string]any{"sent": s.Sent, "received": s.Received, "lossPct": s.LossPct, "minMs": s.MinMs, "avgMs": s.AvgMs, "maxMs": s.MaxMs, "mdevMs": s.MdevMs}
				}
				b.emit("diag:done", ev)
				return
			}
			ev := map[string]any{"runId": id}
			if rt := r.GetResolved(); rt != nil { // solo viene en el primer evento
				ev["resolved"] = map[string]any{"name": rt.Name, "ip": rt.Ip, "family": rt.Family}
			}
			sp := r.GetSweepPoint()
			// Una línea vacía de la salida también cuenta; la única que se omite es la del evento que solo trae run_id (el primero).
			if r.OutputLine != "" || (sp == nil && r.RunId == "") {
				ev["line"] = r.OutputLine
			}
			if sp != nil {
				ev["sweepPoint"] = map[string]any{"size": sp.Size, "sent": sp.Sent, "received": sp.Received, "result": sp.Result}
			}
			if len(ev) > 1 {
				b.emit("diag:line", ev)
			}
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

// DiagStop termina un ping continuo o con duración y deja que el núcleo mande el resumen (#200); DiagCancel corta sin él.
// Si la ejecución ya terminó responde NotFound, igual que StopRun del núcleo: la UI lo ignora. Si sigue viva pero no se puede
// pedir el resumen (aún no llegó el run_id del núcleo, o el núcleo no tiene StopRun), corta como DiagCancel: Detener nunca
// deja el ping corriendo.
func (b *Bridge) DiagStop(runID string) error {
	b.mu.Lock()
	core, hasCore := b.coreRun[runID]
	cancel, live := b.runs[runID]
	b.mu.Unlock()
	if !live {
		return wrapErr(status.Error(codes.NotFound, i18n.In(b.locale(), i18n.New("bridge.err.run_gone", i18n.A("id", runID)))))
	}
	if !hasCore {
		cancel()
		return nil
	}
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := v1.NewDiagServiceClient(c).StopRun(ctx, &v1.StopRunRequest{RunId: core})
		if status.Code(err) == codes.Unimplemented {
			cancel()
			return struct{}{}, nil
		}
		return struct{}{}, err
	})
	return err
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
