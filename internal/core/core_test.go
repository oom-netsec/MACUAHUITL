package core

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func TestMain(m *testing.M) {
	vault.MinMemoryKiB = 8192
	// Las pruebas viven bajo /tmp (1777): sus ancestros se dan por seguros; la regla real la prueba prefs.
	service.AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o755, uint32(os.Getuid()), nil }
	os.Exit(m.Run())
}

type fakeInhibitor struct {
	mu       sync.Mutex
	taken    int
	released int
	missing  []string
}

func (f *fakeInhibitor) Take(string) (func(), []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.taken++
	return func() { f.mu.Lock(); f.released++; f.mu.Unlock() }, f.missing
}

func (f *fakeInhibitor) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.taken, f.released
}

type harness struct {
	core   *Core
	conn   *ipc.ClientConn
	vault  v1.VaultServiceClient
	patrol v1.PatrolServiceClient
	events v1.EventServiceClient
	audit  v1.AuditServiceClient
	inh    *fakeInhibitor
	target *v1.Target
	out    string
	stop   func()
	p      Paths
	o      Options
}

func transcripts() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", "ios-xe")
}

func newHarness(t *testing.T, mut func(*Options)) *harness {
	t.Helper()
	root := t.TempDir()
	sock, _ := os.MkdirTemp("", "mcc")
	t.Cleanup(func() { os.RemoveAll(sock) })
	p := Paths{Config: filepath.Join(root, "c"), Data: filepath.Join(root, "d"), State: filepath.Join(root, "s"), Runtime: sock, Outputs: filepath.Join(root, "o")}
	inh := &fakeInhibitor{}
	o := Options{Inhibitor: inh, VaultParams: &vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1}, Actor: "tester", RetryBackoff: []time.Duration{}, PackKeys: packtest.Keys()}
	if mut != nil {
		mut(&o)
	}
	c, err := New(p, o)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ipc.Listen(filepath.Join(sock, "core.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { c.Serve(ctx, l); close(served) }()
	stop := func() { cancel(); <-served }
	t.Cleanup(func() { cancel(); c.Close() })
	conn, err := ipc.DialPath(filepath.Join(sock, "core.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	esperaServidor(t, conn)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-01", Username: "admin", Password: "MARKER-PW", Enable: "MARKER-EN", Transcripts: transcripts()})
	ap := netip.MustParseAddrPort(addr)
	os.MkdirAll(p.Outputs, 0o700)
	return &harness{core: c, conn: conn, vault: v1.NewVaultServiceClient(conn), patrol: v1.NewPatrolServiceClient(conn),
		events: v1.NewEventServiceClient(conn), audit: v1.NewAuditServiceClient(conn), inh: inh,
		target: &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw1"}, out: p.Outputs, stop: stop, p: p, o: o}
}

// restart cierra el núcleo y abre otro sobre la misma carpeta de datos, como tras reiniciar macuahuitld.
func (h *harness) restart(t *testing.T) {
	t.Helper()
	h.conn.Close()
	h.stop()
	h.core.Close()
	sock, _ := os.MkdirTemp("", "mcc")
	t.Cleanup(func() { os.RemoveAll(sock) })
	h.p.Runtime = sock
	c, err := New(h.p, h.o)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ipc.Listen(filepath.Join(sock, "core.sock"))
	if err != nil {
		t.Fatal(err)
	}
	cx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { c.Serve(cx, l); close(served) }()
	h.stop = func() { cancel(); <-served }
	t.Cleanup(func() { cancel(); c.Close() })
	conn, err := ipc.DialPath(filepath.Join(sock, "core.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	esperaServidor(t, conn)
	h.core, h.conn = c, conn
	h.vault, h.patrol, h.events, h.audit = v1.NewVaultServiceClient(conn), v1.NewPatrolServiceClient(conn), v1.NewEventServiceClient(conn), v1.NewAuditServiceClient(conn)
}

// esperaServidor vuelve cuando Serve ya registró los módulos: conectar al socket no basta (el kernel acepta
// antes), pero una llamada resuelta solo ocurre con el servidor atendiendo.
func esperaServidor(t *testing.T, conn *ipc.ClientConn) {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := v1.NewVaultServiceClient(conn).Status(c, &v1.StatusRequest{}); err != nil {
		t.Fatalf("el servidor no quedó listo: %v", err)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// ready crea la bóveda, guarda la credencial del simulador y devuelve su ID.
func (h *harness) ready(t *testing.T) string {
	t.Helper()
	if _, err := h.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("maestra")}); err != nil {
		t.Fatal(err)
	}
	r, err := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "lab", Username: "admin", Password: []byte("MARKER-PW"), EnableSecret: []byte("MARKER-EN")})
	if err != nil {
		t.Fatal(err)
	}
	return r.Id
}

func (h *harness) spec(cred string) *v1.JobSpec {
	return &v1.JobSpec{Name: "caso-1", Targets: []*v1.Target{h.target}, DefaultCredentialId: cred,
		CustomCommands: "show version\nshow running-config\n", OutputDir: h.out, WindowHours: 1,
		Schedule: &v1.Schedule{IntervalSeconds: 1, Rounds: 2}}
}

func (h *harness) loginTest(t *testing.T, job string) []*v1.LoginTestResponse {
	t.Helper()
	s, err := h.patrol.LoginTest(ctx(t), &v1.LoginTestRequest{JobId: job})
	if err != nil {
		t.Fatal(err)
	}
	var out []*v1.LoginTestResponse
	for {
		r, err := s.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
}

// arm crea el trabajo, corre el Login Test, acepta la huella y arma.
func (h *harness) arm(t *testing.T, cred string) (string, *v1.ArmJobResponse) {
	t.Helper()
	cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)})
	if err != nil {
		t.Fatal(err)
	}
	lt := h.loginTest(t, cj.JobId)
	if len(lt) != 1 || lt[0].FailedStep != v1.LoginTestStep_LOGIN_TEST_STEP_HOST_KEY || lt[0].HostKeyFingerprint == "" {
		t.Fatalf("login test = %+v", lt)
	}
	ar, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: []string{lt[0].HostKeyFingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	return cj.JobId, ar
}

func (h *harness) waitJob(t *testing.T, job string, states ...string) []*v1.SubscribeResponse {
	t.Helper()
	s, err := h.events.Subscribe(ctx(t), &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	var evs []*v1.SubscribeResponse
	for {
		e, err := s.Recv()
		if err != nil {
			t.Fatalf("stream ended: %v (events %d)", err, len(evs))
		}
		evs = append(evs, e)
		if js := e.GetJobStateChanged(); js != nil {
			for _, st := range states {
				if js.State == st {
					return evs
				}
			}
		}
	}
}

func (h *harness) auditText(t *testing.T) string {
	t.Helper()
	s, err := h.audit.Export(ctx(t), &v1.ExportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for {
		r, err := s.Recv()
		if err != nil {
			return b.String()
		}
		b.WriteString(r.JsonLine + "\n")
	}
}

func actionsInOrder(t *testing.T, text string, actions ...string) {
	t.Helper()
	pos := 0
	for _, a := range actions {
		i := strings.Index(text[pos:], `"action":"`+a+`"`)
		if i < 0 {
			t.Fatalf("audit lacks %s after position %d:\n%s", a, pos, text)
		}
		pos += i + 1
	}
}

func TestVaultLifecycleAudited(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	if _, err := h.vault.Lock(ctx(t), &v1.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.vault.Unlock(ctx(t), &v1.UnlockRequest{MasterPassword: []byte("mala")}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := h.vault.Unlock(ctx(t), &v1.UnlockRequest{MasterPassword: []byte("maestra")}); err != nil {
		t.Fatal(err)
	}
	l, err := h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	if err != nil || len(l.Credentials) != 1 || !l.Credentials[0].HasEnableSecret {
		t.Fatalf("list = %+v %v", l, err)
	}
	actionsInOrder(t, h.auditText(t), "vault.create", "credential.put", "vault.lock", "vault.unlock_failed", "vault.unlock")
}

func TestLockedVaultRejectsWrites(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	if _, err := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Username: "x", Password: []byte("y")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
}

func TestWindowHoursOver96Rejected(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	s := h.spec(cred)
	s.WindowHours = 97
	if _, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestJobEndToEnd(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, ar := h.arm(t, cred)
	if ar.WindowEndsAt == nil || len(ar.MissingInhibitors) != 0 {
		t.Fatalf("arm = %+v", ar)
	}
	evs := h.waitJob(t, job, "closed")
	sawCompleted := false
	for _, e := range evs {
		sawCompleted = sawCompleted || e.GetJobStateChanged().GetState() == "completed"
	}
	if !sawCompleted {
		t.Fatal("no completed event before closed")
	}
	zips, _ := filepath.Glob(filepath.Join(h.out, "caso-1_*", "*.zip"))
	if len(zips) != 1 {
		t.Fatalf("zips = %v", zips)
	}
	if taken, released := h.inh.counts(); taken != 1 || released != 1 {
		t.Fatalf("inhibitor taken=%d released=%d", taken, released)
	}
	st, _ := h.vault.Status(ctx(t), &v1.StatusRequest{})
	if len(st.ArmedJobIds) != 0 {
		t.Fatalf("still armed: %v", st.ArmedJobIds)
	}
	run, err := h.patrol.GetRun(ctx(t), &v1.GetRunRequest{JobId: job, Round: 2})
	if err != nil || len(run.Devices) != 1 || run.Devices[0].State != v1.DeviceState_DEVICE_STATE_COMPLETED {
		t.Fatalf("run = %+v %v", run, err)
	}
	actionsInOrder(t, h.auditText(t), "job.create", "job.logintest", "hostkey.accepted", "job.arm", "power.inhibit", "device.round", "device.round", "job.finish", "power.release")
	var leaked bool
	filepath.WalkDir(filepath.Dir(h.out), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			leaked = leaked || bytes.Contains(b, []byte("MARKER-PW")) || bytes.Contains(b, []byte("MARKER-EN"))
		}
		return nil
	})
	if leaked {
		t.Fatal("credential found on disk")
	}
}

func TestArmWithoutLogindWarns(t *testing.T) {
	h := newHarness(t, nil)
	h.inh.missing = []string{"sleep", "handle-lid-switch"}
	cred := h.ready(t)
	job, ar := h.arm(t, cred)
	if len(ar.MissingInhibitors) != 2 {
		t.Fatalf("missing = %v", ar.MissingInhibitors)
	}
	h.waitJob(t, job, "closed")
}

func TestArmRequiresPassingLoginTest(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	cj, _ := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)})
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("arm without accepting host key: %v", err)
	}
}

func TestPrepareForSleepLocksAllAndUnlockResumes(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	s := h.spec(cred)
	s.Schedule = &v1.Schedule{IntervalSeconds: 3600, Rounds: 3}
	cj, _ := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	lt := h.loginTest(t, cj.JobId)
	h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: []string{lt[0].HostKeyFingerprint}})
	h.core.OnSleep()
	st, _ := h.vault.Status(ctx(t), &v1.StatusRequest{})
	if st.State != v1.VaultState_VAULT_STATE_LOCKED {
		t.Fatalf("after sleep: %+v", st)
	}
	if _, err := h.vault.Unlock(ctx(t), &v1.UnlockRequest{MasterPassword: []byte("maestra")}); err != nil {
		t.Fatal(err)
	}
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	st, _ = h.vault.Status(ctx(t), &v1.StatusRequest{})
	if len(st.ArmedJobIds) != 1 {
		t.Fatalf("job window not re-armed after unlock: %+v", st)
	}
	actionsInOrder(t, h.auditText(t), "power.sleep", "vault.unlock", "job.resume")
	h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: cj.JobId})
}

func TestSubscribeDisconnectReleases(t *testing.T) {
	h := newHarness(t, nil)
	c, cancel := context.WithCancel(context.Background())
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s.Header()
	deadline := time.Now().Add(2 * time.Second)
	for h.core.bus.Subscribers() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	for h.core.bus.Subscribers() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.core.bus.Subscribers(); n != 0 {
		t.Fatalf("subscribers = %d after disconnect", n)
	}
}

func TestIdleLock(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.IdleLock = 150 * time.Millisecond })
	time.Sleep(300 * time.Millisecond) // preparación lenta: no debe contar como inactividad de la bóveda
	h.ready(t)
	deadline := time.Now().Add(10 * time.Second)
	for h.core.vaultState() != v1.VaultState_VAULT_STATE_LOCKED && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := h.core.vaultState(); st != v1.VaultState_VAULT_STATE_LOCKED {
		t.Fatalf("state after idle = %v", st)
	}
}

// Los servicios registran su cierre (el modo asistido cancela y espera sus ejecuciones) y corre antes de cerrar la base.
func TestCloseRunsServiceClosersBeforeDatabase(t *testing.T) {
	h := newHarness(t, nil)
	h.core.mu.Lock()
	registered := len(h.core.closers)
	h.core.mu.Unlock()
	if registered == 0 {
		t.Fatal("ningún servicio registró su cierre")
	}
	var pingErr error
	ran := false
	coreDeps{h.core}.OnClose(func() { ran = true; pingErr = h.core.db.Ping() })
	h.core.Close()
	if !ran || pingErr != nil {
		t.Fatalf("cierre corrió=%v, base abierta durante el cierre: %v", ran, pingErr)
	}
}

// La llave de las fichas de respaldo vive en la bóveda pero no es una credencial: no se crea una con su etiqueta ni sale en la lista.
func TestReservedVaultEntriesAreNotCredentials(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	if _, err := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: vault.ReservedPrefix + "llave-de-respaldos", Username: "hmac", Password: []byte("x")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("una etiqueta reservada no se acepta: %v", err)
	}
	if _, err := service.BackupKey(h.core.vault, true); err != nil {
		t.Fatal(err)
	}
	l, err := h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	if err != nil || len(l.Credentials) != 1 || l.Credentials[0].Label == service.BackupKeyLabel {
		t.Fatalf("la llave no aparece en la lista: %+v %v", l, err)
	}
}

func TestAuditAvisaCuandoNoPuedeRegistrar(t *testing.T) {
	var buf bytes.Buffer
	h := newHarness(t, func(o *Options) { o.ErrOut = &buf })
	h.core.db.Close()
	h.core.audit("accion.perdida", "obj", "d")
	if out := buf.String(); !strings.Contains(out, "accion.perdida") || !strings.Contains(out, "obj") {
		t.Fatalf("sin aviso de auditoría perdida: %q", out)
	}
}
