package bridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeEvents struct {
	v1.UnimplementedEventServiceServer
}

func (fakeEvents) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	for i := 0; ; i++ {
		if err := st.Send(&v1.SubscribeResponse{JobId: "j1", Event: &v1.SubscribeResponse_Heartbeat{Heartbeat: &v1.Heartbeat{}}}); err != nil {
			return err
		}
		select {
		case <-st.Context().Done():
			return nil
		case <-time.After(30 * time.Millisecond):
		}
	}
}

func startFull(t *testing.T, path string) context.CancelFunc {
	t.Helper()
	l, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterVaultServiceServer(r, fakeVault{})
		v1.RegisterEventServiceServer(r, fakeEvents{})
	})
	return cancel
}

func (r *recorder) count(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.evs {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

func TestSubscribeOutlivesCallContext(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	defer startFull(t, sock)()
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	root, stop := context.WithCancel(context.Background())
	defer stop()
	Start(root, b)
	call, cancel := context.WithCancel(context.Background())
	if err := b.Subscribe(call, []string{"j1"}); err != nil {
		t.Fatal(err)
	}
	cancel() // Wails cancela el contexto de la llamada al volver
	time.Sleep(300 * time.Millisecond)
	if n := rec.count("core:event"); n < 3 {
		t.Fatalf("events after the call returned = %d", n)
	}
	b.Subscribe(context.Background(), []string{"j1"}) // repetido: no abre otro stream
	before := rec.count("core:event")
	time.Sleep(300 * time.Millisecond)
	if got := rec.count("core:event") - before; got > 15 {
		t.Fatalf("duplicate stream: %d events in 300ms", got)
	}
}

func TestResubscribeAfterReconnect(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	stopSrv := startFull(t, sock)
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	b.Interval = 50 * time.Millisecond
	root, stop := context.WithCancel(context.Background())
	defer stop()
	Start(root, b)
	rec.waitFor(t, `core:status "connected"`)
	b.Subscribe(context.Background(), []string{"j1"})
	stopSrv()
	rec.waitFor(t, `core:status "disconnected"`)
	os.Remove(sock)
	defer startFull(t, sock)()
	rec.reset()
	rec.waitFor(t, `core:status "connected"`)
	time.Sleep(400 * time.Millisecond)
	if rec.count("core:event") == 0 {
		t.Fatal("subscription not re-established after reconnect")
	}
}

func TestStatusMethod(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(filepath.Join(d, "nada.sock")) }, func(string, any) {})
	b.Interval = 30 * time.Millisecond
	root, stop := context.WithCancel(context.Background())
	defer stop()
	Start(root, b)
	time.Sleep(200 * time.Millisecond)
	if s := b.Status(); s != "disconnected" {
		t.Fatalf("Status = %q", s)
	}
}

type fakeAcl struct {
	v1.UnimplementedAclServiceServer
}

func (fakeAcl) Import(_ context.Context, r *v1.ImportRequest) (*v1.ImportResponse, error) {
	return &v1.ImportResponse{Acl: &v1.Acl{Name: "X", Rules: []*v1.AclRule{{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: "ip", Source: "0.0.0.0/0", Destination: "0.0.0.0/0"}}}}, nil
}

func (fakeAcl) Analyze(context.Context, *v1.AnalyzeRequest) (*v1.AnalyzeResponse, error) {
	return &v1.AnalyzeResponse{Findings: []*v1.Finding{{RuleIndex: 0, Kind: "redundant", Detail: "d"}}}, nil
}

func (fakeAcl) Generate(_ context.Context, r *v1.GenerateRequest) (*v1.GenerateResponse, error) {
	return &v1.GenerateResponse{Script: "ip access-list extended " + r.Acl.Name + "\n"}, nil
}

func TestAclBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAclServiceServer(r, fakeAcl{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	a, err := b.AclImport("asa", "x")
	if err != nil || a.Name != "X" || len(a.Rules) != 1 || a.Rules[0].Action != "permit" {
		t.Fatalf("%+v %v", a, err)
	}
	f, err := b.AclAnalyze(a)
	if err != nil || len(f) != 1 || f[0].Kind != "redundant" {
		t.Fatalf("%+v %v", f, err)
	}
	s, err := b.AclGenerate("ios-xe", a)
	if err != nil || !strings.HasPrefix(s, "ip access-list extended X") {
		t.Fatalf("%q %v", s, err)
	}
}

type fakeDiag struct {
	v1.UnimplementedDiagServiceServer
}

func (fakeDiag) Run(r *v1.RunRequest, st v1.DiagService_RunServer) error {
	for i := 0; i < 3; i++ {
		if err := st.Send(&v1.RunResponse{OutputLine: "línea"}); err != nil {
			return err
		}
		select {
		case <-st.Context().Done():
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
	return st.Send(&v1.RunResponse{Done: true, ExitCode: 0, OutputPath: "/out/x.txt"})
}

func TestDiagBridgeStreamsAndCancels(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterDiagServiceServer(r, fakeDiag{}) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	id, err := b.DiagRun("ping", []string{"192.0.2.1"}, map[string]string{"count": "2"})
	if err != nil || id == "" {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for rec.count("diag:done") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rec.count("diag:line") != 3 || rec.count("diag:done") != 1 {
		t.Fatalf("events = %v", rec.evs)
	}
	id2, _ := b.DiagRun("ping", []string{"192.0.2.1"}, nil)
	rec.reset()
	if err := b.DiagCancel(id2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if rec.count("diag:line") >= 3 {
		t.Fatalf("cancel did not stop the stream: %v", rec.evs)
	}
}

// resubscribe (al conectar) puede reemplazar el stream de un trabajo mientras Subscribe
// aún lo abre: la llamada no debe fallar con Canceled, el stream nuevo ya cubre el trabajo.
func TestSubscribeSupersededByResubscribe(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	defer startFull(t, sock)()
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	root, stop := context.WithCancel(context.Background())
	defer stop()
	b.ctx = root
	if err := b.open("j1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		done := make(chan struct{})
		go func() { b.resubscribe(); close(done) }()
		if err := b.open("j1"); err != nil {
			t.Fatalf("iteración %d: %v", i, err)
		}
		<-done
	}
}

// dyingEvents emite latidos por trabajo y termina con Unavailable cuando cierran kill.
type dyingEvents struct {
	v1.UnimplementedEventServiceServer
	mu   sync.Mutex
	kill chan struct{}
}

func (e *dyingEvents) current() chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.kill
}

func (e *dyingEvents) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	kill := e.current() // cada stream muere con el kill vigente al abrirse
	for {
		if err := st.Send(&v1.SubscribeResponse{JobId: r.JobIds[0], Event: &v1.SubscribeResponse_Heartbeat{Heartbeat: &v1.Heartbeat{}}}); err != nil {
			return err
		}
		select {
		case <-st.Context().Done():
			return nil
		case <-kill:
			return status.Error(codes.Unavailable, "cae el stream")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// Un stream que murió (Recv) o cuya apertura falló no puede dejar al trabajo marcado como
// suscrito: el siguiente Subscribe tiene que abrirlo de nuevo.
func TestSubscribeReopensAfterStreamDiesOrOpenFails(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ev := &dyingEvents{kill: make(chan struct{})}
	sctx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()
	go ipc.Serve(sctx, l, func(r ipc.Registrar) { v1.RegisterEventServiceServer(r, ev) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	b.ctx = sctx
	waitJob := func(id string) {
		t.Helper()
		rec.reset()
		deadline := time.Now().Add(3 * time.Second)
		for rec.count(`core:event {"jobId":"`+id+`"`) < 3 {
			if time.Now().After(deadline) {
				t.Fatalf("sin eventos de %s: %v", id, rec.evs)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if err := b.Subscribe(sctx, []string{"j1"}); err != nil {
		t.Fatal(err)
	}
	waitJob("j1")
	close(ev.current()) // el stream de j1 muere: Recv devuelve error
	time.Sleep(200 * time.Millisecond)
	ev.mu.Lock()
	ev.kill = make(chan struct{})
	ev.mu.Unlock()
	b.Subscribe(sctx, []string{"j1"})
	waitJob("j1")

	b.mu.Lock()
	b.conn.Close() // la apertura falla de inmediato: conexión cerrada
	b.mu.Unlock()
	if err := b.open("j2"); err == nil {
		t.Fatal("la apertura con la conexión cerrada debía fallar")
	}
	b.mu.Lock()
	b.conn = nil
	b.mu.Unlock()
	b.Subscribe(sctx, []string{"j2"})
	waitJob("j2")
}
