package bridge

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type relojFalso struct{ t time.Time }

func (r *relojFalso) now() time.Time         { return r.t }
func (r *relojFalso) avanza(d time.Duration) { r.t = r.t.Add(d) }

func lanzador(corre *bool, sondaErr error, inicio error) (*CoreLauncher, *int, *[]error, *relojFalso) {
	r := &relojFalso{t: time.Unix(1_700_000_000, 0)}
	starts, logs := 0, []error{}
	l := &CoreLauncher{
		Running: func() (bool, error) { return *corre, sondaErr },
		Start:   func() error { starts++; return inicio },
		Log:     func(err error) { logs = append(logs, err) },
		Now:     r.now,
	}
	return l, &starts, &logs, r
}

// Sin núcleo se lanza una vez y no se relanza antes de 30 s; después sí. Con núcleo, nunca.
func TestCoreLauncherFreno(t *testing.T) {
	corre := false
	l, starts, _, r := lanzador(&corre, nil, nil)
	l.check()
	if *starts != 1 {
		t.Fatalf("sin núcleo: %d arranques", *starts)
	}
	r.avanza(29 * time.Second)
	l.check()
	if *starts != 1 {
		t.Fatalf("antes de 30 s relanzó: %d", *starts)
	}
	r.avanza(2 * time.Second)
	l.check()
	if *starts != 2 {
		t.Fatalf("pasados 30 s no relanzó: %d", *starts)
	}
	corre = true
	r.avanza(time.Minute)
	l.check()
	if *starts != 2 {
		t.Fatalf("con núcleo corriendo lanzó otro: %d", *starts)
	}
}

// Si la sonda falla no se lanza nada (no se sabe si corre: dos núcleos no) y queda en el registro; un arranque fallido también.
func TestCoreLauncherErrores(t *testing.T) {
	corre := false
	l, starts, logs, _ := lanzador(&corre, errors.New("sonda"), nil)
	l.check()
	if *starts != 0 || len(*logs) != 1 {
		t.Fatalf("sonda con error: %d arranques, %v", *starts, *logs)
	}
	l.check() // el freno también vale para el registro: un error que sigue igual no se repite cada tic
	if len(*logs) != 1 {
		t.Fatalf("la sonda fallando se registró %d veces", len(*logs))
	}
	l, starts, logs, _ = lanzador(&corre, nil, errors.New("no existe macuahuitld.exe"))
	if l.check() || *starts != 1 || len(*logs) != 1 {
		t.Fatalf("arranque con error: %d arranques, %v", *starts, *logs)
	}
	l, _, _, _ = lanzador(&corre, nil, errors.New("x"))
	l.Log = nil // opcional: sin Log los errores se descartan
	l.check()
}

// Con el núcleo respondiendo no se consulta al lanzador.
func TestRunNoConsultaConNucleo(t *testing.T) {
	sock := ipctest.Addr(t.TempDir())
	defer startFake(t, sock)()
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	b.Interval = 10 * time.Millisecond
	var sondas atomic.Int32
	b.Launcher = &CoreLauncher{Running: func() (bool, error) { sondas.Add(1); return false, nil }, Start: func() error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(ctx); close(done) }()
	for deadline := time.Now().Add(2 * time.Second); b.Status() != "connected" && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	sondas.Store(0) // antes de conectar el núcleo falso aún no atendía: ahí sí se consulta, y está bien
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done
	if b.Status() != "connected" {
		t.Fatal("no conectó con el núcleo falso")
	}
	if n := sondas.Load(); n != 0 {
		t.Fatalf("con el núcleo conectado se consultó al lanzador %d veces", n)
	}
}

// run consulta al lanzador cuando el núcleo no responde, sin el candado del puente.
func TestRunLanzaCuandoNoHayNucleo(t *testing.T) {
	b := New(func() (*ipc.ClientConn, error) { return nil, errors.New("sin núcleo") }, func(string, any) {})
	b.Interval = 10 * time.Millisecond
	var sondas atomic.Int32
	b.Launcher = &CoreLauncher{
		Running: func() (bool, error) {
			if !b.mu.TryLock() {
				t.Error("la sonda corre con el candado del puente tomado")
			} else {
				b.mu.Unlock()
			}
			sondas.Add(1)
			return true, nil
		},
		Start: func() error { return nil },
		Log:   func(error) {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for sondas.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if sondas.Load() == 0 {
		t.Fatal("run no consultó al lanzador con el núcleo caído")
	}
}

// Frágil en Windows (#319): con un intervalo corto de prueba, la sonda de estado tenía un tope de 5×Interval (50 ms) y
// un núcleo lento por la carga del runner pasaba por desconectado. El tope ya no baja de probeMin: un núcleo que
// responde en 200 ms sigue conectado aunque el intervalo sea de 10 ms.
func TestSondaLentaNoDesconecta(t *testing.T) {
	sock := ipctest.Addr(t.TempDir())
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterVaultServiceServer(r, lentoVault{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	b.Interval = 10 * time.Millisecond
	rctx, rcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(rctx); close(done) }()
	for deadline := time.Now().Add(5 * time.Second); b.Status() != "connected" && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	st := b.Status()
	rcancel()
	<-done
	if st != "connected" {
		t.Fatalf("un núcleo que responde en 200 ms quedó %q", st)
	}
}

type lentoVault struct {
	v1.UnimplementedVaultServiceServer
}

func (lentoVault) Status(context.Context, *v1.StatusRequest) (*v1.StatusResponse, error) {
	time.Sleep(200 * time.Millisecond)
	return &v1.StatusResponse{}, nil
}

// Cerrar el puente con una sonda en vuelo no es perder el núcleo: el estado sigue «connected» y no se consulta al
// lanzador. Determinista: la segunda sonda se queda colgada hasta que la cancelen (en Windows la sonda por named pipe
// tarda más y el cierre de la prueba caía en medio).
func TestRunCerrarConSondaEnVueloNoDesconecta(t *testing.T) {
	sock := ipctest.Addr(t.TempDir())
	v := &colgadoVault{enVuelo: make(chan struct{}, 1)}
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	go ipc.Serve(sctx, l, func(r ipc.Registrar) { v1.RegisterVaultServiceServer(r, v) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	b.Interval = 10 * time.Millisecond
	var sondas atomic.Int32
	b.Launcher = &CoreLauncher{Running: func() (bool, error) { sondas.Add(1); return false, nil }, Start: func() error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(ctx); close(done) }()
	select {
	case <-v.enVuelo: // la primera sonda respondió (conectado) y la segunda está colgada
	case <-time.After(30 * time.Second):
		t.Fatal("la segunda sonda nunca llegó")
	}
	sondas.Store(0)
	cancel()
	<-done
	if s := b.Status(); s != "connected" {
		t.Fatalf("cerrar el puente lo dejó %q", s)
	}
	if n := sondas.Load(); n != 0 {
		t.Fatalf("al cerrar se consultó al lanzador %d veces", n)
	}
}

type colgadoVault struct {
	v1.UnimplementedVaultServiceServer
	n       atomic.Int32
	enVuelo chan struct{}
}

func (v *colgadoVault) Status(ctx context.Context, _ *v1.StatusRequest) (*v1.StatusResponse, error) {
	if v.n.Add(1) == 1 {
		return &v1.StatusResponse{}, nil
	}
	select {
	case v.enVuelo <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
