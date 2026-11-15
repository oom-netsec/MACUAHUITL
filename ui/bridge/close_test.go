package bridge

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type slowAssist struct {
	v1.UnimplementedAssistServiceServer
	runs  []*v1.AssistRunState
	delay time.Duration
}

func (f *slowAssist) ListRuns(ctx context.Context, _ *v1.ListRunsRequest) (*v1.ListRunsResponse, error) {
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
	}
	return &v1.ListRunsResponse{Runs: f.runs}, nil
}

func busyConNucleo(t *testing.T, f *slowAssist) *Bridge {
	sock := filepath.Join(t.TempDir(), "c.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAssistServiceServer(r, f) })
	return New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
}

// Hallazgo 2: una ejecución viva en el núcleo sin stream local también cuenta; un núcleo mudo no bloquea el cierre.
func TestBusyConsultaAlNucleoLasEjecucionesVivas(t *testing.T) {
	if !Busy(busyConNucleo(t, &slowAssist{runs: []*v1.AssistRunState{{RunId: "r1", Active: true}}})) {
		t.Fatal("una ejecución viva en el núcleo debe avisar aunque no haya stream")
	}
	if Busy(busyConNucleo(t, &slowAssist{})) {
		t.Fatal("sin ejecuciones vivas no avisa")
	}
	t0 := time.Now()
	if Busy(busyConNucleo(t, &slowAssist{runs: []*v1.AssistRunState{{RunId: "r1", Active: true}}, delay: 10 * time.Second})) || time.Since(t0) > 3*time.Second {
		t.Fatal("un núcleo que no responde no debe bloquear el cierre")
	}
}

func TestCloseTextAclaraLaReversaGuardada(t *testing.T) {
	b := New(nil, func(string, any) {})
	b.setLanguage("es")
	if m := CloseTextFor(b).Message; !strings.Contains(m, "sin aplicar la reversa; queda guardada en Reversas pendientes (Cambios)") {
		t.Fatalf("es: %s", m)
	}
	b.setLanguage("en")
	if m := CloseTextFor(b).Message; !strings.Contains(m, "abandoned without rolling back; the rollback stays saved in Pending rollbacks (Changes)") {
		t.Fatalf("en: %s", m)
	}
}

func TestBusyCuentaLoQueSeCortaAlCerrar(t *testing.T) {
	b := New(func() (*ipc.ClientConn, error) { return nil, context.Canceled }, func(string, any) {}) // sin núcleo
	if Busy(b) {
		t.Fatal("sin nada en curso no debe avisar")
	}
	b.streams["job1"] = &stream{} // un trabajo de Patrol sigue en el núcleo: no cuenta
	if Busy(b) {
		t.Fatal("una suscripción de Patrol no corta nada al cerrar")
	}
	b.runs["r1"] = context.CancelFunc(func() {})
	if !Busy(b) {
		t.Fatal("una ejecución con stream se corta al cerrar")
	}
	delete(b.runs, "r1")
	b.assists["a1"] = &stream{}
	if !Busy(b) {
		t.Fatal("un cambio asistido en curso debe avisar")
	}
	delete(b.assists, "a1")
	b.terminals = map[string]*termSess{"t1": {}}
	if !Busy(b) {
		t.Fatal("una terminal abierta debe avisar")
	}
}

func TestCloseTextSigueElIdiomaDeLaInterfaz(t *testing.T) {
	b := New(nil, func(string, any) {})
	b.setLanguage("es")
	if got := CloseTextFor(b); got.Quit != "Cerrar igual" || got.Stay != "Cancelar" {
		t.Fatalf("es: %+v", got)
	}
	b.setLanguage("en")
	if got := CloseTextFor(b); got.Quit != "Close anyway" || got.Title != "Close MACUAHUITL?" {
		t.Fatalf("en: %+v", got)
	}
}
