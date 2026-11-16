package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func (h *harness) shutdown(t *testing.T) error {
	t.Helper()
	_, err := v1.NewCoreServiceClient(h.conn).Shutdown(ctx(t), &v1.ShutdownRequest{})
	return err
}

func (h *harness) sigueServiendo(t *testing.T) bool {
	t.Helper()
	select {
	case <-h.served:
		return false
	case <-time.After(300 * time.Millisecond):
		return true
	}
}

func TestShutdownSinTrabajoAuditaYTerminaServe(t *testing.T) {
	h := newHarness(t, nil)
	// Un suscriptor de eventos abierto (la UI siempre tiene uno) no es trabajo vivo.
	sc, cancel := context.WithCancel(ctx(t))
	defer cancel()
	if _, err := h.events.Subscribe(sc, &v1.SubscribeRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := h.shutdown(t); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	select {
	case <-h.served:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve no terminó")
	}
	// Serve ya terminó: la auditoría se lee de la bitácora, no del RPC.
	var n int
	want := fmt.Sprintf("pid=%d uid=%d", os.Getpid(), os.Getuid())
	if err := h.core.db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'core.shutdown' AND detail = ?`, want).Scan(&n); err != nil || n != 1 {
		t.Fatalf("core.shutdown con %q auditado %d veces (%v)", want, n, err)
	}
}

func TestShutdownConTrabajoVivoSeNiega(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.arm(t, h.ready(t)) // un trabajo de Patrol armado
	err := h.shutdown(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), job) {
		t.Fatalf("Shutdown = %v, quería FailedPrecondition con %s", err, job)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó con trabajo vivo")
	}
	if strings.Contains(h.auditText(t), `"action":"core.shutdown"`) {
		t.Fatal("auditó core.shutdown sin apagar")
	}
}

func TestShutdownListaCadaFuenteDeTrabajo(t *testing.T) {
	h := newHarness(t, nil)
	h.core.addBusy(func(context.Context) []string { return []string{"assist run r1 (sw1)"} })
	err := h.shutdown(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "assist run r1 (sw1)") {
		t.Fatalf("Shutdown = %v", err)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó con trabajo vivo")
	}
}

func TestShutdownSinAuditoriaNoApaga(t *testing.T) {
	h := newHarness(t, nil)
	h.core.db.Close()
	err := h.shutdown(t)
	if err == nil || status.Code(err) == codes.FailedPrecondition {
		t.Fatalf("Shutdown = %v, quería un error de auditoría", err)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó sin poder auditar")
	}
}

// espera a que el contador de trabajo vivo del núcleo muestre algo con ese texto.
func (h *harness) esperaVivo(t *testing.T, texto string) {
	t.Helper()
	for i := 0; i < 500; i++ {
		for _, l := range h.core.live.Active() {
			if strings.Contains(l, texto) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no apareció %q en %v", texto, h.core.live.Active())
}

func (h *harness) noSeApago(t *testing.T, err error, texto string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), texto) {
		t.Fatalf("Shutdown = %v, quería FailedPrecondition con %q", err, texto)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó con trabajo vivo")
	}
}

// Un stream real de trabajo (escucha de syslog) que no está en liveIgnore bloquea el apagado: fija c.live en Serve.
func TestShutdownConStreamDeEscuchaSeNiega(t *testing.T) {
	h := newHarness(t, nil)
	sc, cancel := context.WithCancel(ctx(t))
	defer cancel()
	st, err := v1.NewToolsServiceClient(h.conn).Syslog(sc, &v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recv(); err != nil {
		t.Fatal(err)
	}
	h.noSeApago(t, h.shutdown(t), "ToolsService/Syslog")
	cancel() // al cerrar la escucha, el núcleo ya puede apagarse
	h.esperaSinVivo(t)
	if err := h.shutdown(t); err != nil {
		t.Fatalf("sin escucha, Shutdown = %v", err)
	}
}

func (h *harness) esperaSinVivo(t *testing.T) {
	t.Helper()
	for i := 0; i < 500 && len(h.core.live.Active()) > 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if a := h.core.live.Active(); len(a) > 0 {
		t.Fatalf("sigue vivo: %v", a)
	}
}

// Una transferencia unaria viva (Get hacia un TFTP que no contesta) bloquea el apagado.
func TestShutdownConTransferenciaUnariaSeNiega(t *testing.T) {
	h := newHarness(t, nil)
	gc, cancel := context.WithCancel(ctx(t))
	defer cancel()
	done := make(chan struct{})
	go func() {
		v1.NewTransferServiceClient(h.conn).Get(gc, &v1.GetRequest{Url: "tftp://127.0.0.1:1/x.bin", DestDir: h.out, TimeoutSeconds: 20})
		close(done)
	}()
	h.esperaVivo(t, "TransferService/Get")
	h.noSeApago(t, h.shutdown(t), "TransferService/Get")
	cancel()
	<-done
}

// El Busy de assist está cableado al apagado (assist.Module{Busy: c.addBusy}): sin él, una ejecución asistida viva no se vería.
func TestShutdownTieneLaFuenteDeAssist(t *testing.T) {
	h := newHarness(t, nil)
	h.core.mu.Lock()
	n := len(h.core.busy)
	h.core.mu.Unlock()
	if n != 1 {
		t.Fatalf("fuentes de trabajo registradas = %d, quería 1 (assist)", n)
	}
}
