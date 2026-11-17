package field

import (
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// Revisión: un escáner no llena la auditoría ni bloquea la recepción aunque el
// cliente del stream no lea.
func TestServeSinkRejectionsAreCountedNotAudited(t *testing.T) {
	var mu sync.Mutex
	var audits []string
	unblock := make(chan struct{})
	var sent int
	k := newServeSink("es", func(a, _, d string) { mu.Lock(); audits = append(audits, a+" "+d); mu.Unlock() },
		func(*v1.ServeFilesResponse) error { <-unblock; mu.Lock(); sent++; mu.Unlock(); return nil })
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			k.onTransfer(fileserve.Transfer{Proto: "tftp", File: "x", Result: "error", Rejected: true})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("los rechazos bloquean al llamador")
	}
	mu.Lock()
	if len(audits) != 0 {
		t.Fatalf("rechazos auditados: %d", len(audits))
	}
	mu.Unlock()
	close(unblock)
	k.onTransfer(fileserve.Transfer{Proto: "tftp", File: "c9300.bin", Bytes: 3, Result: "ok"})
	n, rejected := k.stop()
	if n != 1 || rejected != 10000 {
		t.Fatalf("n=%d rechazos=%d", n, rejected)
	}
	if len(audits) != 1 || !strings.HasPrefix(audits[0], "field.serve.transfer") || !strings.Contains(audits[0], "c9300.bin") {
		t.Fatalf("auditoría: %v", audits)
	}
	if sent < 2 { // la transferencia real siempre llega; de los rechazos, los que quepan
		t.Fatalf("enviados %d", sent)
	}
}

// Cierre de seguridad de Campo: una sesión que nadie cerró pasa a failed «stopped» y se audita con session=.
func TestServeSinkShutdownAuditsStranded(t *testing.T) {
	d := servicetest.New(t)
	var audits []string
	k := newServeSink("es", func(a, _, det string) { audits = append(audits, a+" "+det) }, func(*v1.ServeFilesResponse) error { return nil })
	k.reg = d.TransferSessions().Open("F1")
	k.reg.Start(&fileserve.Live{Proto: "tftp", Client: "10.0.0.5:7", File: "x.bin", Dir: "lectura"})
	k.reg.Shutdown(func(x service.Stranded) { k.finished(x.T, x.ID, x.Total) })
	n, _ := k.stop()
	g, _, _ := d.TransferSessions().List("F1", "en")
	if n != 1 || len(g) != 1 || g[0].State != "failed" || g[0].ErrorCode != "fileserve.reason.stopped" {
		t.Fatalf("n=%d %+v", n, g)
	}
	if len(audits) != 1 || !strings.Contains(audits[0], "session="+g[0].Id) || !strings.Contains(audits[0], "result=error") {
		t.Fatalf("auditoría: %v", audits)
	}
}
