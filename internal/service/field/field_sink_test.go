package field

import (
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
)

// Revisión: un escáner no llena la auditoría ni bloquea la recepción aunque el
// cliente del stream no lea.
func TestServeSinkRejectionsAreCountedNotAudited(t *testing.T) {
	var mu sync.Mutex
	var audits []string
	unblock := make(chan struct{})
	var sent int
	k := newServeSink(func(a, _, d string) { mu.Lock(); audits = append(audits, a+" "+d); mu.Unlock() },
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
