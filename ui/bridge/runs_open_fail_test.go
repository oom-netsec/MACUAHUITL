package bridge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Si abrir el stream falla, DiagRun y SyslogStart no dejan su id en b.runs (nadie lo cancelaría ni lo borraría).
func TestRunsSeBorranSiFallaAbrirElStream(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	defer startFake(t, sock)()
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	c, err := b.client()
	if err != nil {
		t.Fatal(err)
	}
	c.Close() // abrir el stream falla de inmediato
	if _, err := b.DiagRun("ping", []string{"10.0.0.1"}, nil); err == nil {
		t.Fatal("DiagRun debía fallar")
	}
	if _, err := b.SyslogStart("127.0.0.1:5514", "udp", false, false, SyslogOptions{}); err == nil {
		t.Fatal("SyslogStart debía fallar")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.runs) != 0 {
		t.Fatalf("quedaron %d ejecuciones", len(b.runs))
	}
}
