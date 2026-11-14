package bridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Si la escritura falla a medias, el archivo parcial se borra: con O_EXCL, dejarlo impediría reintentar con la misma ruta.
func TestSecPkiExportBorraElParcialSiFallaLaEscritura(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterSecurityServiceServer(r, fakeSec{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	dst := filepath.Join(d, "x.p12")
	old := exportWrite
	exportWrite = func(f *os.File, p []byte) (int, error) { n, _ := f.Write(p[:2]); return n, errors.New("disco lleno") }
	defer func() { exportWrite = old }()
	_, err := b.SecPkiExport(ExportDTO{Format: "p12", Cert: "c", Path: dst})
	exportWrite = old
	if err == nil {
		t.Fatal("la escritura debía fallar")
	}
	if _, serr := os.Stat(dst); !os.IsNotExist(serr) {
		t.Fatalf("quedó el archivo parcial: %v", serr)
	}
	if _, err := b.SecPkiExport(ExportDTO{Format: "p12", Cert: "c", Path: dst}); err != nil {
		t.Fatalf("no se pudo reintentar: %v", err)
	}
}
