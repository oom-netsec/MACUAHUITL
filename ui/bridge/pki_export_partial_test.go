package bridge

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
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
	// La respuesta (4 bytes) pasa del tope de tamaño de archivo: write escribe 2 y falla con EFBIG.
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Skip(err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 2, Max: old.Max}); err != nil {
		t.Skip(err)
	}
	_, err := b.SecPkiExport(ExportDTO{Format: "p12", Cert: "c", Path: dst})
	syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
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
