package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func sockPath(t *testing.T) string {
	// Ruta corta: sun_path tiene 108 bytes.
	d, err := os.MkdirTemp("", "mcu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "run", "core.sock")
}

func serve(t *testing.T, l net.Listener) {
	s := NewServer()
	v1.RegisterVaultServiceServer(s, v1.UnimplementedVaultServiceServer{})
	go s.Serve(l)
	t.Cleanup(s.Stop)
}

func call(t *testing.T, path string) error {
	conn, err := DialPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = v1.NewVaultServiceClient(conn).Status(ctx, &v1.StatusRequest{})
	return err
}

func TestSocketPerms(t *testing.T) {
	p := sockPath(t)
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for path, want := range map[string]os.FileMode{filepath.Dir(p): 0o700, p: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s perm = %o, want %o", path, fi.Mode().Perm(), want)
		}
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	p := sockPath(t)
	os.MkdirAll(filepath.Dir(p), 0o700)
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	old.Close() // queda el archivo de un núcleo muerto
	l, err := Listen(p)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l.Close()
}

func TestSecondListenerRefused(t *testing.T) {
	p := sockPath(t)
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := Listen(p); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("err = %v", err)
	}
}

func TestPeerCredSameUIDAccepted(t *testing.T) {
	p := sockPath(t)
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l)
	if err := call(t, p); status.Code(err) != codes.Unimplemented {
		t.Fatalf("err = %v, want Unimplemented (handshake ok)", err)
	}
}

func TestPeerCredCheckRejects(t *testing.T) {
	p := sockPath(t)
	l, err := listen(p, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l)
	if err := call(t, p); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable (connection closed)", err)
	}
}

func TestSocketPathNeedsRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	if _, err := SocketPath(); err == nil {
		t.Fatal("empty XDG_RUNTIME_DIR accepted")
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if p, err := SocketPath(); err != nil || p != "/run/user/1000/macuahuitl/core.sock" {
		t.Fatalf("%q %v", p, err)
	}
}

func TestConcurrentStartWithStaleSocket(t *testing.T) {
	p := sockPath(t)
	os.MkdirAll(filepath.Dir(p), 0o700)
	old, _ := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	old.SetUnlinkOnClose(false)
	old.Close()
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			l, err := Listen(p)
			if err == nil {
				t.Cleanup(func() { l.Close() })
			}
			results <- err
		}()
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatalf("both or neither started: %v / %v", a, b)
	}
	if a != nil && !errors.Is(a, ErrAlreadyRunning) || b != nil && !errors.Is(b, ErrAlreadyRunning) {
		t.Fatalf("loser error = %v / %v", a, b)
	}
}

type eco struct {
	v1.UnimplementedForensicServiceServer
}

// Devuelve un texto del mismo tamaño que el recibido: prueba el límite en los dos sentidos.
func (eco) LogPatterns(_ context.Context, r *v1.LogPatternsRequest) (*v1.LogPatternsResponse, error) {
	return &v1.LogPatternsResponse{Report: &v1.ToolReport{Text: r.Source.Text}}, nil
}

// El límite por omisión de gRPC (4 MiB) es menor que el texto que acepta Forense (8 MiB).
func TestMensajesGrandes(t *testing.T) {
	p := sockPath(t)
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, l, func(r Registrar) { v1.RegisterForensicServiceServer(r, eco{}) })
	conn, err := DialPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := v1.NewForensicServiceClient(conn)
	for _, n := range []int{6 << 20, 8 << 20} {
		cx, stop := context.WithTimeout(ctx, 10*time.Second)
		r, err := c.LogPatterns(cx, &v1.LogPatternsRequest{Source: &v1.LogSource{Text: string(make([]byte, n))}})
		stop()
		if err != nil || len(r.Report.Text) != n {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
}
