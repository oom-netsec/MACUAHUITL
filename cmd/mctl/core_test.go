package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	corecmd "github.com/oom-netsec/MACUAHUITL/cmd/mctl/core"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

type fakeLifecycle struct {
	v1.UnimplementedCoreServiceServer
	shutdown func() error
}

func (f fakeLifecycle) Shutdown(context.Context, *v1.ShutdownRequest) (*v1.ShutdownResponse, error) {
	return &v1.ShutdownResponse{}, f.shutdown()
}

// coreStopEnv levanta un CoreService doble en el socket de la prueba y deja los puntos de apoyo de core stop como estaban.
func coreStopEnv(t *testing.T, shutdown func() error) *bytes.Buffer {
	t.Helper()
	rt, _ := os.MkdirTemp("", "mctl")
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)
	var stderr bytes.Buffer
	pid, wait, errOut := corecmd.ServerPID, corecmd.WaitExit, corecmd.Stderr
	corecmd.Stderr = &stderr
	t.Cleanup(func() { corecmd.ServerPID, corecmd.WaitExit, corecmd.Stderr = pid, wait, errOut })
	if shutdown != nil {
		sock, _ := ipc.SocketPath()
		l, err := ipc.Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		s := ipc.NewServer()
		v1.RegisterCoreServiceServer(s, fakeLifecycle{shutdown: shutdown})
		go s.Serve(l)
		t.Cleanup(s.Stop)
	}
	return &stderr
}

func TestCoreStopSinNucleoSale0(t *testing.T) {
	stderr := coreStopEnv(t, nil)
	out, err := mctlRaw(t, "", "core", "stop")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out != "" || !strings.Contains(stderr.String(), "the core was not running") {
		t.Fatalf("out %q stderr %q", out, stderr.String())
	}
	// un socket huérfano (núcleo muerto) es lo mismo
	sock, _ := ipc.SocketPath()
	l, _ := ipc.Listen(sock)
	l.Close()
	os.WriteFile(sock, nil, 0o600) // deja un archivo donde estaba el socket
	stderr.Reset()
	if _, err := mctlRaw(t, "", "core", "stop"); err != nil || !strings.Contains(stderr.String(), "was not running") {
		t.Fatalf("socket huérfano: err %v stderr %q", err, stderr.String())
	}
}

func TestCoreStopNegativaSale3(t *testing.T) {
	coreStopEnv(t, func() error {
		return status.Error(codes.FailedPrecondition, "work is running, not shutting down: assist run r1 (sw1); stream FieldService/ServeFiles")
	})
	out, err := mctlRaw(t, "", "core", "stop")
	if cli.ExitCode(err) != 3 || err == nil || !strings.Contains(err.Error(), "assist run r1 (sw1)") || !strings.Contains(err.Error(), "FieldService/ServeFiles") {
		t.Fatalf("err = %v (código %d)", err, cli.ExitCode(err))
	}
	if strings.Contains(out, "stopped") {
		t.Fatalf("dijo que paró: %q", out)
	}
}

func TestCoreStopPlazoVencidoSale1(t *testing.T) {
	coreStopEnv(t, func() error { return nil })
	corecmd.ServerPID = func(string) (int, error) { return 4242, nil }
	var gotPID int
	corecmd.WaitExit = func(pid int, _ time.Duration) error { gotPID = pid; return sys.ErrWaitTimeout } // el proceso sigue vivo
	_, err := mctlRaw(t, "", "core", "stop", "--timeout", "300ms")
	if err == nil || cli.ExitCode(err) != 1 || !strings.Contains(err.Error(), "did not exit in time") || gotPID != 4242 {
		t.Fatalf("err = %v (código %d), pid esperado %d", err, cli.ExitCode(err), gotPID)
	}
}

func TestCoreStopEsperaAlProcesoNoAlSocket(t *testing.T) {
	coreStopEnv(t, func() error { return nil })
	corecmd.ServerPID = func(string) (int, error) { return 4242, nil }
	var waited bool
	corecmd.WaitExit = func(pid int, d time.Duration) error { waited = pid == 4242 && d > 0 && d <= 10*time.Second; return nil }
	out, err := mctlRaw(t, "", "core", "stop", "--timeout", "10s")
	if err != nil || !strings.Contains(out, "core stopped (PID 4242)") || !waited {
		t.Fatalf("out %q err %v waited %v", out, err, waited)
	}
}

func TestCoreStopUso(t *testing.T) {
	coreStopEnv(t, nil)
	for _, args := range [][]string{{"core", "stop", "extra"}, {"core", "stop", "--timeout", "0s"}} {
		if _, err := mctlRaw(t, "", args...); err == nil || !strings.Contains(err.Error(), "usage: mctl core stop") {
			t.Fatalf("%v: err = %v", args, err)
		}
	}
}

// Unavailable con el PID ya conocido: el núcleo se está apagando (otro core stop o SIGTERM); se espera a ese proceso.
func TestCoreStopUnavailableEsperaAlPID(t *testing.T) {
	coreStopEnv(t, func() error { return status.Error(codes.Unavailable, "cerrando") })
	corecmd.ServerPID = func(string) (int, error) { return 4242, nil }
	var waited int
	corecmd.WaitExit = func(pid int, _ time.Duration) error { waited = pid; return sys.ErrWaitTimeout }
	_, err := mctlRaw(t, "", "core", "stop", "--timeout", "1s")
	if waited != 4242 || err == nil || !strings.Contains(err.Error(), "did not exit in time") {
		t.Fatalf("waited %d err %v", waited, err)
	}
	corecmd.WaitExit = func(int, time.Duration) error { return nil }
	if out, err := mctlRaw(t, "", "core", "stop"); err != nil || !strings.Contains(out, "core stopped") {
		t.Fatalf("out %q err %v", out, err)
	}
}

func TestCoreStopPIDInvalidoSale1(t *testing.T) {
	coreStopEnv(t, func() error { t.Error("llamó a Shutdown con PID 0"); return nil })
	corecmd.ServerPID = func(string) (int, error) { return 0, nil }
	corecmd.WaitExit = func(int, time.Duration) error {
		t.Error("no debía llamar a Shutdown ni esperar con PID 0")
		return nil
	}
	if _, err := mctlRaw(t, "", "core", "stop"); err == nil || cli.ExitCode(err) != 1 {
		t.Fatalf("err = %v", err)
	}
}
