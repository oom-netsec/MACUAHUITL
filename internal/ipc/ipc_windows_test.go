package ipc

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

type peerVault struct {
	v1.UnimplementedVaultServiceServer
	got chan PeerInfo
}

func (p peerVault) Status(ctx context.Context, _ *v1.StatusRequest) (*v1.StatusResponse, error) {
	pi, _ := PeerFromContext(ctx)
	p.got <- pi
	return &v1.StatusResponse{}, nil
}

func TestPipeLlamadaFunciona(t *testing.T) {
	name := sockPath(t)
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l)
	if err := call(t, name); status.Code(err) != codes.Unimplemented { // el servicio responde: llegó hasta gRPC
		t.Fatalf("err = %v, quería Unimplemented", err)
	}
}

func TestPipeSegundoListenRechazado(t *testing.T) {
	name := sockPath(t)
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := Listen(name); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("segundo Listen = %v, quería ErrAlreadyRunning (FIRST_PIPE_INSTANCE)", err)
	}
}

func TestPipeServerPIDEsElPropio(t *testing.T) {
	name := sockPath(t)
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l)
	pid, err := ServerPID(name)
	if err != nil || pid != os.Getpid() {
		t.Fatalf("ServerPID = %d, %v; quería %d", pid, err, os.Getpid())
	}
}

func TestPipeServerPIDSinPipe(t *testing.T) {
	if _, err := ServerPID(sockPath(t)); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("ServerPID sin pipe = %v, quería ErrNotRunning", err)
	}
}

func TestPipePeerInfoDaPID(t *testing.T) {
	l, err := Listen(sockPath(t))
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer()
	sv := peerVault{got: make(chan PeerInfo, 1)}
	v1.RegisterVaultServiceServer(s, sv)
	go s.Serve(l)
	t.Cleanup(s.Stop)
	call(t, l.Addr().String())
	if pi := <-sv.got; pi.PID != os.Getpid() || pi.UID != -1 {
		t.Fatalf("PeerInfo = %+v, quería pid %d uid -1", pi, os.Getpid())
	}
}

// Un cliente con otro SID se cierra antes de hablar gRPC: la comparación va en peerListener.Accept; aquí se comprueba
// que el pipe real del usuario lleva su SID y que el SID propio se lee.
func TestPipeNombreLlevaElSID(t *testing.T) {
	p, err := SocketPath()
	if err != nil || !strings.HasPrefix(p, `\\.\pipe\macuahuitl-S-1-5-`) {
		t.Fatalf("SocketPath = %q, %v", p, err)
	}
	if got, err := pidSID(windows.GetCurrentProcessId()); err != nil || !sameSID(got, p[len(`\\.\pipe\macuahuitl-`):]) {
		t.Fatalf("pidSID(propio) = %q, %v", got, err)
	}
}

func TestPipeSDDLSoloElUsuario(t *testing.T) {
	if got := pipeSDDL("S-1-5-21-1-2-3-1001"); got != "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)" {
		t.Fatalf("pipeSDDL = %q", got)
	}
}
