package ipc

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	_, err = Listen(name)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("segundo Listen = %v, quería ErrAlreadyRunning (FIRST_PIPE_INSTANCE)", err)
	}
	var ce *i18n.Error
	if errors.As(err, &ce) && ce.Code == "ipc.err.pipe_other_user" {
		t.Fatalf("el pipe es del mismo usuario y el error dice que es de otro: %v", err)
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
	if err := call(t, l.Addr().String()); status.Code(err) != codes.OK {
		t.Fatalf("call = %v", err)
	}
	select {
	case pi := <-sv.got:
		if pi.PID != os.Getpid() || pi.UID != -1 {
			t.Fatalf("PeerInfo = %+v, quería pid %d uid -1", pi, os.Getpid())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el servicio no vio la llamada")
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
	if got := pipeSDDL("S-1-5-21-1-2-3-1001"); got != "O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;S-1-5-21-1-2-3-1001)" {
		t.Fatalf("pipeSDDL = %q", got)
	}
}

// El pipe que crea Listen tiene como dueño al usuario y una DACL protegida con una sola ACE, la del usuario; dialPipe
// lo comprueba (B1) y la prueba lo lee con el mismo handle del cliente.
func TestPipeDuenoYDACL(t *testing.T) {
	name := sockPath(t)
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l)
	own, _ := ownSID()
	c, _, err := dialPipe(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if o, err := pipeOwner(c); err != nil || o != own {
		t.Fatalf("dueño = %q, %v; quería %q", o, err, own)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(c.(interface{ Fd() uintptr }).Fd()), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _, _ := sd.Control()
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 || ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL = %+v, control %x, %v; quería una ACE y protegida", acl, ctrl, err)
	}
	var a *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &a); err != nil || (*windows.SID)(unsafe.Pointer(&a.SidStart)).String() != own {
		t.Fatalf("la única ACE no es del usuario: %v", err)
	}
}

// Un pipe cuyo dueño no es el usuario (aquí Administradores, O:BA) se rechaza aunque su DACL deje entrar y su proceso
// sea el propio: es la comprobación del dueño de dialPipe (B1), de punta a punta.
func TestDialPipeRechazaDuenoAjeno(t *testing.T) {
	name := sockPath(t)
	own, _ := ownSID()
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "O:BAD:P(A;;GA;;;" + own + ")"})
	if err != nil {
		t.Skipf("este token no puede fijar a Administradores como dueño: %v", err) // ERROR_INVALID_OWNER sin elevar
	}
	serve(t, l)
	if c, _, err := dialPipe(context.Background(), name); err == nil {
		c.Close()
		t.Fatal("dialPipe aceptó un pipe de otro dueño")
	}
}

// El token real de este proceso (mismo que tendría el núcleo) se acepta como servidor, y sus datos son plausibles.
// Un servidor Low IL no se prueba aquí (sin hijo de token rebajado en CI): paso manual en la VM, ver el PR.
func TestServerTrustedConTokenPropio(t *testing.T) {
	own := factsOf(windows.GetCurrentProcessToken())
	if own.Err != nil || own.IL < 0x1000 || own.AppContainer || own.Restricted {
		t.Fatalf("token propio inesperado: %+v", own)
	}
	if err := serverTrusted(pidFacts(uint32(os.Getpid())), own); err != nil {
		t.Fatalf("el propio proceso debe aceptarse: %v", err)
	}
	if err := serverTrusted(pidFacts(0xFFFFFFF0), own); err == nil {
		t.Fatal("un PID que no se puede abrir debe rechazarse")
	}
}
