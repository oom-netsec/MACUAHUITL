package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
)

// Pipe de Windows (ADR 0012 a). go-winio (MIT) crea el pipe con NtCreateNamedPipeFile: la primera instancia con
// FILE_CREATE (falla si el nombre existe: el equivalente de FILE_FLAG_FIRST_PIPE_INSTANCE y el candado de instancia
// única) y FILE_PIPE_REJECT_REMOTE_CLIENTS siempre; el descriptor SDDL se aplica a esa primera instancia.

var ownSID = sync.OnceValues(func() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
})

// CoreAddr es el nombre del pipe del usuario; runtime se ignora (en Windows no hay carpeta runtime).
func CoreAddr(string) (string, error) { return SocketPath() }

// SocketPath es \\.\pipe\macuahuitl-<SID del usuario>.
func SocketPath() (string, error) {
	sid, err := ownSID()
	if err != nil {
		return "", fmt.Errorf("ipc: %w", err)
	}
	return `\\.\pipe\macuahuitl-` + sid, nil
}

// pipeSDDL es la DACL protegida con un solo acceso: el SID del usuario. Sin Everyone, sin Usuarios, sin herencia.
func pipeSDDL(sid string) string { return "D:P(A;;GA;;;" + sid + ")" }

// Listen crea el pipe name solo para el usuario actual y solo acepta clientes cuyo proceso tenga su mismo SID.
// ErrAlreadyRunning si el nombre ya existe.
func Listen(name string) (net.Listener, error) {
	sid, err := ownSID()
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSDDL(sid), InputBufferSize: 64 << 10, OutputBufferSize: 64 << 10})
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return nil, fmt.Errorf("%w (%v)", ErrAlreadyRunning, err)
	}
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	return &peerListener{Listener: l, sid: sid}, nil
}

// peerListener cierra toda conexión cuyo cliente (GetNamedPipeClientProcessId) no corra con el SID esperado.
type peerListener struct {
	net.Listener
	sid string
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if sid, err := pipeSID(c, windows.GetNamedPipeClientProcessId); err == nil && sameSID(sid, l.sid) {
			return c, nil
		}
		c.Close()
	}
}

// pidOf lee el PID del otro extremo con get (cliente o servidor); fd es el handle del pipe de go-winio.
func pidOf(c net.Conn, get func(windows.Handle, *uint32) error) (uint32, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("ipc: la conexión no es un pipe")
	}
	var pid uint32
	if err := get(windows.Handle(f.Fd()), &pid); err != nil {
		return 0, err
	}
	return pid, nil
}

// pipeSID es el SID del usuario del proceso del otro extremo: PID → OpenProcess → OpenProcessToken → TokenUser.
func pipeSID(c net.Conn, get func(windows.Handle, *uint32) error) (string, error) {
	pid, err := pidOf(c, get)
	if err != nil {
		return "", err
	}
	return pidSID(pid)
}

func pidSID(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// dialPipe conecta al pipe y comprueba que su servidor corra con el SID del usuario: sin esto otro usuario podría
// crear el pipe antes y recibir la contraseña maestra. Devuelve el PID del servidor.
func dialPipe(ctx context.Context, name string) (net.Conn, uint32, error) {
	c, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		return nil, 0, err
	}
	own, err := ownSID()
	if err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("ipc: %w", err)
	}
	pid, err := pidOf(c, windows.GetNamedPipeServerProcessId)
	var sid string
	if err == nil {
		sid, err = pidSID(pid)
	}
	if err != nil || !sameSID(sid, own) {
		c.Close()
		return nil, 0, fmt.Errorf("ipc: el pipe %s no lo atiende un proceso de este usuario", name)
	}
	return c, pid, nil
}

// DialPath conecta al pipe name (pruebas y diagnóstico), verificando al servidor.
func DialPath(name string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		c, _, err := dialPipe(ctx, name)
		return c, err
	}
	return grpc.NewClient("passthrough:///core", baseDial(append([]grpc.DialOption{grpc.WithContextDialer(dialer)}, opts...))...)
}

// CoreRunning dice si el pipe del usuario existe y lo atiende un proceso suyo: abre y cierra, sin sesión gRPC.
func CoreRunning() (bool, error) {
	p, err := SocketPath()
	if err != nil {
		return false, err
	}
	return coreRunning(p)
}

func coreRunning(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := dialPipe(ctx, name)
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return false, nil
	case errors.Is(err, context.DeadlineExceeded): // todas las instancias ocupadas: el pipe existe
		return true, nil
	case err != nil:
		return false, err
	}
	c.Close()
	return true, nil
}
