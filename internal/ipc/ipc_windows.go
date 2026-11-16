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

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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

// pipeSDDL fija el dueño del pipe (con un token elevado el dueño por omisión sería Administradores) y una DACL protegida
// con un solo acceso: el SID del usuario. Sin Everyone, sin Usuarios, sin herencia. El dueño lo lee dialPipe.
func pipeSDDL(sid string) string { return "O:" + sid + "D:P(A;;GA;;;" + sid + ")" }

// Listen crea el pipe name solo para el usuario actual y solo acepta clientes cuyo proceso tenga su mismo SID.
// ErrAlreadyRunning si el nombre ya existe.
func Listen(name string) (net.Listener, error) {
	sid, err := ownSID()
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSDDL(sid), InputBufferSize: 64 << 10, OutputBufferSize: 64 << 10})
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// FILE_CREATE sobre un pipe que ya existe da ACCESS_DENIED aunque sea del mismo usuario (el caso común: otro núcleo
		// nuestro). Se sondea: si conecta y pasa la verificación es nuestro; si no, lo tiene otro usuario.
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		c, _, perr := dialPipe(ctx, name)
		if perr == nil {
			c.Close()
		}
		if perr == nil || errors.Is(perr, context.DeadlineExceeded) { // ocupado: existe y no se sabe de quién; no se acusa
			return nil, fmt.Errorf("%w (%v)", ErrAlreadyRunning, err)
		}
		return nil, i18n.Wrap("ipc.err.pipe_other_user", ErrAlreadyRunning, nil)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
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
		return 0, i18n.New("ipc.err.not_pipe", nil)
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

// pipeOwner es el SID del dueño del objeto pipe al que c está conectado.
func pipeOwner(c net.Conn) (string, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return "", i18n.New("ipc.err.not_pipe", nil)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	o, _, err := sd.Owner()
	if err != nil || o == nil {
		return "", i18n.New("ipc.err.pipe_no_owner", nil)
	}
	return o.String(), nil
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
	// El PID solo no basta: GetNamedPipeServerProcessId da el de quien creó la instancia aunque ya haya muerto, y otro
	// proceso pudo heredar ese PID. El dueño del objeto pipe (fijado en pipeSDDL) no se puede reutilizar así: se
	// comprueba además. Con el handle del cliente, que ya tiene READ_CONTROL.
	owner, oerr := pipeOwner(c)
	pid, perr := pidOf(c, windows.GetNamedPipeServerProcessId)
	var sid string
	var serr error
	if perr == nil {
		sid, serr = pidSID(pid)
	}
	if err := errors.Join(oerr, perr, serr); err != nil || checkServer(owner, sid, own) != nil {
		c.Close()
		return nil, 0, i18n.New("ipc.err.pipe_not_user", i18n.A("name", name))
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
// Límite: con todas las instancias ocupadas da true sin verificar el SID del servidor. Es un DoS posible (otro usuario que
// ocupe las instancias), el mismo que ya permite el squatting del nombre; nunca entrega datos, y Dial sí verifica.
func CoreRunning() (bool, error) {
	p, err := SocketPath()
	if err != nil {
		return false, err
	}
	return coreRunning(p)
}

// coreRunningWait: CoreRunning vuelve antes del tic de 1 s del puente; con todas las instancias ocupadas el pipe existe.
const coreRunningWait = 500 * time.Millisecond

func coreRunning(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), coreRunningWait) // el puente lo consulta cada segundo
	defer cancel()
	c, _, err := dialPipe(ctx, name)
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return false, nil
	case errors.Is(err, context.DeadlineExceeded): // todas las instancias ocupadas: el pipe existe, sin comprobar su dueño
		return true, nil
	case err != nil:
		return false, err
	}
	c.Close()
	return true, nil
}
