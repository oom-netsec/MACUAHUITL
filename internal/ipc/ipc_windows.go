package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

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
	return `\\.\pipe\macuahuitl-` + sid + TestPipeSuffix, nil
}

// pipeSDDL fija el dueño del pipe (con un token elevado el dueño por omisión sería Administradores) y una DACL protegida
// con un solo acceso: el SID del usuario. Sin Everyone, sin Usuarios, sin herencia. El dueño lo lee dialPipe. La etiqueta
// Medium explícita (S:(ML;;NW;;;ME)) hace que «sin etiqueta» no pueda pasar por Medium: un proceso Medium puede fijar una
// etiqueta menor o igual a la suya sin privilegios, y uno Low no puede fijar Medium.
func pipeSDDL(sid string) string { return "O:" + sid + "D:P(A;;GA;;;" + sid + ")S:(ML;;NW;;;ME)" }

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
		var ie *i18n.Error
		if errors.As(perr, &ie) && ie.Code == "ipc.err.pipe_low_integrity" { // existe y es nuestro, pero de menor integridad
			return nil, i18n.Wrap(ie.Code, ErrAlreadyRunning, ie.Args)
		}
		return nil, i18n.Wrap("ipc.err.pipe_other_user", ErrAlreadyRunning, nil)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return nil, fmt.Errorf("%w (%v)", ErrAlreadyRunning, err)
	}
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	return &peerListener{Listener: closeWait{Listener: l, max: 2 * time.Second}, sid: sid}, nil
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
	sid, f := pidInfo(pid)
	if sid == "" {
		return "", f.Err
	}
	return sid, nil
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

// pipeLabel es el RID MÍNIMO de las etiquetas de integridad (SYSTEM_MANDATORY_LABEL_ACE de la SACL, todas, también las
// INHERIT_ONLY) del objeto pipe al que c está conectado; 0 si no tiene ninguna (serverTrusted lo rechaza). Con el handle
// del cliente basta READ_CONTROL. Cualquier error de lectura se propaga (falla cerrado).
func pipeLabel(c net.Conn) (uint32, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0, i18n.New("ipc.err.not_pipe", nil)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_KERNEL_OBJECT, windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	acl, _, err := sd.SACL()
	if err != nil {
		return 0, err
	}
	if acl == nil {
		return 0, nil
	}
	var menor uint32
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &a); err != nil {
			return 0, err
		}
		if a.Header.AceType != aceMandatoryLabel {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		n := sid.SubAuthorityCount()
		if n == 0 {
			return 0, errors.New("etiqueta de integridad sin RID")
		}
		if rid := sid.SubAuthority(uint32(n) - 1); menor == 0 || rid < menor {
			menor = rid
		}
	}
	return menor, nil
}

const aceMandatoryLabel = 0x11 // SYSTEM_MANDATORY_LABEL_ACE_TYPE; x/sys no la define

// heapMin es el tamaño mínimo de un búfer que Windows llena con punteros a sí mismo: por encima de 32 bytes, un make de
// tamaño variable nunca va al stack (ver factsOf).
const heapMin = 64

const tokenIsAppContainer = 29 // TOKEN_INFORMATION_CLASS::TokenIsAppContainer; x/sys no la define

// factsOf lee integridad, AppContainer y restricción de un token abierto con TOKEN_QUERY. Cualquier fallo va en Err.
func factsOf(tok windows.Token) tokenFacts {
	var f tokenFacts
	var n uint32
	// Label.Sid apunta dentro del propio búfer, y ese puntero lo escribe Windows en un []byte: si el búfer viviera en el
	// stack, al crecer el stack Go movería el búfer sin corregir Label.Sid, que quedaría apuntando al stack viejo ya
	// liberado («found pointer to free object», checkptr). Desde Go 1.25 un make de tamaño variable de hasta 32 bytes que
	// no escapa va al stack (el TOKEN_MANDATORY_LABEL mide 28): con 64 o más va siempre al heap.
	err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		f.Err = err
		return f
	}
	buf := make([]byte, max(n, heapMin))
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &n); err != nil {
		f.Err = err
		return f
	}
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		f.Err = errors.New("sin SID de integridad")
		return f
	}
	f.IL = sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1)
	var ac uint32
	if err := windows.GetTokenInformation(tok, tokenIsAppContainer, (*byte)(unsafe.Pointer(&ac)), 4, &n); err != nil {
		f.Err = err
		return f
	}
	f.AppContainer = ac != 0
	r, err := tok.IsRestricted()
	f.Restricted, f.Err = r, err
	return f
}

// pidInfo abre una sola vez el proceso pid (PROCESS_QUERY_LIMITED_INFORMATION) y su token (TOKEN_QUERY) y devuelve el SID
// del usuario y los datos del token. sid vacío = no se pudo leer (la causa va en facts.Err).
func pidInfo(pid uint32) (sid string, facts tokenFacts) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", tokenFacts{Err: err}
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", tokenFacts{Err: err}
	}
	defer tok.Close()
	facts = factsOf(tok)
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", tokenFacts{Err: err}
	}
	return u.User.Sid.String(), facts
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
	// proceso pudo heredar ese PID (o el creador, de integridad baja, pasó el handle a un hijo y murió). El dueño y la
	// etiqueta de integridad del objeto pipe no se pueden reutilizar así: se comprueban además, con el handle del
	// cliente (basta READ_CONTROL). El token por PID solo aporta AppContainer y token restringido.
	owner, oerr := pipeOwner(c)
	pid, perr := pidOf(c, windows.GetNamedPipeServerProcessId)
	var sid string
	var facts tokenFacts
	if perr == nil {
		sid, facts = pidInfo(pid)
	}
	if err := errors.Join(oerr, perr); err != nil || checkServer(owner, sid, own) != nil {
		c.Close()
		return nil, 0, i18n.New("ipc.err.pipe_not_user", i18n.A("name", name))
	}
	label, lerr := pipeLabel(c)
	if lerr != nil || serverTrusted(label, facts, factsOf(windows.GetCurrentProcessToken())) != nil {
		c.Close()
		return nil, 0, i18n.New("ipc.err.pipe_low_integrity", i18n.A("name", name))
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
