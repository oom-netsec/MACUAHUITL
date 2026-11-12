// Package ipc es dueño del socket Unix del núcleo: lo crea con permisos de
// solo-usuario, rechaza clientes de otro UID (SO_PEERCRED) y ofrece el Dial que
// usan la UI y mctl (spec §5.2).
//
// No hace: escuchar en TCP; solo socket Unix.
package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var ErrAlreadyRunning = errors.New("ipc: ya hay un núcleo escuchando en el socket")

// SocketPath es $XDG_RUNTIME_DIR/macuahuitl/core.sock.
func SocketPath() (string, error) {
	rt := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(rt) {
		return "", errors.New("ipc: XDG_RUNTIME_DIR no está definido; el núcleo corre como servicio de usuario de systemd")
	}
	return filepath.Join(rt, "macuahuitl", "core.sock"), nil
}

// Listen crea el socket (directorio 0700, socket 0600) y solo acepta clientes del mismo UID.
func Listen(path string) (net.Listener, error) { return listen(path, os.Getuid()) }

func listen(path string, uid int) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	// Un candado de archivo serializa arranques simultáneos: el kernel lo suelta si el núcleo muere.
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		// Con el candado tomado, un socket existente es de un núcleo muerto.
		if err := os.Remove(path); err != nil {
			lock.Close()
			return nil, fmt.Errorf("ipc: %w", err)
		}
	}
	old := syscall.Umask(0o177) // el socket nace 0600, sin ventana con otros permisos
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("ipc: %w", err)
	}
	return &peerListener{Listener: l, uid: uid, lock: lock}, nil
}

// peerListener cierra toda conexión cuyo UID (SO_PEERCRED) no sea el esperado.
type peerListener struct {
	net.Listener
	uid  int
	lock *os.File
}

func (l *peerListener) Close() error {
	err := l.Listener.Close()
	l.lock.Close()
	return err
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if peerUID(c) == l.uid {
			return c, nil
		}
		c.Close()
	}
}

func peerUID(c net.Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	uid := -1
	raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			uid = int(cred.Uid)
		}
	})
	return uid
}

// MaxMsg es el tamaño máximo de un mensaje gRPC en los dos sentidos. El límite por omisión (4 MiB)
// no alcanza para el texto que pega la UI (hasta 8 MiB en Forense) ni para sus informes; los
// servicios que devuelven listas largas acotan su informe por debajo de este tope.
const MaxMsg = 16 << 20

// NewServer crea el servidor gRPC del núcleo. Sin TLS: el canal es un socket Unix local
// protegido por permisos y SO_PEERCRED.
func NewServer(opts ...grpc.ServerOption) *grpc.Server {
	return grpc.NewServer(append([]grpc.ServerOption{grpc.MaxRecvMsgSize(MaxMsg), grpc.MaxSendMsgSize(MaxMsg)}, opts...)...)
}

// Dial conecta al núcleo del usuario actual.
func Dial(ctx context.Context, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	p, err := SocketPath()
	if err != nil {
		return nil, err
	}
	return DialPath(p, opts...)
}

// DialPath conecta a un socket concreto (pruebas y diagnóstico).
func DialPath(path string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.NewClient("unix://"+path, append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMsg), grpc.MaxCallSendMsgSize(MaxMsg))}, opts...)...)
}

// DialOption y WithLanguage dejan a un cliente pedir el idioma del núcleo sin tocar cada llamada: toda llamada,
// unaria o de stream, lleva el metadato accept-language.
type DialOption = grpc.DialOption

func WithLanguage(lang string) []DialOption {
	add := func(ctx context.Context) context.Context {
		return metadata.AppendToOutgoingContext(ctx, "accept-language", lang)
	}
	return []DialOption{
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(add(ctx), method, req, reply, cc, opts...)
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return streamer(add(ctx), desc, cc, method, opts...)
		}),
	}
}

// Alias para que el núcleo y los clientes usen gRPC sin importar red (noegress).
type (
	Listener   = net.Listener
	Registrar  = grpc.ServiceRegistrar
	ClientConn = grpc.ClientConn
)

// Serve registra los servicios y atiende l hasta que ctx termine. Al terminar espera
// a las llamadas en curso como máximo 2 s: un stream de eventos abierto no frena el apagado.
func Serve(ctx context.Context, l Listener, register func(Registrar), opts ...grpc.ServerOption) error {
	s := NewServer(opts...)
	register(s)
	go func() {
		<-ctx.Done()
		done := make(chan struct{})
		go func() { s.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			s.Stop()
		}
	}()
	return s.Serve(l)
}
