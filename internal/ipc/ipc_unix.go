//go:build !windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

// CoreAddr es la dirección del canal del núcleo: en Linux core.sock dentro de la carpeta runtime (en Windows, el
// nombre del pipe del usuario, y runtime se ignora).
func CoreAddr(runtime string) (string, error) { return filepath.Join(runtime, "core.sock"), nil }

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

// DialPath conecta a un socket concreto (pruebas y diagnóstico).
func DialPath(path string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.NewClient("unix://"+path, baseDial(opts)...)
}
