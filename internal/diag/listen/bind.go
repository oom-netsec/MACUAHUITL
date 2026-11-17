package listen

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"syscall"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Errno de Winsock que Go no mapea a syscall.EACCES / EADDRINUSE.
const (
	wsaEACCES     = syscall.Errno(10013)
	wsaEADDRINUSE = syscall.Errno(10048)
)

// minSysctlPort es el puerto más bajo que se sugiere en el sysctl (el FTP de control, 21).
const minSysctlPort = 21

// Bind traduce el error de abrir un socket (ADR 0004, enmienda 2026-11-16): el código no tiene privilegios, el kernel
// decide. port es el que falló; el sysctl sugerido lo usa (mínimo 21). Cualquier otro error se devuelve envuelto en
// "prefijo: ..." con su causa.
func Bind(prefix string, err error, port int) error {
	return bindFor(runtime.GOOS, prefix, err, port)
}

func bindFor(goos, prefix string, err error, port int) error {
	var en syscall.Errno
	if err == nil || !errors.As(err, &en) || port == 0 {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	denied, inUse := en == syscall.EACCES || en == syscall.EPERM, en == syscall.EADDRINUSE
	if goos == "windows" {
		denied, inUse = en == wsaEACCES, en == wsaEADDRINUSE
	}
	args := i18n.A("port", port)
	switch {
	case inUse:
		return i18n.Wrap("fileserve.err.port_in_use", err, args)
	case denied && goos == "linux" && port < 1024:
		low := max(port, minSysctlPort)
		args["min_port"] = strconv.Itoa(low)
		args["cmd"] = fmt.Sprintf("echo 'net.ipv4.ip_unprivileged_port_start=%d' | sudo tee /etc/sysctl.d/60-macuahuitl.conf && sudo sysctl --system", low)
		return i18n.Wrap("fileserve.err.port_denied", err, args)
	case denied && goos == "linux":
		return i18n.Wrap("fileserve.err.port_denied_linux", err, args)
	case denied:
		return i18n.Wrap("fileserve.err.port_denied_win", err, args)
	}
	return fmt.Errorf("%s: %w", prefix, err)
}

// PortOf es el puerto de "host:puerto" (0 si no se lee).
func PortOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return n
}
