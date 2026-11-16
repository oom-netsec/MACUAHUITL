//go:build !windows

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

const authType = "unix-peercred"

// peerOf lee SO_PEERCRED del socket aceptado.
func peerOf(c net.Conn) PeerInfo {
	pi := PeerInfo{PID: -1, UID: -1}
	if uc, ok := c.(*net.UnixConn); ok {
		if raw, err := uc.SyscallConn(); err == nil {
			raw.Control(func(fd uintptr) {
				if cr, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
					pi = PeerInfo{PID: int(cr.Pid), UID: int(cr.Uid)}
				}
			})
		}
	}
	return pi
}
