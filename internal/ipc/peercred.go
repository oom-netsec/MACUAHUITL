package ipc

import (
	"context"
	"net"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerInfo es quién llama, según SO_PEERCRED al aceptar la conexión. PID y UID son -1 si no se pudieron leer.
type PeerInfo struct{ PID, UID int }

func (PeerInfo) AuthType() string { return "unix-peercred" }

// PeerFromContext da el PeerInfo del cliente de una llamada gRPC (para auditar quién pidió algo).
func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return PeerInfo{}, false
	}
	pi, ok := p.AuthInfo.(PeerInfo)
	return pi, ok
}

// peerCreds no cifra nada (el canal es un socket Unix 0600): solo deja el PID y el UID del cliente en el contexto.
type peerCreds struct{}

func (peerCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
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
	return c, pi, nil
}
func (peerCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, PeerInfo{PID: -1, UID: -1}, nil
}
func (peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix-peercred"}
}
func (peerCreds) Clone() credentials.TransportCredentials { return peerCreds{} }
func (peerCreds) OverrideServerName(string) error         { return nil }
