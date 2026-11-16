package ipc

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerInfo es quién llama, según el sistema al aceptar la conexión: en Linux SO_PEERCRED (PID y UID); en Windows
// GetNamedPipeClientProcessId (PID) y UID siempre -1, porque la identidad es un SID que ya se comparó en Accept. PID y
// UID son -1 si no se pudieron leer.
type PeerInfo struct{ PID, UID int }

func (PeerInfo) AuthType() string { return authType }

// PeerFromContext da el PeerInfo del cliente de una llamada gRPC (para auditar quién pidió algo).
func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return PeerInfo{}, false
	}
	pi, ok := p.AuthInfo.(PeerInfo)
	return pi, ok
}

// peerCreds no cifra nada (el canal es local y privado): solo deja el PID y el UID del cliente en el contexto.
type peerCreds struct{}

func (peerCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, peerOf(c), nil
}
func (peerCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, PeerInfo{PID: -1, UID: -1}, nil
}
func (peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: authType}
}
func (peerCreds) Clone() credentials.TransportCredentials { return peerCreds{} }
func (peerCreds) OverrideServerName(string) error         { return nil }
