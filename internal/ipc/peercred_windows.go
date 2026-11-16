package ipc

import (
	"net"

	"golang.org/x/sys/windows"
)

const authType = "pipe-sid"

// peerOf da el PID real del cliente (GetNamedPipeClientProcessId). El SID ya se comparó en Accept, así que aquí no hay
// UID: vale siempre -1 y la auditoría de core.shutdown registra «uid=-1».
func peerOf(c net.Conn) PeerInfo {
	pid, err := pidOf(c, windows.GetNamedPipeClientProcessId)
	if err != nil {
		return PeerInfo{PID: -1, UID: -1}
	}
	return PeerInfo{PID: int(pid), UID: -1}
}
