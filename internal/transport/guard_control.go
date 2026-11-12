package transport

import (
	"net/netip"
	"syscall"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
)

// Control es net.Dialer.Control para librerías que marcan por su cuenta (gosnmp):
// recibe la dirección ya resuelta y corta el socket antes de conectar si jobID no
// la tiene autorizada. El rechazo queda auditado igual que en DialNetwork.
func (g *Guard) Control(jobID string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if ap, err := netip.ParseAddrPort(address); err == nil && g.permitted(jobID, ap.Addr().Unmap(), ap.Port()) {
			return nil
		}
		g.onDeny(audit.Entry{Action: "egress.denied", Target: address, Detail: jobID + " " + network})
		return ErrEgressDenied
	}
}
