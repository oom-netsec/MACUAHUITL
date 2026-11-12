package diag

import (
	"net" // want `importa "net"`

	_ "github.com/oom-netsec/MACUAHUITL/internal/diag/dnsq" // propio subpaquete: permitido
)

var _ net.Conn
