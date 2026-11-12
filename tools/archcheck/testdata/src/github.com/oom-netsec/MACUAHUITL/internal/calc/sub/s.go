package sub

import (
	"net" // want `importa "net"`

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1" // want `importa "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"`
	"github.com/oom-netsec/MACUAHUITL/internal/transport"   // want `un dominio no importa ipc ni transport`
)

var (
	_ net.Conn
	_ v1.Acl
	_ transport.Guard
)
