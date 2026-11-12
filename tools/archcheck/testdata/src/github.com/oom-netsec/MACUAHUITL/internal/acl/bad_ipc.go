package acl

import (
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"       // want `un dominio no importa ipc ni transport`
	"github.com/oom-netsec/MACUAHUITL/internal/transport" // want `un dominio no importa ipc ni transport`
)

var (
	_ ipc.Conn
	_ transport.Guard
)
