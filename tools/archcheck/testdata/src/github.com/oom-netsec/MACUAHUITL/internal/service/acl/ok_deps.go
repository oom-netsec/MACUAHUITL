package acl

import (
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/calc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

var (
	_ audit.X
	_ = calc.Subnet
	_ ipc.Conn
	_ = iosxe.Parse
	_ service.Deps
	_ transport.Guard
	_ = vault.Open
)
