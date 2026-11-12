package dnsq

import (
	"net" // la capa de red puede usar net

	"github.com/oom-netsec/MACUAHUITL/internal/calc" // want `otro dominio \(internal/calc\)`
	"github.com/oom-netsec/MACUAHUITL/internal/core" // want `importa "github.com/oom-netsec/MACUAHUITL/internal/core"`
)

var (
	_ net.Conn
	_ = calc.Subnet
	_ core.Core
)
