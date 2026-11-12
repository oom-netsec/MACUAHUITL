package core

import (
	"github.com/oom-netsec/MACUAHUITL/internal/acl"  // want `core no importa dominios \(internal/acl\)`
	"github.com/oom-netsec/MACUAHUITL/internal/calc" // want `core no importa dominios \(internal/calc\)`
	svc "github.com/oom-netsec/MACUAHUITL/internal/service/acl"
	"github.com/oom-netsec/MACUAHUITL/internal/vault" // no es dominio: permitido
)

var (
	_ acl.Rule
	_ = vault.Open
	_ = calc.Subnet
	_ svc.Svc
)
