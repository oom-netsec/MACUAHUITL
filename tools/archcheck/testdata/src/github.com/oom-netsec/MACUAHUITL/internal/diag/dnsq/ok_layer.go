package dnsq

import (
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1" // la capa de red de diag puede usar gen
	"github.com/oom-netsec/MACUAHUITL/internal/transport"   // y transport
)

var (
	_ v1.Acl
	_ transport.Guard
)

type Q struct{}
