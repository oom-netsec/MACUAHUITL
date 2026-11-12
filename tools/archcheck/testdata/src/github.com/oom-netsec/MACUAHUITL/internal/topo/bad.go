package topo

import (
	"net" // want `importa "net"`

	"google.golang.org/grpc" // want `importa "google.golang.org/grpc"`

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"     // want `importa "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"`
	"github.com/oom-netsec/MACUAHUITL/internal/acl"             // want `otro dominio \(internal/acl\)`
	"github.com/oom-netsec/MACUAHUITL/internal/core"            // want `importa "github.com/oom-netsec/MACUAHUITL/internal/core"`
	svc "github.com/oom-netsec/MACUAHUITL/internal/service/acl" // want `importa "github.com/oom-netsec/MACUAHUITL/internal/service/acl"`
)

var (
	_ net.Conn
	_ grpc.Server
	_ v1.Acl
	_ acl.Rule
	_ core.Core
	_ svc.Svc
)
