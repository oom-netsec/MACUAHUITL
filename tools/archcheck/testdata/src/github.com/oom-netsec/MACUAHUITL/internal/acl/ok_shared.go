package acl

import (
	"github.com/oom-netsec/MACUAHUITL/internal/audit"   // infraestructura: permitido
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf" // compartido
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"  // compartido
)

var (
	_ audit.X
	_ iosconf.X
	_ pcapan.X
)
