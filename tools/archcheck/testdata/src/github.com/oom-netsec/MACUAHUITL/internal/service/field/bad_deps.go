package field

import (
	"github.com/oom-netsec/MACUAHUITL/internal/core"                // want `un servicio no depende de core`
	"github.com/oom-netsec/MACUAHUITL/internal/service/calc"        // want `un servicio no importa el de otra área`
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest" // want `servicetest es solo para pruebas`
)

var (
	_ core.Core
	_ calc.Svc
	_ servicetest.Env
)
