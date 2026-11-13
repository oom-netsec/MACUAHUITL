package core

import (
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/acl"
	"github.com/oom-netsec/MACUAHUITL/internal/service/adhoc"
	"github.com/oom-netsec/MACUAHUITL/internal/service/analysis"
	"github.com/oom-netsec/MACUAHUITL/internal/service/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/service/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/service/calc"
	"github.com/oom-netsec/MACUAHUITL/internal/service/change"
	"github.com/oom-netsec/MACUAHUITL/internal/service/cleaner"
	"github.com/oom-netsec/MACUAHUITL/internal/service/diag"
	"github.com/oom-netsec/MACUAHUITL/internal/service/drift"
	"github.com/oom-netsec/MACUAHUITL/internal/service/field"
	"github.com/oom-netsec/MACUAHUITL/internal/service/fleet"
	"github.com/oom-netsec/MACUAHUITL/internal/service/forensic"
	"github.com/oom-netsec/MACUAHUITL/internal/service/inventory"
	"github.com/oom-netsec/MACUAHUITL/internal/service/metrics"
	packsvc "github.com/oom-netsec/MACUAHUITL/internal/service/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/service/prefs"
	"github.com/oom-netsec/MACUAHUITL/internal/service/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service/security"
	"github.com/oom-netsec/MACUAHUITL/internal/service/terminal"
	"github.com/oom-netsec/MACUAHUITL/internal/service/tools"
	"github.com/oom-netsec/MACUAHUITL/internal/service/transfer"
	"github.com/oom-netsec/MACUAHUITL/internal/service/visibility"
)

// modules es la lista de servicios que atiende el núcleo: agregar un área = una línea aquí.
func modules(c *Core) []service.Module {
	return []service.Module{
		nucleo{c},
		acl.Module{},
		analysis.Module{},
		calc.Module{},
		change.Module{},
		diag.Module{},
		field.Module{},
		fleet.Module{},
		prefs.Module{},
		security.Module{},
		tools.Module{},
		visibility.Module{},
		assist.Module{},
		adhoc.Module{},
		drift.Module{},
		cleaner.Module{},
		backup.Module{},
		terminal.Module{},
		forensic.Module{},
		transfer.Module{},
		metrics.Module{},
		inventory.Module{},
		scripts.Module{Packs: c.packs},
		packsvc.Module{Store: c.packs, UserIDs: c.userIDs, ConfigDir: c.p.Config, UserPlaybooks: c.userPlaybooks, Reload: c.reloadUser},
	}
}

// nucleo registra los servicios que son el ciclo de vida del propio núcleo (bóveda, patrol,
// eventos, auditoría): leen y mutan el estado interno de Core (jobs, bus, planificador, bóveda),
// así que no caben detrás de service.Deps.
type nucleo struct{ c *Core }

func (n nucleo) Register(s ipc.Registrar, _ service.Deps) {
	v1.RegisterVaultServiceServer(s, &vaultSvc{c: n.c})
	v1.RegisterPatrolServiceServer(s, &patrolSvc{c: n.c})
	v1.RegisterEventServiceServer(s, &eventSvc{c: n.c})
	v1.RegisterAuditServiceServer(s, &auditSvc{c: n.c})
}
