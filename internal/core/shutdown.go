package core

import (
	"context"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// liveIgnore son los streams pasivos: quien los abre solo mira, no hay trabajo que cortar. Todo otro stream
// (escuchas de syslog, traps y flujos, capturas, servidores de archivos, terminales, consolas, transferencias)
// cuenta como trabajo vivo mientras esté abierto.
var liveIgnore = []string{"EventService/Subscribe", "AssistService/WatchRun", "AuditService/Export"}

// addBusy registra una fuente de trabajo vivo: devuelve una línea por cosa que correría y se cortaría al apagar.
func (c *Core) addBusy(f func(context.Context) []string) {
	c.mu.Lock()
	c.busy = append(c.busy, f)
	c.mu.Unlock()
}

// busyWork enumera todo el trabajo vivo: las fuentes de los servicios (ejecuciones asistidas, las mismas que
// ListRuns con ActiveOnly), los streams de trabajo abiertos y los trabajos de Patrol armados.
func (c *Core) busyWork(ctx context.Context) []string {
	c.mu.Lock()
	srcs := append([]func(context.Context) []string(nil), c.busy...)
	var jobs []string
	for id, j := range c.jobs {
		if j.state == "armed" || j.state == "arming" {
			jobs = append(jobs, "patrol job "+id+" ("+j.state+")")
		}
	}
	c.mu.Unlock()
	sort.Strings(jobs)
	var out []string
	for _, f := range srcs {
		out = append(out, f(ctx)...)
	}
	for _, m := range c.live.Active() {
		out = append(out, "stream "+m)
	}
	return append(out, jobs...)
}

// coreSvc es el ciclo de vida del propio núcleo (CoreService): lo que cancela Serve vive en Core.
type coreSvc struct {
	v1.UnimplementedCoreServiceServer
	c *Core
}

// Shutdown apaga el núcleo como SIGTERM, pero solo sin trabajo vivo y con la auditoría hecha.
// shortcut: un trabajo que arranque entre la revisión y la cancelación se corta igual que con SIGTERM; el cierre lo
// audita, y la ventana es de milisegundos.
func (s *coreSvc) Shutdown(ctx context.Context, _ *v1.ShutdownRequest) (*v1.ShutdownResponse, error) {
	if work := s.c.busyWork(ctx); len(work) > 0 {
		return nil, service.Err(ctx, codes.FailedPrecondition, "core.svc.shutdown_busy", i18n.A("work", strings.Join(work, "; ")))
	}
	who := "unix"
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		who = p.Addr.String()
	}
	// Sin rastro no hay acción: si no se puede auditar, el núcleo sigue en pie.
	if err := s.c.appendAudit("core.shutdown", "core", "peer="+who); err != nil {
		return nil, service.Err(ctx, codes.Internal, "core.svc.shutdown_audit", i18n.A("err", err.Error()))
	}
	s.c.mu.Lock()
	cancel := s.c.cancelServe
	s.c.mu.Unlock()
	if cancel != nil {
		cancel() // Serve hace GracefulStop: esta respuesta sale antes de que cierre
	}
	return &v1.ShutdownResponse{}, nil
}
