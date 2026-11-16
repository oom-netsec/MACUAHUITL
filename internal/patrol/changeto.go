package patrol

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
)

// changetoTimeout es la inactividad que se tolera en un changeto o en show context.
const changetoTimeout = 30 * time.Second

// ctxLineRe: línea de show context con un contexto; el nombre va tras un espacio o el «*» del contexto admin y
// la siguiente columna (Class) ya trae texto. Las líneas de continuación de Interfaces empiezan con muchos espacios.
var ctxLineRe = regexp.MustCompile(`^[ *]([A-Za-z0-9][A-Za-z0-9_-]{0,31}) +\S`)

// parseShowContext saca los nombres de contexto de la salida de show context (espacio del sistema).
// shortcut: parser mínimo hasta que internal/parse/asa (42c) traiga el de show context; entonces se integra y esto se borra.
func parseShowContext(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "Total active") {
			break
		}
		if m := ctxLineRe.FindStringSubmatch(l); m != nil && m[1] != "Context" {
			out = append(out, m[1])
		}
	}
	return out
}

// changeto es la única ruta que manda «changeto» a un equipo (ADR 0011): audita antes de mandarlo (sin rastro no
// se manda) y el driver verifica el prompt de llegada. to es "system" o un nombre de contexto ya validado.
func changeto(ctx context.Context, d Deps, jobID, hp string, round int, sw platform.ContextSwitcher, to string) error {
	from := sw.Prompt().Context
	if from == "" {
		from = "system"
	}
	if _, err := d.Audit.Append(context.WithoutCancel(ctx), audit.Entry{Actor: "patrol", Action: "patrol.changeto", Target: hp,
		Detail: fmt.Sprintf("job=%s round=%d context=%s from=%s", jobID, round, to, from)}); err != nil {
		return i18n.New("patrol.err.audit", i18n.A("error", err.Error()))
	}
	return windowEnded(ctx, sw.ChangeTo(ctx, to, changetoTimeout))
}

// enterContext lleva la sesión al destino del trabajo. Un contexto solo se manda si está en el show context de esta
// misma ronda (que solo existe en el sistema, así que antes se pasa al sistema); un nombre que no esté no se manda.
func enterContext(ctx context.Context, d Deps, jobID, hp string, round int, c *connected, target string) error {
	sw, ok := c.drv.(platform.ContextSwitcher)
	if !ok || c.platform != "asa" {
		return platform.ErrChangetoUnsupported
	}
	if target != "system" {
		if sw.Prompt().Context != "" {
			if err := changeto(ctx, d, jobID, hp, round, sw, "system"); err != nil {
				return err
			}
		}
		cctx, cancel := context.WithTimeout(ctx, maxCmd(changetoTimeout))
		out, err := c.drv.Run(cctx, "show context", changetoTimeout)
		cancel()
		if err = windowEnded(ctx, err); err != nil {
			if errors.Is(err, ErrWindowEnded) {
				return err
			}
			return i18n.Wrap("patrol.err.context_list", err, i18n.A("error", err.Error()))
		}
		if out.Invalid {
			return i18n.New("patrol.err.context_list", i18n.A("error", strings.TrimSpace(out.Text)))
		}
		found := false
		for _, n := range parseShowContext(out.Text) {
			found = found || n == target
		}
		if !found {
			return i18n.New("patrol.err.context_not_listed", i18n.A("context", target))
		}
	}
	return changeto(ctx, d, jobID, hp, round, sw, target)
}

// leaveContext vuelve al contexto de entrada (entry vacío = sistema), aunque el trabajo haya fallado o se haya cancelado.
func leaveContext(ctx context.Context, d Deps, jobID, hp string, round int, c *connected, entry string) {
	sw, ok := c.drv.(platform.ContextSwitcher)
	if !ok || c.drv.Err() != nil {
		return
	}
	if entry == "" {
		entry = "system"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	changeto(ctx, d, jobID, hp, round, sw, entry) // si falla, la sesión se cierra enseguida: no hay más que hacer
}
