package patrol

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/asa"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// changetoTimeout es la inactividad que se tolera en un changeto o en show context.
const changetoTimeout = 30 * time.Second

// changeto es la única ruta que manda «changeto» a un equipo (ADR 0011): audita antes de mandarlo (sin rastro no
// se manda) y el driver verifica el prompt de llegada. to es "system" o un nombre de contexto ya validado.
func changeto(ctx context.Context, d Deps, jobID, hp string, round int, sw platform.ContextSwitcher, to string) error {
	if _, err := playbook.ValidateValue("context", to); err != nil { // nunca se audita ni se manda lo que no es un nombre válido
		return i18n.New("platform.err.changeto_name", i18n.A("name", to))
	}
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
		list, _, _ := asa.ParseContexts(out.Text) // sin el encabezado de show context la lista sale vacía y no se manda nada
		if !slices.ContainsFunc(list, func(c asa.Context) bool { return c.Name == target }) {
			return i18n.New("patrol.err.context_not_listed", i18n.A("context", target))
		}
	}
	return changeto(ctx, d, jobID, hp, round, sw, target)
}

// leaveContext vuelve al contexto de entrada (entry vacío = sistema), aunque el trabajo haya fallado o se haya cancelado.
func leaveContext(ctx context.Context, d Deps, jobID, hp string, round int, c *connected, entry string) {
	sw, ok := c.drv.(platform.ContextSwitcher)
	// Con el trabajo cancelado o la ventana vencida no se manda nada más: la sesión se cierra igual.
	if !ok || c.platform != "asa" || ctx.Err() != nil || c.drv.Err() != nil {
		return
	}
	if entry == "" {
		entry = "system"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	changeto(ctx, d, jobID, hp, round, sw, entry) // si falla, la sesión se cierra enseguida: no hay más que hacer
}
