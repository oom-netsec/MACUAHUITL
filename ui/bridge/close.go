package bridge

import (
	"context"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// busyPlazo es lo que Busy espera al núcleo: si no responde, el cierre no se bloquea.
const busyPlazo = time.Second

// Aviso al cerrar la ventana (ui/main.go). Son funciones y no métodos para que Wails no las exponga a la interfaz.

// Busy dice si cerrar la ventana corta algo: ejecuciones con stream (diagnóstico, escuchas, servidores de Campo y
// Transferencias), cambios asistidos en curso (su watch termina con la ejecución), consolas serie y terminales SSH.
// Los trabajos de Patrol y los respaldos programados viven en el núcleo y no cuentan.
func Busy(b *Bridge) bool {
	b.mu.Lock()
	local := len(b.runs)+len(b.assists)+len(b.consoles)+len(b.terminals) > 0
	b.mu.Unlock()
	if local {
		return true
	}
	// Una ejecución asistida viva en el núcleo sin stream aquí (ventana reabierta, o stream caído) también se abandona si nadie vuelve.
	c, err := b.client()
	if err != nil {
		return false
	}
	// Sin callCtx: puede leer la preferencia de idioma (hasta 3 s) y aquí el idioma no hace falta.
	b.mu.Lock()
	base := b.ctx
	b.mu.Unlock()
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, busyPlazo)
	defer cancel()
	r, err := v1.NewAssistServiceClient(c).ListRuns(ctx, &v1.ListRunsRequest{ActiveOnly: true})
	return err == nil && len(r.GetRuns()) > 0
}

// CloseText es el texto del aviso en el idioma de la interfaz: título, mensaje, botón de cerrar y botón de quedarse.
type CloseText struct{ Title, Message, Quit, Stay string }

func CloseTextFor(b *Bridge) CloseText {
	if b.language() == "es" {
		return CloseText{
			Title:   "¿Cerrar MACUAHUITL?",
			Message: "Hay sesiones o tareas en curso (terminal, consola serie, diagnóstico, escuchas o un cambio asistido). Al cerrar se cortan. Un cambio asistido sigue esperando en el núcleo: si nadie vuelve en 30 minutos, se abandona sin aplicar la reversa; queda guardada en Reversas pendientes (Cambios). Los trabajos de Patrol y los respaldos programados siguen en el núcleo.",
			Quit:    "Cerrar igual",
			Stay:    "Cancelar",
		}
	}
	return CloseText{
		Title:   "Close MACUAHUITL?",
		Message: "Sessions or tasks are running (terminal, serial console, diagnostics, listeners or an assisted change). Closing stops them. An assisted change keeps waiting in the core: if nobody returns within 30 minutes, it is abandoned without rolling back; the rollback stays saved in Pending rollbacks (Changes). Patrol jobs and scheduled backups keep running in the core.",
		Quit:    "Close anyway",
		Stay:    "Cancel",
	}
}
