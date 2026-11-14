package bridge

// Aviso al cerrar la ventana (ui/main.go). Son funciones y no métodos para que Wails no las exponga a la interfaz.

// Busy dice si cerrar la ventana corta algo: ejecuciones con stream (diagnóstico, escuchas, servidores de Campo y
// Transferencias), cambios asistidos en curso (su watch termina con la ejecución), consolas serie y terminales SSH.
// Los trabajos de Patrol y los respaldos programados viven en el núcleo y no cuentan.
func Busy(b *Bridge) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.runs)+len(b.assists)+len(b.consoles)+len(b.terminals) > 0
}

// CloseText es el texto del aviso en el idioma de la interfaz: título, mensaje, botón de cerrar y botón de quedarse.
type CloseText struct{ Title, Message, Quit, Stay string }

func CloseTextFor(b *Bridge) CloseText {
	if b.language() == "es" {
		return CloseText{
			Title:   "¿Cerrar MACUAHUITL?",
			Message: "Hay sesiones o tareas en curso (terminal, consola serie, diagnóstico, escuchas o un cambio asistido). Al cerrar se cortan. Un cambio asistido sigue esperando en el núcleo: si nadie vuelve en 30 minutos, se abandona sin reversa. Los trabajos de Patrol y los respaldos programados siguen en el núcleo.",
			Quit:    "Cerrar igual",
			Stay:    "Cancelar",
		}
	}
	return CloseText{
		Title:   "Close MACUAHUITL?",
		Message: "Sessions or tasks are running (terminal, serial console, diagnostics, listeners or an assisted change). Closing stops them. An assisted change keeps waiting in the core: if nobody returns within 30 minutes, it is abandoned without rollback. Patrol jobs and scheduled backups keep running in the core.",
		Quit:    "Close anyway",
		Stay:    "Cancel",
	}
}
