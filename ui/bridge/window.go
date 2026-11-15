package bridge

// Tamaño de la ventana (ui/main.go). Funciones y constantes, no métodos: Wails no las expone a la interfaz.
const (
	WindowWidth, WindowHeight       = 1280, 800 // preferido
	WindowMinWidth, WindowMinHeight = 960, 640
)

// InitialSize es el tamaño con el que abre la ventana: el preferido, sin pasar del 90 % del área de trabajo de la
// pantalla (en 1366×768 la barra de estado quedaba fuera) y nunca menos que el mínimo. Sin datos de pantalla (0), el preferido.
func InitialSize(workW, workH int) (int, int) {
	fit := func(pref, work, least int) int {
		if work <= 0 {
			return pref
		}
		return max(least, min(pref, work*9/10))
	}
	return fit(WindowWidth, workW, WindowMinWidth), fit(WindowHeight, workH, WindowMinHeight)
}
