package bridge

import "time"

// coreRelaunchAfter es lo mínimo entre dos lanzamientos: un núcleo que tarda en abrir su pipe no se lanza dos veces, y
// uno que se niega a arrancar (p. ej. elevado) no se relanza en cada tic.
const coreRelaunchAfter = 30 * time.Second

// CoreLauncher arranca el núcleo si no está corriendo (Windows, ADR 0012 (g)): no hay servicio, y la entrada Run de HKCU
// solo lo lanza al iniciar sesión. run lo consulta cuando el núcleo no responde, en su propia goroutine y sin el
// candado del puente: lanza y vuelve, y el tic siguiente vuelve a conectar. Solo lo usa run, así que no lleva candado.
type CoreLauncher struct {
	// Running es la sonda real del pipe (ipc.CoreRunning): un dial de gRPC no conecta y no sirve. Obligatoria, y debe
	// volver en menos de Interval (sin dial bloqueante): run la espera y no atiende nada más mientras tanto.
	Running func() (bool, error)
	Start   func() error     // obligatoria: lanzamiento separado de la app, con la ruta junto al exe (sys.StartDetached)
	Log     func(error)      // a dónde van los errores (nil: se descartan); el puente solo muestra «desconectado»
	Now     func() time.Time // nil: time.Now
	last    time.Time
}

// check devuelve si lanzó el núcleo (run reinicia entonces la espera de reconexión de gRPC).
func (l *CoreLauncher) check() (launched bool) {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	t := now()
	if !l.last.IsZero() && t.Sub(l.last) < coreRelaunchAfter {
		return false
	}
	up, err := l.Running()
	if err != nil { // sin saber si corre no se lanza: dos núcleos no (el segundo no podría abrir el pipe)
		l.last = t // el freno también vale para el registro: un error que no cambia no llena el log cada segundo
		l.log(err)
		return false
	}
	if up {
		return false
	}
	l.last = t
	if err := l.Start(); err != nil {
		l.log(err)
		return false
	}
	return true
}

func (l *CoreLauncher) log(err error) {
	if l.Log != nil {
		l.Log(err)
	}
}
