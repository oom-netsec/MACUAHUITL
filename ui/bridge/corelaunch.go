package bridge

import "time"

// coreRelaunchAfter es lo mínimo entre dos lanzamientos: un núcleo que tarda en abrir su pipe no se lanza dos veces, y
// uno que se niega a arrancar (p. ej. elevado) no se relanza en cada tic.
const coreRelaunchAfter = 30 * time.Second

// CoreLauncher arranca el núcleo si no está corriendo (Windows, ADR 0012 (g)): no hay servicio, y la entrada Run de HKCU
// solo lo lanza al iniciar sesión. run lo consulta cuando el núcleo no responde, en su propia goroutine y sin el
// candado del puente: lanza y vuelve, y el tic siguiente vuelve a conectar. Solo lo usa run, así que no lleva candado.
type CoreLauncher struct {
	Running func() (bool, error) // sonda real del pipe (ipc.CoreRunning): un dial de gRPC no conecta y no sirve
	Start   func() error         // lanzamiento separado de la app, con la ruta junto al exe (sys.StartDetached)
	Log     func(error)          // a dónde van los errores: el puente solo muestra «desconectado»
	Now     func() time.Time     // nil: time.Now
	last    time.Time
}

func (l *CoreLauncher) check() {
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	t := now()
	if !l.last.IsZero() && t.Sub(l.last) < coreRelaunchAfter {
		return
	}
	up, err := l.Running()
	if err != nil { // sin saber si corre no se lanza: dos núcleos no (el segundo no podría abrir el pipe)
		l.Log(err)
		return
	}
	if up {
		return
	}
	l.last = t
	if err := l.Start(); err != nil {
		l.Log(err)
	}
}
