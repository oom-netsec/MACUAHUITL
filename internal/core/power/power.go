// Package power evita que la laptop se suspenda durante trabajos armados y
// avisa al núcleo de suspensión, apagado y bloqueo de pantalla, vía logind en Linux y
// PowerRequest + ventana message-only en Windows (spec §10.4, ADR 0012 (d)).
package power

// Inhibitor toma los bloqueos de logind; release los suelta. missing lista los que no se pudieron tomar.
type Inhibitor interface {
	Take(why string) (release func(), missing []string)
}

// What son los bloqueos de spec §10.4: no suspender, no apagar, no reaccionar a la tapa ni a la inactividad.
var What = []string{"sleep", "idle", "handle-lid-switch", "shutdown"}

// Noop no bloquea nada y reporta todo como faltante (sin logind).
type Noop struct{}

func (Noop) Take(string) (func(), []string) { return func() {}, What }
