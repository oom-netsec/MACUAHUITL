package diag

import "os/exec"

// setupKill en Windows no hay grupos de procesos POSIX ni SIGTERM: Cancel mata al proceso de la herramienta (el
// comportamiento por omisión de exec.CommandContext). Los hijos que retengan la tubería los corta WaitDelay.
// shortcut: no mata el árbol de procesos (haría falta un Job Object); llega con la fase de herramientas de Windows.
func setupKill(*exec.Cmd) {}
