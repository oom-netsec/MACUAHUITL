//go:build !windows

package diag

import (
	"os/exec"
	"syscall"
	"time"
)

// setupKill pone la herramienta en un grupo de procesos propio: al cancelar, la señal alcanza también a los hijos de la
// herramienta, que si no heredarían la tubería y la dejarían abierta.
func setupKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		time.AfterFunc(cmd.WaitDelay, func() { syscall.Kill(pgid, syscall.SIGKILL) })
		return syscall.Kill(pgid, syscall.SIGTERM)
	}
}
