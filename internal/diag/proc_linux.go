package diag

import (
	"os/exec"
	"syscall"
	"time"
)

// lookPath en Linux es el PATH del sistema, como siempre.
func lookPath(name string) (string, error) { return exec.LookPath(name) }

// childEnv es el entorno del hijo: PATH fijo y sin idioma.
func childEnv(tool string) []string { return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"} }

// confine pone al hijo en un grupo de procesos propio: al cancelar, la señal alcanza también a sus hijos, que si no
// heredarían la tubería y la dejarían abierta. started corre tras Start; done, tras Wait.
func confine(cmd *exec.Cmd) (started func() error, done func(), err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 3 * time.Second // tras SIGTERM, SIGKILL al grupo entero y cierre de tuberías
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		time.AfterFunc(cmd.WaitDelay, func() { syscall.Kill(pgid, syscall.SIGKILL) })
		return syscall.Kill(pgid, syscall.SIGTERM)
	}
	return func() error { return nil }, func() {}, nil
}

// interrupt pide a la herramienta que termine sola: SIGINT al grupo, como Ctrl+C (ping imprime su resumen).
func interrupt(cmd *exec.Cmd) { syscall.Kill(-cmd.Process.Pid, syscall.SIGINT) }
