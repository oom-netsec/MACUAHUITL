package diag

import (
	"errors"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func lookPath(name string) (string, error) {
	exe, _ := os.Executable()
	dir := ""
	if i := lastSep(exe); i > 0 {
		dir = exe[:i]
	}
	return winLook(os.Getenv, dir, func(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }, name)
}

func lastSep(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '\\' {
			return i
		}
	}
	return -1
}

func childEnv(tool string) []string { return winChildEnv(os.Getenv, tool) }

// confine mete el hijo en un Job Object con KILL_ON_JOB_CLOSE: cancelar o cerrar el job mata todo el árbol. El hijo
// arranca suspendido y se reanuda tras asignarlo al job, así que no hay ventana en la que un nieto escape.
func confine(cmd *exec.Cmd) (started func() error, done func(), err error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, nil, err
	}
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error {
		// El proceso aún puede no estar en el job (cancelación durante el arranque): Kill cubre ese caso.
		windows.TerminateJobObject(job, 1)
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	}
	started = func() error {
		h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
		if err == nil {
			err = windows.AssignProcessToJobObject(job, h)
			windows.CloseHandle(h)
		}
		if err == nil {
			err = resume(uint32(cmd.Process.Pid))
		}
		if err != nil {
			cmd.Process.Kill()
		}
		return err
	}
	return started, func() { windows.CloseHandle(job) }, nil
}

// resume reanuda los hilos del proceso recién creado (solo tiene el principal).
func resume(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	te := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	found := false
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, oerr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if oerr != nil {
			return oerr
		}
		_, rerr := windows.ResumeThread(th)
		windows.CloseHandle(th)
		if rerr != nil {
			return rerr
		}
		found = true
	}
	if !found {
		return errors.New("no se encontró el hilo del proceso hijo")
	}
	return nil
}
