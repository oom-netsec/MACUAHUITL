package diag

import (
	"errors"
	"os"
	"os/exec"
	"sync"
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
	return winLook(sysEnv, dir, func(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }, name)
}

func lastSep(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '\\' {
			return i
		}
	}
	return -1
}

func init() { winAdapters = realAdapters }

// realAdapters lista los adaptadores con GetAdaptersAddresses.
func realAdapters() []winAdapter {
	size := uint32(15000)
	for range 3 {
		buf := selfPtrBuf(int(size)) // IP_ADAPTER_ADDRESSES enlaza nodos dentro del mismo búfer: tiene que estar en el heap
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []winAdapter
		for ; aa != nil; aa = aa.Next {
			out = append(out, winAdapter{Friendly: windows.UTF16PtrToString(aa.FriendlyName), Name: windows.BytePtrToString(aa.AdapterName)})
		}
		return out
	}
	return nil
}

func childEnv(tool string) []string { return winChildEnv(sysEnv, tool) }

// sysEnv es os.Getenv salvo en las raíces del sistema, que salen de la API y no del entorno: un SystemRoot,
// ProgramFiles o ProgramFiles(x86) falsos (C:\evil) no cambian de dónde se resuelven ping.exe, nmap.exe ni dumpcap.exe.
// Si la API falla se devuelve "": la herramienta no se encuentra, nunca se cae al entorno.
func sysEnv(k string) string {
	var p string
	var err error
	switch k {
	case "SystemRoot":
		p, err = windows.GetSystemWindowsDirectory()
	case "ProgramFiles":
		p, err = windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	case "ProgramFiles(x86)":
		p, err = windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX86, 0)
	default:
		return os.Getenv(k)
	}
	if err != nil {
		return ""
	}
	return p
}

// confine mete el hijo en un Job Object con KILL_ON_JOB_CLOSE: cancelar o cerrar el job mata todo el árbol. El hijo
// arranca suspendido y se reanuda tras asignarlo al job, así que no hay ventana en la que un nieto escape.
func confine(cmd *exec.Cmd) (started func() error, done func(), err error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	// LazyProc.Call lleva //go:uintptrescapes: info escapa al heap y no se mueve con el stack mientras dura la llamada.
	// El wrapper SetInformationJobObject de x/sys recibe un uintptr sin esa marca, y el kernel leería una copia vieja del stack.
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if r, _, e := procSetInformationJobObject.Call(uintptr(job), uintptr(windows.JobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		windows.CloseHandle(job)
		return nil, nil, e
	}
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW}
	cmd.WaitDelay = 3 * time.Second
	// Las DLL que falten se buscan junto a la herramienta, no en el cwd heredado.
	if i := lastSep(cmd.Path); i > 0 {
		cmd.Dir = cmd.Path[:i]
	}
	// jobMu y jobClosed: la goroutine de diag puede llamar a Cancel justo cuando done cierra el job; con el número de handle
	// ya reutilizado, TerminateJobObject mataría un objeto ajeno.
	var jobMu sync.Mutex
	jobClosed := false
	cmd.Cancel = func() error {
		// El proceso aún puede no estar en el job (cancelación durante el arranque): Kill cubre ese caso.
		jobMu.Lock()
		if !jobClosed {
			terminateJob(job, 143) // como el 143 de Linux
		}
		jobMu.Unlock()
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
	return started, func() {
		jobMu.Lock()
		defer jobMu.Unlock()
		if !jobClosed {
			jobClosed = true
			windows.CloseHandle(job)
		}
	}, nil
}

var procSetInformationJobObject = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetInformationJobObject")

// terminateJob es la costura de las pruebas: comprueban que no se termina un job ya cerrado.
var terminateJob = windows.TerminateJobObject

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

// interrupt en Windows termina el Job Object (ping.exe no tiene una señal de salida ordenada): el resumen lo
// calcula el núcleo de las respuestas ya leídas.
func interrupt(cmd *exec.Cmd) { cmd.Cancel() }
