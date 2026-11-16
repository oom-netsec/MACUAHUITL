package sys

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Mínimo y máximo (blando) del working set. VirtualLock solo bloquea hasta casi el mínimo, y el valor por omisión es
// de unos 200 KiB: 64 MiB sobran para el material de llaves sin pedirle de más al sistema. Sin
// QUOTA_LIMITS_HARDWS_MAX_ENABLE el máximo no es un tope duro: el sistema puede recortarlo solo bajo presión de memoria.
const (
	workingSetMin = 64 << 20
	workingSetMax = 1 << 30
)

// Harden se llama al arrancar el núcleo. Devuelve avisos como textos con clave (la auditoría los guarda en inglés con
// Text.In(i18n.En); la consola sale en el idioma del proceso); nunca falla. En Windows no hay «bloquear todo» (ADR 0012,
// b): se sube el mínimo del working set y las llaves de la bóveda viven en buffers de memguard, que se bloquean solos con VirtualLock.
func Harden() []i18n.Text {
	warns := NoDump()
	if err := windows.SetProcessWorkingSetSizeEx(windows.CurrentProcess(), workingSetMin, workingSetMax, 0); err != nil {
		warns = append(warns, i18n.Tx("harden.workingset", "cause", err.Error()))
	}
	warns = append(warns, hibernateWarnings(readHibernate())...)
	return append(warns, pagefileWarnings(readPagingFiles())...)
}

// NoDump excluye al proceso de los reportes de error de Windows (sin volcados de WER) y apaga los diálogos de fallo; la
// UI usa solo esto. Devuelve avisos; nunca falla.
func NoDump() []i18n.Text {
	var warns []i18n.Text
	if err := werExclude(); err != nil {
		warns = append(warns, i18n.Tx("harden.wer", "cause", err.Error()))
	}
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
	return warns
}

// werExclude llama a WerAddExcludedApplication(exe, FALSE): por usuario (HKCU), sin admin. Devuelve un HRESULT.
func werExclude() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	proc := windows.NewLazySystemDLL("wer.dll").NewProc("WerAddExcludedApplication")
	if err := proc.Find(); err != nil {
		return err
	}
	if hr, _, _ := proc.Call(uintptr(unsafe.Pointer(p)), 0); hr != 0 {
		return fmt.Errorf("HRESULT 0x%08x", uint32(hr))
	}
	return nil
}

func readHibernate() (uint64, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Power`, registry.QUERY_VALUE)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("HibernateEnabled")
	if errors.Is(err, registry.ErrNotExist) {
		return 0, nil // sin el valor, Windows no tiene hibernación
	}
	return v, err
}

func readPagingFiles() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("PagingFiles")
	return v, err
}

// Privileged dice si el token del proceso está elevado (UAC); el núcleo se niega a arrancar así (ADR 0012, c).
func Privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
