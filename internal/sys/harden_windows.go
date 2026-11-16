package sys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Mínimo y máximo (blando) del working set. VirtualLock solo bloquea hasta casi el mínimo, y el valor por omisión
// alcanza para unas 40 páginas: memguard hace panic si VirtualLock falla. 64 MiB sobran para las llaves sin pedirle de
// más al sistema. Sin QUOTA_LIMITS_HARDWS_MAX_ENABLE el máximo no es un tope duro: el sistema puede recortarlo solo bajo
// presión de memoria.
const (
	workingSetMin = 64 << 20
	workingSetMax = 1 << 30
)

var (
	lockQuotaOnce sync.Once
	lockQuotaErr  error
)

// EnsureLockQuota sube el mínimo del working set, lo que VirtualLock necesita (una sola vez; el error queda guardado).
// internal/secret la llama en init(), así la tienen el núcleo, la UI y las pruebas antes del primer buffer de memguard.
func EnsureLockQuota() error {
	lockQuotaOnce.Do(func() {
		lockQuotaErr = windows.SetProcessWorkingSetSizeEx(windows.CurrentProcess(), workingSetMin, workingSetMax, 0)
	})
	return lockQuotaErr
}

// Harden se llama al arrancar el núcleo. Devuelve avisos como textos con clave (la auditoría los guarda en inglés con
// Text.In(i18n.En); la consola sale en el idioma del proceso). En Windows no hay «bloquear todo» (ADR 0012, b): las
// llaves de la bóveda viven en buffers de memguard, que se bloquean con VirtualLock. Si no se pudo subir el working
// set, memguard haría panic: eso es un error y el núcleo no arranca.
func Harden() ([]i18n.Text, error) {
	warns := NoDump()
	if err := EnsureLockQuota(); err != nil {
		return warns, i18n.New("harden.err.lockquota", i18n.A("cause", err.Error()))
	}
	warns = append(warns, hibernateWarnings(readHibernate())...)
	return append(warns, pagefileWarnings(readPagingFiles())...), nil
}

// NoDump excluye al proceso de los reportes de error de Windows (sin volcados de WER); la
// UI usa solo esto. Devuelve avisos; nunca falla.
func NoDump() []i18n.Text {
	var warns []i18n.Text
	if err := werExclude(); err != nil {
		warns = append(warns, i18n.Tx("harden.wer", "cause", err.Error()))
	}
	return warns
}

// werExclude llama a WerAddExcludedApplication(nombre del exe, FALSE): por usuario (HKCU), sin admin. Devuelve un HRESULT.
func werExclude() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(filepath.Base(exe)) // la API pide el nombre del ejecutable, no la ruta
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

// readHibernate lee HibernateEnabled y, si falta, HibernateEnabledDefault; si faltan los dos devuelve el error (el
// aviso es «no se pudo comprobar», nunca el silencio).
func readHibernate() (uint64, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Power`, registry.QUERY_VALUE)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("HibernateEnabled")
	if errors.Is(err, registry.ErrNotExist) {
		v, _, err = k.GetIntegerValue("HibernateEnabledDefault")
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

// Privileged dice si el token del proceso está elevado (UAC); el núcleo se niega a arrancar así (ADR 0012, c). Falla
// abierto hacia «elevado»: Token.IsElevated devuelve false si GetTokenInformation falla, y aquí cualquier error cuenta
// como elevado.
func Privileged() bool {
	var e struct{ TokenIsElevated uint32 }
	var n uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevation, (*byte)(unsafe.Pointer(&e)), uint32(unsafe.Sizeof(e)), &n)
	return err != nil || e.TokenIsElevated != 0
}
