// Package sys concentra las llamadas al sistema de endurecimiento del núcleo y de apertura de archivos, por sistema:
// en Linux prctl, setrlimit, mlockall y la revisión de swap e hibernación (spec §10.3); en Windows WER, el working set,
// VirtualLock y la revisión de pagefile e hibernación (ADR 0012). Es el único paquete fuera de transport/diag/ipc que
// puede usar golang.org/x/sys/unix y golang.org/x/sys/windows.
//
// Lo común vive en harden.go y openregular.go; lo que cambia por sistema, en los archivos _linux.go y _windows.go.
package sys

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// SignalContext termina con SIGTERM o SIGINT (systemctl stop, Ctrl-C). En Windows Go entrega os.Interrupt con Ctrl-C y
// con el cierre de la consola, y syscall.SIGTERM existe aunque nadie lo envíe.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// hibernateWarnings decide el aviso de hibernación de Windows a partir de HibernateEnabled ya leído (o del error de
// leerlo). Es pura para probarla en Linux; solo la lectura del registro es de Windows.
func hibernateWarnings(enabled uint64, err error) []i18n.Text {
	if err != nil {
		return []i18n.Text{i18n.Tx("harden.hibernation_unknown", "cause", err.Error())}
	}
	if enabled == 1 {
		return []i18n.Text{i18n.Tx("harden.hibernation_win")}
	}
	return nil
}

// NoDriveLetter dice si p no empieza con «X:» (letra de unidad): \\?\C:\, \\.\, \??\ y las UNC (que abren SMB y filtran el hash
// NTLM) saltarían las listas de rutas porque ni Clean ni EvalSymlinks les quitan el prefijo. Pura: se prueba en cualquier sistema.
func NoDriveLetter(p string) bool {
	return len(p) < 2 || p[1] != ':' || !(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z')
}

// unsafeVolume dice si el volumen de una ruta (filepath.VolumeName) es algo distinto de una letra de unidad: UNC
// (\\host\share abre SMB, sale a la red fuera de EgressGuard y filtra el hash NTLM), \\?\ y \\.\ (dispositivos y pipes).
// Vacío (ruta relativa) y «X:» son lo único que pasa.
func unsafeVolume(vol string) bool { return vol != "" && len(vol) != 2 }

// pagefileWarnings decide el aviso del archivo de paginación a partir de PagingFiles (REG_MULTI_SZ) ya leído.
// Una lista vacía (o de cadenas vacías) significa que no hay pagefile. encrypted es NtfsEncryptPagingFile=1: sin aviso.
// BitLocker no se considera (leerlo pide admin).
func pagefileWarnings(files []string, encrypted bool, err error) []i18n.Text {
	if err != nil {
		return []i18n.Text{i18n.Tx("harden.pagefile_unknown", "cause", err.Error())}
	}
	var set []i18n.Text
	for _, f := range files {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		// «?:» es el marcador de Windows para «la unidad del sistema»; así se lee en claro.
		f = pagefilePath(f)
		if rest, ok := strings.CutPrefix(f, "?:"); ok {
			set = append(set, i18n.Tx("harden.pagefile_sysdrive", "path", rest))
		} else {
			set = append(set, i18n.Lit(f, f))
		}
	}
	if len(set) == 0 || encrypted {
		return nil
	}
	return []i18n.Text{i18n.Tx("harden.pagefile").With("files", i18n.Join(", ", set...))}
}

// pagefilePath deja solo la ruta de una entrada de PagingFiles, que puede traer tamaños («C:\pagefile.sys 0 0»).
func pagefilePath(f string) string {
	for i := 0; i+1 < len(f); i++ {
		if f[i] == ' ' && f[i+1] >= '0' && f[i+1] <= '9' {
			return strings.TrimSpace(f[:i])
		}
	}
	return f
}
