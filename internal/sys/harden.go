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

// unsafeVolume dice si el volumen de una ruta (filepath.VolumeName) es algo distinto de una letra de unidad: UNC
// (\\host\share abre SMB, sale a la red fuera de EgressGuard y filtra el hash NTLM), \\?\ y \\.\ (dispositivos y pipes).
// Vacío (ruta relativa) y «X:» son lo único que pasa.
func unsafeVolume(vol string) bool { return vol != "" && len(vol) != 2 }

// pagefileWarnings decide el aviso del archivo de paginación a partir de PagingFiles (REG_MULTI_SZ) ya leído.
// Una lista vacía (o de cadenas vacías) significa que no hay pagefile.
func pagefileWarnings(files []string, err error) []i18n.Text {
	if err != nil {
		return []i18n.Text{i18n.Tx("harden.pagefile_unknown", "cause", err.Error())}
	}
	var set []i18n.Text
	for _, f := range files {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		// «?:» es el marcador de Windows para «la unidad del sistema»; así se lee en claro.
		if rest, ok := strings.CutPrefix(f, "?:"); ok {
			set = append(set, i18n.Tx("harden.pagefile_sysdrive", "path", rest))
		} else {
			set = append(set, i18n.Lit(f, f))
		}
	}
	if len(set) == 0 {
		return nil
	}
	return []i18n.Text{i18n.Join("", i18n.Tx("harden.pagefile_head"), i18n.Join(", ", set...), i18n.Tx("harden.pagefile_tail"))}
}
