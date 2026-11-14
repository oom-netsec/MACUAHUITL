// Package sys concentra las llamadas al sistema de endurecimiento del núcleo
// (prctl, setrlimit, mlockall) y la revisión de swap e hibernación (spec §10.3).
// Es el único paquete fuera de transport/diag/ipc que puede usar golang.org/x/sys/unix.
package sys

import (
	"bufio"
	"context"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"golang.org/x/sys/unix"
)

// Harden se llama al arrancar el núcleo. Devuelve avisos como textos con clave (la auditoría los guarda en inglés con
// Text.In(i18n.En); la consola sale en el idioma del proceso); nunca falla.
func Harden() []i18n.Text {
	warns := NoDump()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		warns = append(warns, i18n.Tx("harden.memlock_read", "cause", err.Error()))
	} else if w := mlockWarning(lim.Cur); !w.Empty() {
		warns = append(warns, w)
	} else if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		warns = append(warns, i18n.Tx("harden.mlockall", "cause", err.Error()))
	}
	warns = append(warns, swapWarnings("/proc/swaps")...)
	return append(warns, hibernationWarnings("/sys/power/resume")...)
}

// NoDump marca el proceso como no volcable y sin core dumps (lo que Harden hace primero); la UI usa solo esto, porque
// mlockall y los avisos de swap son del núcleo. Devuelve avisos; nunca falla.
func NoDump() []i18n.Text {
	var warns []i18n.Text
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		warns = append(warns, i18n.Tx("harden.nodump", "cause", err.Error()))
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		warns = append(warns, i18n.Tx("harden.nocore", "cause", err.Error()))
	}
	return warns
}

// mlockWarning: con un límite finito, MCL_FUTURE haría fallar al runtime de Go cuando crezca
// más allá del límite, así que solo se bloquea toda la memoria si el límite es ilimitado.
func mlockWarning(cur uint64) i18n.Text {
	if cur == unix.RLIM_INFINITY {
		return i18n.Text{}
	}
	return i18n.Tx("harden.memlock_limit", "bytes", strconv.FormatUint(cur, 10))
}

// swapWarnings avisa por cada swap que no esté en RAM (zram) ni sobre device-mapper (normalmente cifrado).
func swapWarnings(path string) []i18n.Text {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var warns []i18n.Text
	sc := bufio.NewScanner(f)
	sc.Scan() // encabezado
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		dev := fields[0]
		if strings.HasPrefix(dev, "/dev/zram") || strings.HasPrefix(dev, "/dev/mapper/") || strings.HasPrefix(dev, "/dev/dm-") {
			continue
		}
		warns = append(warns, i18n.Tx("harden.swap", "dev", dev))
	}
	return warns
}

// hibernationWarnings avisa si hay un dispositivo de reanudación configurado.
func hibernationWarnings(resumePath string) []i18n.Text {
	b, err := os.ReadFile(resumePath)
	if err != nil {
		return nil
	}
	if v := strings.TrimSpace(string(b)); v != "" && v != "0:0" {
		return []i18n.Text{i18n.Tx("harden.hibernation", "resume", v)}
	}
	return nil
}

func dumpable() int {
	v, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return v
}

func coreLimit() uint64 {
	var l unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_CORE, &l)
	return l.Cur
}

// SignalContext termina con SIGTERM o SIGINT (systemctl stop, Ctrl-C).
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), unix.SIGTERM, unix.SIGINT)
}
