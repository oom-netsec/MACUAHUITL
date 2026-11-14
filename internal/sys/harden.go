// Package sys concentra las llamadas al sistema de endurecimiento del núcleo
// (prctl, setrlimit, mlockall) y la revisión de swap e hibernación (spec §10.3).
// Es el único paquete fuera de transport/diag/ipc que puede usar golang.org/x/sys/unix.
package sys

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/sys/unix"
)

// Harden se llama al arrancar el núcleo. Devuelve avisos para la auditoría (en inglés, como toda la auditoría); nunca falla.
func Harden() []string {
	warns := NoDump()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		warns = append(warns, "could not read RLIMIT_MEMLOCK: "+err.Error())
	} else if w := mlockWarning(lim.Cur); w != "" {
		warns = append(warns, w)
	} else if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		warns = append(warns, "mlockall failed; core memory could be swapped out: "+err.Error())
	}
	warns = append(warns, swapWarnings("/proc/swaps")...)
	return append(warns, hibernationWarnings("/sys/power/resume")...)
}

// NoDump marca el proceso como no volcable y sin core dumps (lo que Harden hace primero); la UI usa solo esto, porque
// mlockall y los avisos de swap son del núcleo. Devuelve avisos; nunca falla.
func NoDump() []string {
	var warns []string
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		warns = append(warns, "could not mark the process as non-dumpable: "+err.Error())
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		warns = append(warns, "could not disable core dumps: "+err.Error())
	}
	return warns
}

// mlockWarning: con un límite finito, MCL_FUTURE haría fallar al runtime de Go cuando crezca
// más allá del límite, así que solo se bloquea toda la memoria si el límite es ilimitado.
func mlockWarning(cur uint64) string {
	if cur == unix.RLIM_INFINITY {
		return ""
	}
	return fmt.Sprintf("RLIMIT_MEMLOCK is %d bytes; not all memory is locked. Set LimitMEMLOCK=infinity in the systemd unit", cur)
}

// swapWarnings avisa por cada swap que no esté en RAM (zram) ni sobre device-mapper (normalmente cifrado).
func swapWarnings(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var warns []string
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
		warns = append(warns, "swap possibly unencrypted: "+dev)
	}
	return warns
}

// hibernationWarnings avisa si hay un dispositivo de reanudación configurado.
func hibernationWarnings(resumePath string) []string {
	b, err := os.ReadFile(resumePath)
	if err != nil {
		return nil
	}
	if v := strings.TrimSpace(string(b)); v != "" && v != "0:0" {
		return []string{"hibernation configured (resume=" + v + "): memory could be written to disk"}
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
