package sys

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

// WaitExit espera a que el proceso pid termine, hasta timeout. Nil si terminó o ya no existía; ErrWaitTimeout si
// sigue vivo al vencer el plazo.
func WaitExit(pid int, timeout time.Duration) error {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) { // ya no existe ese pid
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	ms := max(timeout.Milliseconds(), 0) // un plazo negativo daría la vuelta en uint32 (~49 días)
	if ms >= int64(windows.INFINITE) {
		ms = int64(windows.INFINITE) - 1
	}
	switch ev, err := windows.WaitForSingleObject(h, uint32(ms)); {
	case err != nil:
		return err
	case ev == uint32(windows.WAIT_OBJECT_0):
		return nil
	default:
		return ErrWaitTimeout
	}
}
