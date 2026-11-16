package sys

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// WaitExit espera a que el proceso pid termine, hasta timeout. Nil si terminó o ya no existía; ErrWaitTimeout si
// sigue vivo al vencer el plazo. Sirve para procesos que no son hijos nuestros (el núcleo que se apaga).
func WaitExit(pid int, timeout time.Duration) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil { // kernel sin pidfd (ENOSYS) o sin permiso: se sondea
		return waitExitPoll(pid, timeout)
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(timeout)
	for {
		ms := int(time.Until(deadline).Milliseconds()) + 1
		if ms <= 0 {
			return ErrWaitTimeout
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		switch {
		case err == unix.EINTR:
		case err != nil:
			return err
		case n > 0:
			return nil
		}
	}
}

// waitExitPoll es el respaldo sin pidfd: kill(pid, 0) cada 20 ms.
// shortcut: un zombi sin reapar cuenta como vivo y un pid reutilizado también; el núcleo lo reapa su padre, y el
// plazo acota el resto.
func waitExitPoll(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrWaitTimeout
		}
		time.Sleep(20 * time.Millisecond)
	}
}
