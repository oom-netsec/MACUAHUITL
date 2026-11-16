// Package core es el área de mctl para el ciclo de vida del núcleo (fase 43b): core stop lo apaga de forma ordenada.
package core

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

const help = `  core stop [--timeout 10s]
        (apaga el núcleo de forma ordenada y espera a que su proceso termine. Con trabajo en curso (ejecuciones asistidas, escuchas, capturas,
         servidores, terminales o trabajos de Patrol armados) se niega, lo lista y sale con 3 sin cortar nada. Si el núcleo no corre, avisa y sale con 0;
         core stop nunca lo arranca. Sale con 1 si vence el plazo)`

// Salidas de mctl core stop: 0 terminó o no corría, 3 se negó por trabajo vivo, 1 lo demás.
const exitBusy = 3

// Los puntos de apoyo de las pruebas.
var (
	Stderr    io.Writer = os.Stderr
	ServerPID           = ipc.ServerPID
	WaitExit            = sys.WaitExit
)

// stop apaga el núcleo. Nunca lo lanza: con el arranque bajo demanda de 43a4 (ADR 0012 g) mctl lo lanzará si no
// encuentra el pipe, y core stop quedará exento de eso.
func stop(c *cli.Env, args []string) error {
	var timeout time.Duration
	fs, err := cli.Flags("core stop", args, func(fs *flag.FlagSet) {
		fs.DurationVar(&timeout, "timeout", 10*time.Second, "plazo para que el núcleo termine")
	})
	if err != nil || fs.NArg() != 0 || timeout <= 0 {
		return errors.New("uso: mctl core stop [--timeout 10s]")
	}
	path, err := ipc.SocketPath()
	if err != nil {
		return err
	}
	pid, err := ServerPID(path)
	if errors.Is(err, ipc.ErrNotRunning) {
		return notRunning()
	}
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	_, err = v1.NewCoreServiceClient(c.Conn).Shutdown(ctx, &v1.ShutdownRequest{})
	switch status.Code(err) {
	case codes.OK:
	case codes.FailedPrecondition:
		return cli.ExitError{Code: exitBusy, Err: errors.New(status.Convert(err).Message())}
	case codes.Unavailable: // se fue entre el PID y la llamada
		return notRunning()
	case codes.DeadlineExceeded:
		return cli.Err("mctl.core.timeout", "pid", pid)
	default:
		return err
	}
	if err := WaitExit(pid, time.Until(deadline)); err != nil {
		if errors.Is(err, sys.ErrWaitTimeout) {
			return cli.Err("mctl.core.timeout", "pid", pid)
		}
		return err
	}
	fmt.Fprintln(c.Out, cli.T("mctl.core.stopped", "pid", pid))
	return nil
}

func notRunning() error {
	fmt.Fprintln(Stderr, cli.T("mctl.core.not_running"))
	return nil
}

// Area registra core stop.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "core stop", Run: stop}}}
}
