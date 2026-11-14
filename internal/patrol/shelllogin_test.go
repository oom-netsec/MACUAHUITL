package patrol

import (
	"context"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// shellDrv es el driver real que además anota la credencial que Patrol le entrega con SetLogin.
type shellDrv struct {
	platform.Driver
	user, pw string
	calls    int
}

func (s *shellDrv) SetLogin(user string, pw *secret.Secret) {
	s.calls++
	s.user, s.pw = user, string(pw.Bytes())
}

// Patrol entrega usuario y clave a los drivers con ShellLogin antes de Open; a los demás no les pasa nada.
func TestPatrolEntregaLaCredencialAlShellLogin(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	drv := &shellDrv{Driver: e.d.driver()}
	e.d.NewDriver = func() platform.Driver { return drv }
	if r := LoginTest(context.Background(), e.d, "j", e.spec, false, nil); r[0].FailedStep != "" {
		t.Fatalf("LoginTest = %+v", r[0])
	}
	if drv.calls != 1 || drv.user != "admin" || drv.pw != "MARKER-PW" {
		t.Fatalf("SetLogin: %d llamadas, user %q", drv.calls, drv.user)
	}
	e.d.NewDriver = func() platform.Driver { return e.d.driver() } // sin ShellLogin: sigue igual
}
