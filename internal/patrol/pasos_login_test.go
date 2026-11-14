package patrol

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// Los errores de prompt del driver caen en «prompt» (también envueltos) y no se reintentan como fallas de red; ErrLoginFailed es «auth».
func TestStepClasificaErroresDelDriver(t *testing.T) {
	for want, errs := range map[string][]error{
		"prompt": {platform.ErrConfigPrompt, platform.ErrDesync, platform.ErrConfirmPrompt},
		"auth":   {platform.ErrLoginFailed},
	} {
		for _, e := range errs {
			for _, err := range []error{e, fmt.Errorf("envuelto: %w", e)} {
				if got := step(err); got != want {
					t.Errorf("step(%v) = %q, quería %q", err, got, want)
				}
			}
		}
	}
}

// loginRechazo es el driver real cuya primera Open falla con ErrLoginFailed (el shell de AireOS rechazó la credencial).
type loginRechazo struct {
	platform.Driver
	opens *int
}

func (l loginRechazo) Open(ctx context.Context, r io.Reader, w io.Writer, en *secret.Secret) error {
	*l.opens++
	if *l.opens == 1 {
		en.Destroy()
		return platform.ErrLoginFailed
	}
	return l.Driver.Open(ctx, r, w, en)
}

// Un rechazo del shell (ErrLoginFailed) prueba la credencial de respaldo igual que ErrAuth, solo si la principal estaba verificada.
func TestRechazoDelShellProbarespaldo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	good := e.spec.DefaultCredentialID
	fb, _ := e.d.Vault.Put(vault.Credential{Username: "admin", Password: secret.New([]byte("MARKER-PW")), Enable: secret.New([]byte("MARKER-EN"))})
	e.spec.Overrides = []Override{{DeviceID: "sw1", FallbackCredentialID: fb}}
	_ = good
	opens := 0
	e.d.NewDriver = func() platform.Driver { return loginRechazo{Driver: iosxe.New(), opens: &opens} }
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "failed" || opens != 1 {
		t.Fatalf("sin principal verificada: %+v, opens %d", res, opens)
	}
	opens = 0
	e.d.PrimaryVerified = map[string]bool{hostport(e.spec.Targets[0]): true}
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "completed" || opens != 2 {
		t.Fatalf("con principal verificada: %+v, opens %d", res, opens)
	}
}

// Con un error de prompt del driver no hay reintentos de conexión.
func TestErrorDePromptNoSeReintenta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	n := 0
	e.d.NewDriver = func() platform.Driver {
		n++
		return errOpen{Driver: iosxe.New(), err: fmt.Errorf("x: %w", platform.ErrConfigPrompt)}
	}
	e.d.RetryBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "failed" || n != 1 {
		t.Fatalf("%+v, intentos %d", res, n)
	}
}

type errOpen struct {
	platform.Driver
	err error
}

func (o errOpen) Open(_ context.Context, _ io.Reader, _ io.Writer, en *secret.Secret) error {
	en.Destroy()
	return o.err
}
