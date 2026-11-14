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

// obs anota lo que Patrol le hace al driver: aperturas, cierres y la credencial del shell que le entrega.
type obs struct {
	opens, closes int
	users, pws    []string
	pwSecrets     []*secret.Secret
	openErr       func(n int) error
	detectErr     error
}

type obsDrv struct {
	platform.Driver
	o *obs
}

func (d obsDrv) SetLogin(user string, pw *secret.Secret) {
	d.o.users, d.o.pws = append(d.o.users, user), append(d.o.pws, string(pw.Bytes()))
	d.o.pwSecrets = append(d.o.pwSecrets, pw)
}

func (d obsDrv) Open(ctx context.Context, r io.Reader, w io.Writer, en *secret.Secret) error {
	d.o.opens++
	if d.o.openErr != nil {
		if err := d.o.openErr(d.o.opens); err != nil {
			en.Destroy()
			return err
		}
	}
	return d.Driver.Open(ctx, r, w, en)
}

func (d obsDrv) Detect(ctx context.Context) (string, error) {
	if d.o.detectErr != nil {
		return "", d.o.detectErr
	}
	return d.Driver.Detect(ctx)
}

func (d obsDrv) Close() { d.o.closes++; d.Driver.Close() }

func runObs(t *testing.T, o *obs, verified bool, users map[string]string, fbUser, fbPw string) (*env, DeviceResult) {
	t.Helper()
	e := newEnv(t, simulator.Config{Users: users})
	e.trust(t)
	fb, _ := e.d.Vault.Put(vault.Credential{Username: fbUser, Password: secret.New([]byte(fbPw)), Enable: secret.New([]byte("MARKER-EN"))})
	e.spec.Overrides = []Override{{DeviceID: "sw1", FallbackCredentialID: fb}}
	e.d.NewDriver = func() platform.Driver { return obsDrv{Driver: iosxe.New(), o: o} }
	if verified {
		e.d.PrimaryVerified = map[string]bool{hostport(e.spec.Targets[0]): true}
	}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	return e, RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
}

// El respaldo solo se prueba tras un rechazo de credencial (ErrAuth, ErrLoginFailed), no con cualquier error.
func TestRespaldoSoloConRechazoDeCredencial(t *testing.T) {
	o := &obs{openErr: func(int) error { return platform.ErrFirstLogin }}
	if _, res := runObs(t, o, true, nil, "admin", "MARKER-PW"); res.State != "failed" || o.opens != 1 {
		t.Fatalf("%+v, opens %d", res, o.opens)
	}
}

// El login del shell del respaldo usa la clave del respaldo (no la de la credencial principal), y la copia se destruye al terminar.
func TestLoginDelShellDelRespaldoUsaSuClave(t *testing.T) {
	o := &obs{openErr: func(n int) error {
		if n == 1 {
			return platform.ErrLoginFailed
		}
		return nil
	}}
	_, res := runObs(t, o, true, map[string]string{"backup": "fb-pw"}, "backup", "fb-pw")
	if res.State != "completed" || len(o.pws) != 2 || o.pws[0] != "MARKER-PW" || o.pws[1] != "fb-pw" || o.users[1] != "backup" {
		t.Fatalf("%+v, users %q pws %q", res, o.users, o.pws)
	}
	for i, s := range o.pwSecrets {
		if !s.Empty() {
			t.Errorf("la clave del shell %d no se destruyó", i)
		}
	}
}

// Si Open o Detect fallan se cierra el driver (y la sesión); la clave del shell tampoco queda viva.
func TestFallaOpenODetectCierraElDriver(t *testing.T) {
	for name, o := range map[string]*obs{
		"open":   {openErr: func(int) error { return platform.ErrFirstLogin }},
		"detect": {detectErr: platform.ErrUnknownPlatform},
	} {
		_, res := runObs(t, o, false, nil, "admin", "MARKER-PW")
		if res.State != "failed" || o.closes < 1 {
			t.Fatalf("%s: %+v, cierres %d", name, res, o.closes)
		}
		for _, s := range o.pwSecrets {
			if !s.Empty() {
				t.Errorf("%s: la clave del shell sigue viva", name)
			}
		}
	}
}
