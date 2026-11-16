package patrol

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// asaEnv es un ASA multicontexto simulado: entra por admin y tiene ctx1.
func asaEnv(t *testing.T, landsIn string) (*env, *simulator.Recorder) {
	t.Helper()
	rec := &simulator.Recorder{}
	e := newEnv(t, simulator.Config{Hostname: "asa", Transcripts: transcripts("asa-asav"), Contexts: []string{"admin", "ctx1"},
		ChangetoLandsIn: landsIn, Recorder: rec, Commands: map[string]string{"show clock": "10:00:00.000 UTC Mon Nov 3 2026\n"}})
	e.spec.CustomCommands = "show clock\n"
	e.trust(t)
	return e, rec
}

func runCtx(t *testing.T, e *env, target string) (DeviceResult, *Writer) {
	t.Helper()
	w, err := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tg := e.spec.Targets[0]
	tg.Context = target
	return RunDevice(context.Background(), e.d, "j", e.spec, w, 1, tg, func(Progress) {}), w
}

func auditText(t *testing.T, e *env) string {
	t.Helper()
	var b bytes.Buffer
	if err := e.d.Audit.Export(context.Background(), &b, time.Time{}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestChangetoExito(t *testing.T) {
	e, rec := asaEnv(t, "")
	res, w := runCtx(t, e, "ctx1")
	if res.State != "completed" || res.Context != "ctx1" || res.Hostname != "asa/ctx1" {
		t.Fatalf("res = %+v", res)
	}
	// Entra por admin: pasa al sistema para leer show context, va a ctx1 y al final vuelve a admin.
	want := []string{"!changeto system", "!changeto context ctx1", "!changeto context admin"}
	if got := rec.Lines(); !slices.Equal(got, want) {
		t.Fatalf("changeto = %q", got)
	}
	if len(w.Files()) == 0 || !strings.Contains(w.Files()[0], "asa_ctx1") {
		t.Fatalf("la evidencia no lleva el contexto: %v", w.Files())
	}
	a := auditText(t, e)
	for _, s := range []string{"patrol.changeto", "round=1", "context=ctx1", "context=system", "context=admin"} {
		if !strings.Contains(a, s) {
			t.Errorf("auditoría sin %q: %s", s, a)
		}
	}
	if n := strings.Count(a, "patrol.changeto"); n != 3 {
		t.Errorf("%d changeto auditados", n)
	}
}

func TestChangetoSistema(t *testing.T) {
	e, rec := asaEnv(t, "")
	res, _ := runCtx(t, e, "system")
	if res.State != "completed" || res.Hostname != "asa" || res.Context != "system" {
		t.Fatalf("res = %+v", res)
	}
	if got := rec.Lines(); !slices.Equal(got, []string{"!changeto system", "!changeto context admin"}) {
		t.Fatalf("changeto = %q", got)
	}
}

// El equipo aterriza en otro contexto: el destino falla y no se guarda evidencia.
func TestChangetoPromptNoCoincide(t *testing.T) {
	e, _ := asaEnv(t, "admin") // changeto system «aterriza» en admin
	res, w := runCtx(t, e, "ctx1")
	if res.State != "failed" || !strings.Contains(res.Detail, "changeto") {
		t.Fatalf("res = %+v", res)
	}
	if len(w.Files()) != 0 {
		t.Fatalf("hay evidencia de un contexto equivocado: %v", w.Files())
	}
}

// Un nombre que no está en show context no se manda.
func TestChangetoFueraDeLaListaBlanca(t *testing.T) {
	e, rec := asaEnv(t, "")
	res, w := runCtx(t, e, "ghost")
	if res.State != "failed" || !strings.Contains(res.Detail, "ghost") {
		t.Fatalf("res = %+v", res)
	}
	for _, l := range rec.Lines() {
		if strings.Contains(l, "ghost") {
			t.Fatalf("se mandó %q", l)
		}
	}
	if len(w.Files()) != 0 {
		t.Fatalf("evidencia: %v", w.Files())
	}
	// Aun así vuelve al contexto de entrada.
	if l := rec.Lines(); l[len(l)-1] != "!changeto context admin" {
		t.Fatalf("sin vuelta: %q", l)
	}
}

// failRun hace fallar un comando a mitad del bloque con un error que no es de sesión.
type failRun struct{ platform.Driver }

func (f failRun) Run(ctx context.Context, cmd string, to time.Duration) (platform.Output, error) {
	if cmd == "show clock" {
		return platform.Output{Command: cmd}, errors.New("boom")
	}
	return f.Driver.Run(ctx, cmd, to)
}
func (f failRun) Prompt() platform.Prompt { return f.Driver.(platform.ContextSwitcher).Prompt() }
func (f failRun) ChangeTo(ctx context.Context, t string, to time.Duration) error {
	return f.Driver.(platform.ContextSwitcher).ChangeTo(ctx, t, to)
}

func TestChangetoVueltaAunqueHayaError(t *testing.T) {
	e, rec := asaEnv(t, "")
	e.d.NewDriver = func() platform.Driver { return failRun{iosxe.New()} }
	res, _ := runCtx(t, e, "ctx1")
	if res.State != "failed" || !strings.Contains(res.Detail, "boom") {
		t.Fatalf("res = %+v", res)
	}
	if l := rec.Lines(); l[len(l)-1] != "!changeto context admin" {
		t.Fatalf("no volvió al contexto de entrada: %q", l)
	}
}

func TestChangetoValidaElDestino(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	for _, c := range []string{"ctx 1", "ctx1; reload", "-x", strings.Repeat("a", 33), "a/b"} {
		e.spec.Targets[0].Context = c
		if err := ValidateWith(e.spec, e.d.Playbooks, nil, nil); err == nil {
			t.Errorf("%q aceptado", c)
		}
	}
	for _, c := range []string{"", "system", "ctx1"} {
		e.spec.Targets[0].Context = c
		if err := ValidateWith(e.spec, e.d.Playbooks, nil, nil); err != nil {
			t.Errorf("%q: %v", c, err)
		}
	}
}

// Una plataforma que no es ASA no admite contexto: falla sin mandar changeto.
func TestChangetoSoloASA(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	res, w := runCtx(t, e, "ctx1")
	if res.State != "failed" || len(w.Files()) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestParseShowContext(t *testing.T) {
	b, err := os.ReadFile("../parse/asa/testdata/sys_show-context.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := parseShowContext(string(b)); !slices.Equal(got, []string{"admin", "ctx1", "ctx2"}) {
		t.Fatalf("got %q", got)
	}
}
