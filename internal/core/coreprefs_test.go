package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Las preferencias del núcleo sobreviven al reinicio y rigen en coreDeps.Outputs sin reiniciar nada.
func TestPreferenciasDelNucleoPersistenYRigen(t *testing.T) {
	h := newHarness(t, nil)
	cl := v1.NewPrefsServiceClient(h.conn)
	nueva := carpetaSegura(t)
	if got := (coreDeps{h.core}).Outputs(); got != h.p.Outputs {
		t.Fatalf("de fábrica = %s", got)
	}
	r, err := cl.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: nueva, IngestDefaults: &v1.IngestDefaults{MaxFiles: 12, Format: "crudo"}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.State.OutputsDirDefault != h.p.Outputs {
		t.Fatalf("default = %s", r.State.OutputsDirDefault)
	}
	if got := (coreDeps{h.core}).Outputs(); got != nueva {
		t.Fatalf("vigente tras el cambio = %s", got)
	}
	h.restart(t)
	g, err := v1.NewPrefsServiceClient(h.conn).GetCorePrefs(context.Background(), &v1.GetCorePrefsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if g.State.OutputsDirEffective != nueva || g.State.Prefs.IngestDefaults.MaxFiles != 12 || g.State.Prefs.IngestDefaults.Format != "crudo" {
		t.Fatalf("tras reabrir = %+v", g.State)
	}
	if got := (coreDeps{h.core}).Outputs(); got != nueva {
		t.Fatalf("vigente tras reabrir = %s", got)
	}
	// la carpeta de datos del núcleo no se acepta
	_, err = v1.NewPrefsServiceClient(h.conn).SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: h.p.Data}})
	if err == nil {
		t.Fatal("la carpeta de datos debía rechazarse")
	}
	// tampoco la de ejecución (socket del núcleo)
	if _, err = v1.NewPrefsServiceClient(h.conn).SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: h.p.Runtime}}); err == nil || !strings.Contains(err.Error(), "reservada") {
		t.Fatalf("la carpeta de ejecución debía rechazarse como reservada: %v", err)
	}
}

// carpetaSegura crea una carpeta 0700 junto a las pruebas: /tmp es de todos y la validación no la acepta como ancestro.
func carpetaSegura(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp(".", "salidas-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	abs, err := filepath.Abs(d)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// Al arrancar se revalida la carpeta guardada: si dejó de ser 0700 rige la de fábrica, queda una entrada prefs.core
// con el motivo y GetCorePrefs lo avisa en note; los defaults de ingest guardados siguen.
func TestArranqueRevalidaLaCarpetaGuardada(t *testing.T) {
	h := newHarness(t, nil)
	nueva := carpetaSegura(t)
	if _, err := v1.NewPrefsServiceClient(h.conn).SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: nueva, IngestDefaults: &v1.IngestDefaults{MaxFiles: 12}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nueva, 0o755); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	if got := (coreDeps{h.core}).Outputs(); got != h.p.Outputs {
		t.Fatalf("debía regir la de fábrica (%s), rige %s", h.p.Outputs, got)
	}
	g, err := v1.NewPrefsServiceClient(h.conn).GetCorePrefs(context.Background(), &v1.GetCorePrefsRequest{})
	if err != nil || !strings.Contains(g.State.Note, "chmod 700 "+nueva) || g.State.OutputsDirEffective != h.p.Outputs || g.State.Prefs.OutputsDir != nueva || g.State.Prefs.IngestDefaults.MaxFiles != 12 {
		t.Fatalf("estado = %+v %v", g.State, err)
	}
	var b strings.Builder
	if err := h.core.log.Export(context.Background(), &b, time.Time{}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a := b.String(); !strings.Contains(a, `"action":"prefs.core"`) || !strings.Contains(a, "ya no es válida") {
		t.Fatalf("auditoría sin el motivo:\n%s", a)
	}
}
