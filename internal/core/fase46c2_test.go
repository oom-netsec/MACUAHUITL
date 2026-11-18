package core

import (
	"fmt"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type lote46c2 struct{ state, dir string }

// siembra46c2 abre un núcleo con trabajos viejos (para la poda) cuya carpeta de salida es la dada.
func siembra46c2(t *testing.T, h *harness, filas map[string]lote46c2) *Core {
	t.Helper()
	viejo := ahora46d.Add(-30 * 24 * time.Hour)
	return reabre(t, h, func() time.Time { return ahora46d }, func(x func(string, ...any)) {
		for id, f := range filas {
			spec := fmt.Sprintf(`{"Name":"n","OutputDir":%q}`, f.dir)
			x(`INSERT INTO jobs(id,name,spec_json,state,created_at,history_json) VALUES(?,'n',?,?,?,'{}')`, id, spec, f.state, viejo.UTC().Format(time.RFC3339))
		}
	})
}

func existe46c2(p string) bool { _, err := os.Lstat(p); return err == nil }

// Quitar por id y podar borran la lote-* vacía de un created; el resto de casos no se toca (46c2).
func TestQuitarCreatedBorraSoloLaLoteVacia(t *testing.T) {
	for _, via := range []string{"id", "poda"} {
		t.Run(via, func(t *testing.T) {
			h := newHarness(t, nil)
			out := h.core.settings.Outputs()
			vacia := filepath.Join(out, "adhoc", "lote-vacia")
			conArchivo := filepath.Join(out, "adhoc", "lote-conarchivo")
			otroNombre := filepath.Join(out, "adhoc", "otra")
			fuera := filepath.Join(t.TempDir(), "lote-fuera")
			real := filepath.Join(out, "adhoc", "real-vacia")
			enlace := filepath.Join(out, "adhoc", "lote-enlace")
			terminal := filepath.Join(out, "adhoc", "lote-terminal")
			for _, d := range []string{vacia, conArchivo, otroNombre, fuera, real, terminal} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			os.WriteFile(filepath.Join(conArchivo, "ev.txt"), []byte("x"), 0o600)
			if err := os.Symlink(real, enlace); err != nil {
				t.Skip("sin symlinks:", err)
			}
			filas := map[string]lote46c2{"vacia": {"created", vacia}, "archivo": {"created", conArchivo}, "otro": {"created", otroNombre},
				"fuera": {"created", fuera}, "raiz": {"created", out}, "enlace": {"created", enlace}, "terminal": {"cancelled", terminal}}
			c := siembra46c2(t, h, filas)
			if via == "id" {
				ids := make([]string, 0, len(filas))
				for id := range filas {
					ids = append(ids, id)
				}
				if rem, _, err := c.removeJobs(ids, "manual"); err != nil || len(rem) != len(filas) {
					t.Fatalf("quitó %v %v", rem, err)
				}
			} else if n := c.pruneJobs(); n != len(filas) {
				t.Fatalf("podó %d", n)
			}
			if existe46c2(vacia) {
				t.Error("la lote-* vacía de un created debía borrarse")
			}
			for name, p := range map[string]string{"con archivo": conArchivo, "otro nombre": otroNombre, "fuera": fuera, "raíz": out,
				"enlace": enlace, "destino del enlace": real, "terminal": terminal} {
				if !existe46c2(p) {
					t.Errorf("%s: no debía borrarse", name)
				}
			}
		})
	}
}

// Un ArmJob fallido deja la fase ARM_FAILED con el código del error y sus argumentos; el trabajo sigue en created (46c2).
func TestArmJobFallidoDejaLaFaseArmFailed(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	for _, c := range []struct {
		nombre, reason, arg string
		excluir             bool
	}{
		{"sin equipos", "patrol.svc.no_devices_left", "", true},
		{"login", "patrol.svc.login_failed", "failed", false},
	} {
		cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: &v1.JobSpec{Name: c.nombre, Targets: []*v1.Target{h.target}, DefaultCredentialId: cred,
			CustomCommands: "show clock", OutputDir: h.out, WindowHours: 1}})
		if err != nil {
			t.Fatal(err)
		}
		req := &v1.ArmJobRequest{JobId: cj.JobId}
		if c.excluir {
			req.ExcludedDeviceIds = []string{h.target.Address}
		}
		if _, err := h.patrol.ArmJob(ctx(t), req); err == nil {
			t.Fatalf("%s: debía fallar", c.nombre)
		}
		s := h.summary(t, cj.JobId)
		ph := s.Phases[len(s.Phases)-1]
		if s.State != "created" || s.FinishedAt != nil || ph.Kind != v1.JobPhaseKind_JOB_PHASE_KIND_ARM_FAILED || ph.Reason != c.reason {
			t.Fatalf("%s: estado=%s finished=%v última fase=%+v", c.nombre, s.State, s.FinishedAt, ph)
		}
		if _, ok := ph.Args[c.arg]; c.arg != "" && !ok {
			t.Errorf("%s: sin arg %s: %v", c.nombre, c.arg, ph.Args)
		}
	}
}
