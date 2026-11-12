package ingest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Regresión byte por byte: el texto en es de cada rechazo es el de antes del catálogo, y la metadata trae el campo.
func TestValidacionTextoEsYMetadata(t *testing.T) {
	ok := Sink{Dir: "x", Template: "t_{fecha}", MaxFiles: 1}
	for _, tc := range []struct {
		name  string
		err   error
		es    string
		en    string
		field string
		meta  map[string]string
	}{
		{"tasa origen", Limits{PerSource: 20000}.Validate(), "la tasa por origen debe estar entre 1 y 10000 (0 = default), no 20000", "the per-source rate must be between 1 and 10000 (0 = default), not 20000", "rate_per_source", map[string]string{"min": "1", "max": "10000"}},
		{"rafaga origen", Limits{PerSourceBurst: -1}.Validate(), "la ráfaga por origen debe estar entre 1 y 1000000 (0 = default), no -1", "", "burst_per_source", map[string]string{"min": "1", "max": "1000000"}},
		{"tasa global", Limits{Global: 100001}.Validate(), "la tasa global debe estar entre 1 y 100000 (0 = default), no 100001", "", "rate_global", nil},
		{"rafaga global", Limits{GlobalBurst: 1000001}.Validate(), "la ráfaga global debe estar entre 1 y 1000000 (0 = default), no 1000001", "", "burst_global", nil},
		{"cola", Limits{Queue: 10}.Validate(), "la cola debe estar entre 64 y 65536 (0 = default), no 10", "the queue size must be between 64 and 65536 (0 = default), not 10", "queue_size", map[string]string{"min": "64", "max": "65536"}},
		{"sin carpeta", Sink{Template: "t_{fecha}", MaxFiles: 1}.Validate(), "falta la carpeta de salida", "the output folder is missing", "dir", nil},
		{"plantilla vacía", ValidateTemplate(""), "la plantilla debe tener entre 1 y 64 caracteres", "the template must be between 1 and 64 characters long", "name_template", map[string]string{"template_problem": "len", "min": "1", "max": "64"}},
		{"plantilla sin fecha", ValidateTemplate("abc"), "la plantilla debe llevar {fecha} o {hora}", "the template must contain {date} or {time}", "name_template", map[string]string{"template_problem": "need"}},
		{"plantilla tokens", ValidateTemplate("{fecha}{x}"), "la plantilla solo admite los tokens {fecha}, {hora} y {origen}, bien cerrados", "the template only accepts the tokens {date}, {time} and {source}, properly closed", "name_template", map[string]string{"template_problem": "tokens"}},
		{"plantilla caracteres", ValidateTemplate("{fecha} x"), `la plantilla solo admite letras, dígitos, _ . - y los tokens; no ' '`, `the template only accepts letters, digits, _ . - and the tokens; not ' '`, "name_template", map[string]string{"template_problem": "chars"}},
		{"plantilla puntos", ValidateTemplate("{fecha}.."), `la plantilla no puede llevar ".."`, `the template cannot contain ".."`, "name_template", map[string]string{"template_problem": "dots"}},
		{"rotate mb", Sink{Dir: "x", Template: "t_{fecha}", MaxFiles: 1, RotateBytes: 1}.Validate(), "el tamaño de rotación debe estar entre 1 y 1024 MB", "the rotation size must be between 1 and 1024 MB", "rotate_mb", map[string]string{"min": "1", "max": "1024"}},
		{"rotate min", Sink{Dir: "x", Template: "t_{fecha}", MaxFiles: 1, RotateEvery: time.Second}.Validate(), "la rotación por tiempo debe estar entre 1 minuto y 7 días", "the time-based rotation must be between 1 minute and 7 days", "rotate_minutes", map[string]string{"min": "1", "max": "10080"}},
		{"max files", Sink{Dir: "x", Template: "t_{fecha}"}.Validate(), "el máximo de archivos debe estar entre 1 y 1000", "the maximum number of files must be between 1 and 1000", "max_files", map[string]string{"min": "1", "max": "1000"}},
		{"formato", Sink{Dir: ok.Dir, Template: ok.Template, MaxFiles: 1, Format: "xml"}.Validate(), `formato "xml" no soportado (texto, crudo o jsonl)`, `format "xml" is not supported (texto, crudo or jsonl)`, "format", map[string]string{"value": "xml"}},
	} {
		var c i18n.Coded
		if !errors.As(tc.err, &c) {
			t.Errorf("%s: sin código: %v", tc.name, tc.err)
			continue
		}
		if tc.err.Error() != tc.es {
			t.Errorf("%s: es = %q, quiero %q", tc.name, tc.err.Error(), tc.es)
		}
		if tc.en != "" && c.Localize(i18n.En) != tc.en {
			t.Errorf("%s: en = %q, quiero %q", tc.name, c.Localize(i18n.En), tc.en)
		}
		m := c.Metadata()
		if c.Reason() != "ingest.invalid" || m["field"] != tc.field {
			t.Errorf("%s: reason %q metadata %v", tc.name, c.Reason(), m)
		}
		for k, v := range tc.meta {
			if m[k] != v {
				t.Errorf("%s: metadata[%s] = %q, quiero %q (%v)", tc.name, k, m[k], v, m)
			}
		}
	}
}

// Los tokens en inglés valen igual que los de español, en la validación y en el nombre.
func TestSinonimosDePlantilla(t *testing.T) {
	for _, tpl := range []string{"x_{date}", "x_{time}", "x_{date}_{time}_{source}", "x_{fecha}_{time}"} {
		if err := ValidateTemplate(tpl); err != nil {
			t.Errorf("%s debe ser válida: %v", tpl, err)
		}
	}
	if ValidateTemplate("x_{source}") == nil {
		t.Error("{source} solo no basta: falta fecha u hora")
	}
	now := time.Date(2026, 11, 12, 10, 20, 30, 0, time.UTC)
	for tpl, want := range map[string]string{"s_{date}_{time}.log": "s_20261112_102030.log", "s_{fecha}_{hora}.log": "s_20261112_102030.log"} {
		dir := t.TempDir()
		w, err := NewWriter(Sink{Dir: dir, Template: tpl[:len(tpl)-4], MaxFiles: 5}, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.create("", now); err != nil {
			t.Fatal(err)
		}
		w.Close()
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("%s: no creó %s: %v", tpl, want, err)
		}
	}
}

// La retención reconoce los archivos de la misma plantilla escrita con tokens en español o en inglés.
func TestRetencionConSinonimos(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for i, name := range []string{"s_20261101_000000.log", "s_20261102_000000.log", "s_20261103_000000.log"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, base.Add(time.Duration(i)*time.Hour), base.Add(time.Duration(i)*time.Hour))
	}
	w, err := NewWriter(Sink{Dir: dir, Template: "s_{date}_{time}", MaxFiles: 2}, func() time.Time { return base.Add(48 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.create("", base.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Fatalf("con max_files=2 deben quedar 2 archivos, hay %d", len(ents))
	}
}

// La retención de t_{date} no toca archivos de otra plantilla ni de otro formato de fecha.
func TestRetencionNoBorraArchivosAjenos(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	ajenos := []string{"x_20261101.log", "t_20261101_000000.log"}
	for _, name := range append(ajenos, "t_20261101.log", "t_20261102.log") {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, base.Add(-72*time.Hour), base.Add(-72*time.Hour))
	}
	w, err := NewWriter(Sink{Dir: dir, Template: "t_{date}", MaxFiles: 1}, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.create("", base); err != nil {
		t.Fatal(err)
	}
	w.Close()
	for _, name := range ajenos {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("borró %s, que no es de la plantilla: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "t_20261101.log")); err == nil {
		t.Error("debía borrar t_20261101.log (es de la plantilla y excede max_files)")
	}
}
