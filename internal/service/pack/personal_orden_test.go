package pack

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	dom "github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

func nScripts(t *testing.T, q querier) int {
	t.Helper()
	var n int
	if err := q.QueryRow(`SELECT count(*) FROM scripts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Los playbooks del import no son visibles hasta que los scripts ya están confirmados: antes quedan con nombre
// temporal. Si publicarlos falla, el import se deshace entero (ni scripts ni archivos a medias).
func TestImportPublicaPlaybooksTrasConfirmarScripts(t *testing.T) {
	s2, d2, mp, pbDir := prepImport(t)
	conflict := []byte("# de otro\n")
	called := false
	beforePublish = func() {
		called = true
		if n := nScripts(t, d2.DB()); n != 1 {
			t.Errorf("al publicar los playbooks los scripts debían estar confirmados: %d", n)
		}
		chocar(pbDir, conflict)
	}
	t.Cleanup(func() { beforePublish = nil })
	_, err := s2.Import(context.Background(), &v1.PackServiceImportRequest{Path: mp, Confirm: true, Sha256: sumOf(t, mp)})
	if err == nil || !called {
		t.Fatalf("debía fallar al publicar (hook %v): %v", called, err)
	}
	if n := nScripts(t, d2.DB()); n != 0 {
		t.Fatalf("quedaron %d scripts a medias", n)
	}
	es, _ := os.ReadDir(pbDir)
	if len(es) != 1 || es[0].Name() != "acme-mio.yaml" {
		t.Fatalf("la carpeta debía tener solo el archivo ajeno: %v", es)
	}
	if b, _ := os.ReadFile(filepath.Join(pbDir, "acme-mio.yaml")); string(b) != string(conflict) {
		t.Fatalf("se pisó el archivo ajeno: %q", b)
	}
}

// chocar crea el nombre final de cada temporal de dir, como si alguien lo hubiera creado justo antes de publicar.
func chocar(dir string, b []byte) {
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if n, ok := strings.CutSuffix(e.Name(), ".tmp"); ok {
			os.WriteFile(filepath.Join(dir, n[:strings.LastIndex(n, ".")]), b, 0o600)
		}
	}
}

// Si retirar los scripts tras un fallo de publicación también falla, queda auditado y el error lo dice.
func TestImportCompensacionFallidaSeAudita(t *testing.T) {
	s2, d2, mp, pbDir := prepImport(t)
	beforePublish = func() {
		chocar(pbDir, []byte("x"))
		d2.DB().Exec(`CREATE TRIGGER no_borrar BEFORE DELETE ON scripts BEGIN SELECT RAISE(ABORT, 'no'); END`)
	}
	t.Cleanup(func() { beforePublish = nil })
	_, err := s2.Import(context.Background(), &v1.PackServiceImportRequest{Path: mp, Confirm: true, Sha256: sumOf(t, mp)})
	if err == nil || !strings.Contains(err.Error(), "scripts") || !strings.Contains(d2.AuditText(), "pack.import.compensate_failed") {
		t.Fatalf("err=%v\n%s", err, d2.AuditText())
	}
}

// prepImport exporta un .mpack con un script y un playbook y devuelve un servicio vacío listo para importarlo.
func prepImport(t *testing.T) (*svc, *servicetest.Deps, string, string) {
	t.Helper()
	d1 := servicetest.New(t)
	st1, _, err := dom.Open(t.TempDir(), "v0.3.0", nil, dom.Base{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := put(d1.DB(), scripts.Script{ID: "s1", Name: "Uno", Tech: "l3", Platform: "ios", Commands: []string{"show clock"}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	s1 := &svc{d: d1, store: st1, cfg: Module{UserPlaybooks: func() []playbook.Playbook {
		return []playbook.Playbook{{ID: "ios-xe/mio", Platform: "ios-xe", Name: "Mio", Commands: []playbook.Command{{Text: "show clock", Timeout: time.Minute}}}}
	}}}
	mp := filepath.Join(t.TempDir(), "p.mpack")
	if _, err := s1.Export(context.Background(), &v1.PackServiceExportRequest{EditorName: "acme/mio", ScriptIds: []string{"s1"}, IncludePlaybooks: true, Path: mp}); err != nil {
		t.Fatal(err)
	}

	d2 := servicetest.New(t)
	st2, _, err := dom.Open(t.TempDir(), "v0.3.0", nil, dom.Base{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := t.TempDir()
	pbDir := filepath.Join(cfg, "playbooks")
	s2 := &svc{d: d2, store: st2, cfg: Module{ConfigDir: cfg}}
	return s2, d2, mp, pbDir
}

// sumOf es el sha256 del archivo, como lo daría la vista previa.
func sumOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return dom.SHA256(b)
}
