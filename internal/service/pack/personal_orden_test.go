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
	conflict := []byte("# de otro\n")
	called := false
	beforePublish = func() {
		called = true
		if n := nScripts(t, d2.DB()); n != 1 {
			t.Errorf("al publicar los playbooks los scripts debían estar confirmados: %d", n)
		}
		es, _ := os.ReadDir(pbDir)
		for _, e := range es {
			if !strings.HasSuffix(e.Name(), ".tmp") {
				t.Errorf("playbook visible antes de confirmar los scripts: %s", e.Name())
				continue
			}
			os.WriteFile(filepath.Join(pbDir, strings.TrimSuffix(e.Name(), ".tmp")), conflict, 0o600) // alguien lo crea justo ahora
		}
	}
	t.Cleanup(func() { beforePublish = nil })
	_, err = s2.Import(context.Background(), &v1.PackServiceImportRequest{Path: mp, Confirm: true})
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
