package pack_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

// Cada packs/* del repo pasa las reglas del instalador salvo la firma, y se instala firmado sin chocar con la base.
func TestPacksDelRepoSonValidos(t *testing.T) {
	dirs, _ := filepath.Glob(filepath.Join(packtest.RepoDir(), "packs", "*"))
	if len(dirs) == 0 {
		t.Fatal("no hay packs/*")
	}
	base := repoBase(t)
	for _, d := range dirs {
		t.Run(filepath.Base(d), func(t *testing.T) {
			p, err := pack.ValidateSource(d, "v0.4.0")
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Playbooks) == 0 {
				t.Fatal("un paquete sin playbooks no se publica")
			}
			if _, err := os.Stat(filepath.Join(d, "SIGNATURE")); err == nil {
				t.Fatal("la fuente no lleva SIGNATURE")
			}
			st, _, err := pack.Open(t.TempDir(), "v0.4.0", packtest.Keys(), base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Install(packtest.Signed(t, d), false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// repoBase es el contenido base embebido, contra el que se instala cada paquete.
func repoBase(t *testing.T) pack.Base {
	t.Helper()
	base := pack.Base{}
	pbs, err := playbook.Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pbs {
		base.PlaybookIDs = append(base.PlaybookIDs, p.ID)
	}
	lib, _, err := scripts.LibraryWithEN(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range lib {
		base.ScriptIDs, base.ScriptNames = append(base.ScriptIDs, s.ID), append(base.ScriptNames, s.Name)
	}
	return base
}

// oom/ios y oom/ios-xe conviven en el mismo almacén: playbooks distintos por plataforma y scripts por el prefijo ios-.
func TestIOSEIOSXEConviven(t *testing.T) {
	st, _, err := pack.Open(t.TempDir(), "v0.4.0", packtest.Keys(), repoBase(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ios-xe", "ios"} {
		if _, err := st.Install(packtest.Signed(t, filepath.Join(packtest.RepoDir(), "packs", n)), false); err != nil {
			t.Fatalf("oom/%s: %v", n, err)
		}
	}
	for _, n := range []string{"ios-xe", "ios"} {
		files, _ := filepath.Glob(filepath.Join(packtest.RepoDir(), "packs", n, "playbooks", "*.yaml"))
		p := st.Snapshot().Find("oom/" + n)
		if p == nil || len(files) == 0 || len(p.Playbooks) != len(files) {
			t.Fatalf("oom/%s: deben quedar instalados sus %d playbooks", n, len(files))
		}
		for _, pb := range p.Playbooks {
			if pb.Platform != n || !strings.HasPrefix(pb.ID, n+"/") {
				t.Errorf("oom/%s: %s es de %s", n, pb.ID, pb.Platform)
			}
		}
	}
}

func TestBuildEsDeterminista(t *testing.T) {
	d := filepath.Join(packtest.RepoDir(), "packs", "ios-xe")
	a, err := pack.Build(d)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pack.Build(d)
	if string(a) != string(b) {
		t.Fatal("Build no es determinista")
	}
	if _, err := pack.Verify(a, "v0.4.0", nil); pack.Reason(err) != "editor.reserved" {
		t.Fatalf("sin firma, oom está reservado: %v", err)
	}
}

// Quien agregue un segmento oficial (base, movido a oom/ios-xe o un packs/*) debe reservarlo en reservedSegments:
// si no, un tercero con ese editor podría publicar IDs que bloquearan al oficial.
func TestSegmentosOficialesEstanReservados(t *testing.T) {
	first := func(id string) string {
		if _, rest, ok := strings.Cut(id, "/"); ok {
			id = rest
		}
		id = strings.TrimPrefix(id, "lib-")
		seg, _, _ := strings.Cut(id, "-")
		return seg
	}
	check := func(origin, id string) {
		if seg := first(id); !pack.IsReservedSegment(seg) {
			t.Errorf("%s: el ID %q usa el segmento %q, que no está en reservedSegments (internal/pack/reserved.go)", origin, id, seg)
		}
	}
	pbs, err := playbook.Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pbs {
		check("base", p.ID)
	}
	lib, _, err := scripts.LibraryWithEN(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range lib {
		check("biblioteca base", s.ID)
	}
	for _, id := range playbooks.MovedToIOSXE {
		check("movido", id)
	}
	dirs, _ := filepath.Glob(filepath.Join(packtest.RepoDir(), "packs", "*"))
	for _, d := range dirs {
		p, err := pack.ValidateSource(d, "v0.4.0")
		if err != nil {
			t.Fatal(err)
		}
		for _, pb := range p.Playbooks {
			check("packs/"+filepath.Base(d), pb.ID)
		}
		for _, id := range p.ScriptIDs() {
			check("packs/"+filepath.Base(d), id)
		}
	}
	// La prueba muerde: un segmento que no existe no está reservado.
	if pack.IsReservedSegment("acme") {
		t.Fatal("acme no debe estar reservado")
	}
}
