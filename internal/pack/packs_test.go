package pack_test

import (
	"os"
	"path/filepath"
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
	for _, d := range dirs {
		t.Run(filepath.Base(d), func(t *testing.T) {
			p, err := pack.Validate(d, "v0.2.0")
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Playbooks) == 0 {
				t.Fatal("un paquete sin playbooks no se publica")
			}
			if _, err := os.Stat(filepath.Join(d, "SIGNATURE")); err == nil {
				t.Fatal("la fuente no lleva SIGNATURE")
			}
			st, _, err := pack.Open(t.TempDir(), "v0.2.0", packtest.Keys(), base)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Install(packtest.Signed(t, d), false); err != nil {
				t.Fatal(err)
			}
		})
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
	if _, err := pack.Verify(a, "v0.2.0", nil); pack.Reason(err) != "editor.reserved" {
		t.Fatalf("sin firma, oom está reservado: %v", err)
	}
}
