package core

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

func TestListPlaybooks(t *testing.T) {
	cmd := func(s string) playbook.Command { return playbook.Command{Text: s} }
	s := &patrolSvc{c: &Core{pbs: []playbook.Playbook{
		{ID: "ios-xe/zeta", Platform: "ios-xe", Name: "Z", Commands: []playbook.Command{cmd("show a"), cmd("show b")}},
		{ID: "nx-os/mid", Platform: "nx-os", Name: "M", Commands: []playbook.Command{cmd("show c")}},
		{ID: "ios-xe/alfa", Platform: "ios-xe", Name: "A", Commands: []playbook.Command{cmd("show d")}},
	}}}
	ids := func(r *v1.ListPlaybooksResponse) []string {
		var out []string
		for _, p := range r.Playbooks {
			out = append(out, p.Id)
		}
		return out
	}

	all, err := s.ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ids(all), []string{"ios-xe/alfa", "ios-xe/zeta", "nx-os/mid"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ids = %v, quiero %v", got, want)
	}
	if z := all.Playbooks[1]; z.Platform != "ios-xe" || z.Name != "Z" || !reflect.DeepEqual(z.Commands, []string{"show a", "show b"}) {
		t.Fatalf("zeta = %+v", z)
	}

	nx, _ := s.ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{Platform: "nx-os"})
	if got := ids(nx); !reflect.DeepEqual(got, []string{"nx-os/mid"}) {
		t.Fatalf("filtro = %v", got)
	}
	none, _ := s.ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{Platform: "junos"})
	if len(none.Playbooks) != 0 {
		t.Fatalf("junos = %v", ids(none))
	}
}

// Con el catálogo real embebido: ids con la forma que acepta CreateJob y comandos presentes.
func TestListPlaybooksCatalogoReal(t *testing.T) {
	h := newHarness(t, nil)
	r, err := h.patrol.ListPlaybooks(ctx(t), &v1.ListPlaybooksRequest{Platform: "ios-xe"})
	if err != nil || len(r.Playbooks) == 0 {
		t.Fatalf("catálogo vacío: %v", err)
	}
	for _, p := range r.Playbooks {
		if !strings.HasPrefix(p.Id, "ios-xe/") || len(p.Commands) == 0 {
			t.Fatalf("playbook inválido: %+v", p)
		}
	}
}

// Un playbook del usuario con el mismo id que uno embebido lo reemplaza: la lista no lo duplica y lo que
// se ve es lo que corre (patrol toma el primero que coincide). Los pre van antes, como los corre patrol.
func TestLoadPlaybooksUserOverridesEmbedded(t *testing.T) {
	config := t.TempDir()
	dir := filepath.Join(config, "playbooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	yaml := "id: tac-baseline\nplatform: ios-xe\nname: TAC · Mi línea base\npre:\n  - terminal width 200\ncommands:\n  - cmd: show version\n"
	if err := os.WriteFile(filepath.Join(dir, "mia.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	pbs, err := loadPlaybooks(config)
	if err != nil {
		t.Fatal(err)
	}
	s := &patrolSvc{c: &Core{pbs: pbs}}
	r, _ := s.ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{})
	var got []*v1.PlaybookInfo
	for _, p := range r.Playbooks {
		if p.Id == "ios-xe/tac-baseline" {
			got = append(got, p)
		}
	}
	if len(got) != 1 || got[0].Name != "TAC · Mi línea base" || !reflect.DeepEqual(got[0].Commands, []string{"terminal width 200", "show version"}) {
		t.Fatalf("tac-baseline = %+v", got)
	}
}
