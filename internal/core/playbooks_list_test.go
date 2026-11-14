package core

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// coreWith es un Core con solo el catálogo de playbooks dado.
func coreWith(pbs []playbook.Playbook) *Core {
	c := &Core{}
	c.pbs.Store(&pbs)
	return c
}

func TestListPlaybooks(t *testing.T) {
	cmd := func(s string) playbook.Command { return playbook.Command{Text: s} }
	s := &patrolSvc{c: coreWith([]playbook.Playbook{
		{ID: "ios-xe/zeta", Platform: "ios-xe", Name: "Z", Commands: []playbook.Command{cmd("show a"), cmd("show b")}},
		{ID: "nx-os/mid", Platform: "nx-os", Name: "M", Commands: []playbook.Command{cmd("show c")}},
		{ID: "ios-xe/alfa", Platform: "ios-xe", Name: "A", Commands: []playbook.Command{cmd("show d")}},
	})}
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

	// Con oom/ios instalado, un IOS clásico ve ios/alfa y ya no el ios-xe/alfa repetido; ios-xe/zeta sigue.
	pbs := append(*s.c.pbs.Load(), playbook.Playbook{ID: "ios/alfa", Platform: "ios", Name: "A (IOS)"})
	s.c.pbs.Store(&pbs)
	ios, _ := s.ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{Platform: "ios"})
	if got := ids(ios); !reflect.DeepEqual(got, []string{"ios-xe/zeta", "ios/alfa"}) {
		t.Fatalf("ios = %v", got)
	}
}

// Con el catálogo real embebido: ids con la forma que acepta CreateJob y comandos presentes.
func TestListPlaybooksCatalogoReal(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
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
	c := &Core{p: Paths{Config: config, Data: t.TempDir()}, o: Options{CoreVersion: "dev"}}
	if err := c.openPacks(); err != nil {
		t.Fatal(err)
	}
	s := &patrolSvc{c: c}
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

// Un equipo ios clásico lista los playbooks de ios-xe, sin los comandos que solo corren en ios-xe (dir bootflash:).
func TestListPlaybooksIOSListaLosDeIOSXE(t *testing.T) {
	h := newHarness(t, nil)
	h.installIOSXE(t)
	xe, _ := h.patrol.ListPlaybooks(ctx(t), &v1.ListPlaybooksRequest{Platform: "ios-xe"})
	ios, err := h.patrol.ListPlaybooks(ctx(t), &v1.ListPlaybooksRequest{Platform: "ios"})
	if err != nil || len(ios.Playbooks) == 0 || len(ios.Playbooks) != len(xe.Playbooks) {
		t.Fatalf("ios lista %d y ios-xe %d: %v", len(ios.Playbooks), len(xe.Playbooks), err)
	}
	tiene := func(r *v1.ListPlaybooksResponse, id, cmd string) bool {
		for _, p := range r.Playbooks {
			if p.Id == id {
				return slices.Contains(p.Commands, cmd)
			}
		}
		t.Fatalf("%s no está", id)
		return false
	}
	if !tiene(xe, "ios-xe/flota", "dir bootflash:") || tiene(ios, "ios-xe/flota", "dir bootflash:") {
		t.Fatal("dir bootflash: debe verse en ios-xe y no en ios")
	}
}

// El nombre sale en el idioma del contexto: es (o sin idioma) es el de siempre; en usa name_en y cae al español si no lo hay.
func TestListPlaybooksNombreSegunIdioma(t *testing.T) {
	s := &patrolSvc{c: coreWith([]playbook.Playbook{
		{ID: "ios-xe/a", Platform: "ios-xe", Name: "Plataforma · CPU alta", NameEn: "Platform · High CPU", Commands: []playbook.Command{{Text: "show a"}}},
		{ID: "ios-xe/b", Platform: "ios-xe", Name: "Mío · Propio", Commands: []playbook.Command{{Text: "show b"}}},
	})}
	name := func(loc string, i int) string {
		ctx := context.Background()
		if loc != "" {
			ctx = i18n.WithLocale(ctx, loc)
		}
		r, err := s.ListPlaybooks(ctx, &v1.ListPlaybooksRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return r.Playbooks[i].Name
	}
	for loc, want := range map[string]string{"": "Plataforma · CPU alta", "es": "Plataforma · CPU alta", "en": "Platform · High CPU"} {
		if got := name(loc, 0); got != want {
			t.Errorf("%q: %q, quiero %q", loc, got, want)
		}
	}
	if got := name("en", 1); got != "Mío · Propio" {
		t.Errorf("sin name_en cae al español: %q", got)
	}
}

// Un ios-xe lista los playbooks de cat9k y sda (contenido sobre ios-xe); ios, wlc-9800 y nx-os no.
func TestListPlaybooksCat9kSDASoloParaIOSXE(t *testing.T) {
	cmd := []playbook.Command{{Text: "show clock"}}
	s := &patrolSvc{c: coreWith([]playbook.Playbook{
		{ID: "ios-xe/plat-salud", Platform: "ios-xe", Name: "A", Commands: cmd},
		{ID: "cat9k/plat-salud", Platform: "cat9k", Name: "B", Commands: cmd},
		{ID: "sda/lisp-sitios", Platform: "sda", Name: "C", Commands: cmd},
	})}
	for plat, want := range map[string][]string{
		"ios-xe":   {"cat9k/plat-salud", "ios-xe/plat-salud", "sda/lisp-sitios"},
		"ios":      {"ios-xe/plat-salud"},
		"wlc-9800": {"ios-xe/plat-salud"},
		"nx-os":    nil,
	} {
		r, err := s.ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{Platform: plat})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range r.Playbooks {
			got = append(got, p.Id)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s ve %v, quiero %v", plat, got, want)
		}
	}
}
