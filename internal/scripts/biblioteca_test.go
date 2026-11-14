package scripts

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

// conPaquete es la biblioteca con el contenido del paquete oficial oom/ios-xe, como la ve un núcleo que lo instaló.
func conPaquete(t *testing.T) []Script {
	t.Helper()
	pbs, err := playbook.Load(os.DirFS("../../packs/ios-xe/playbooks"))
	if err != nil {
		t.Fatal(err)
	}
	lib, _, err := LibraryWith(playbooks.FS, []Contenido{{Playbooks: pbs}})
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func TestBibliotecaCargaYSusScriptsSonValidos(t *testing.T) {
	lib := conPaquete(t)
	if len(lib) < 60 {
		t.Fatalf("faltan scripts de la biblioteca: %d", len(lib))
	}
	ids, nombres := map[string]bool{}, map[string]bool{}
	var lectura, config int
	for _, s := range lib {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", s.ID, err)
		}
		if !strings.HasPrefix(s.ID, "lib-") || s.Origin != OrigenBiblioteca {
			t.Errorf("%s: id u origen de la biblioteca mal", s.ID)
		}
		if ids[s.ID] || nombres[s.Name] {
			t.Errorf("%s / %q repetido", s.ID, s.Name)
		}
		ids[s.ID], nombres[s.Name] = true, true
		if s.ReadOnly() {
			lectura++
		} else {
			config++
		}
	}
	// los de diagnóstico vienen de los playbooks (solo lectura); los de configuración, no
	if lectura < 50 || config < 10 {
		t.Errorf("lectura=%d configuración=%d", lectura, config)
	}
	// IDs estables: el de un playbook conocido y uno de configuración
	for _, id := range []string{"lib-l2-stp", "lib-cfg-vlan-acceso"} {
		if !ids[id] {
			t.Errorf("falta %s", id)
		}
	}
}

// Los scripts de diagnóstico siguen en sincronía con los playbooks porque se derivan de ellos al cargar.
func TestBibliotecaDiagnosticoCoincideConElPlaybook(t *testing.T) {
	lib := conPaquete(t)
	for _, s := range lib {
		if s.ID != "lib-l2-stp" {
			continue
		}
		if s.Tech != "l2" || s.Platform != "ios-xe" || !s.ReadOnly() || !strings.Contains(strings.Join(s.Commands, "\n"), "show spanning-tree summary") {
			t.Fatalf("lib-l2-stp = %+v", s)
		}
		return
	}
	t.Fatal("sin lib-l2-stp")
}

func pb(platform, id, name string) string {
	return "id: " + id + "\nplatform: " + platform + "\nname: " + name + "\ncommands:\n  - cmd: show clock\n"
}

func TestBibliotecaIDIncluyeLaPlataformaSalvoIosXe(t *testing.T) {
	fsys := fstest.MapFS{
		"cisco/ios-xe/foo.yaml": {Data: []byte(pb("ios-xe", "foo", "Foo"))},
		"cisco/nx-os/foo.yaml":  {Data: []byte(pb("nx-os", "foo", "Foo NX"))},
	}
	lib, err := Library(fsys)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, s := range lib {
		ids[s.ID] = true
	}
	if !ids["lib-foo"] || !ids["lib-nx-os-foo"] {
		t.Fatalf("ids = %v", ids)
	}
}

func TestBibliotecaRechazaIDOnombreRepetido(t *testing.T) {
	// mismo ID en dos carpetas de la misma plataforma
	_, err := Library(fstest.MapFS{
		"cisco/a/foo.yaml": {Data: []byte(pb("ios-xe", "foo", "Foo"))},
		"cisco/b/foo.yaml": {Data: []byte(pb("ios-xe", "foo", "Otro"))},
	})
	if err == nil || !strings.Contains(err.Error(), "repetido") {
		t.Fatalf("id repetido: %v", err)
	}
	// mismo nombre con IDs distintos
	_, err = Library(fstest.MapFS{
		"cisco/a/foo.yaml": {Data: []byte(pb("ios-xe", "foo", "Foo"))},
		"cisco/a/bar.yaml": {Data: []byte(pb("ios-xe", "bar", "FOO"))},
	})
	if err == nil || !strings.Contains(err.Error(), "repetido") {
		t.Fatalf("nombre repetido: %v", err)
	}
}

func TestTechDeUnPlaybook(t *testing.T) {
	casos := map[string]string{
		"l2-stp": "l2", "l2-etherchannel": "etherchannel", "l2-dot1x-mab": "seguridad", "l3-ospf": "l3",
		"svc-qos": "qos", "svc-ntp": "gestion", "svc-acl": "seguridad", "l1-poe": "diagnostico", "vpn-ipsec-ike": "seguridad",
		"tac-baseline": "diagnostico", "pre-post": "diagnostico",
	}
	for id, want := range casos {
		if got := techDe(id); got != want {
			t.Errorf("techDe(%q) = %q, quiero %q", id, got, want)
		}
	}
}

// Derived devuelve solo los scripts derivados de playbooks; los de configuración entran una sola vez, con la base,
// aunque haya varios paquetes (si se llamara LibraryWithEN por paquete saldrían duplicados).
func TestDerivedNoTraeConfiguracionYLaBibliotecaNoLaDuplica(t *testing.T) {
	pbs, err := playbook.Load(os.DirFS("../../packs/ios-xe/playbooks"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Derived(pbs) {
		if strings.HasPrefix(s.ID, "lib-cfg-") {
			t.Fatalf("Derived trajo un script de configuración: %s", s.ID)
		}
	}
	otro := []playbook.Playbook{{ID: "ios-xe/acme-a", Platform: "ios-xe", Name: "Acme · A", Commands: []playbook.Command{{Text: "show clock"}}}}
	lib, _, err := LibraryWith(playbooks.FS, []Contenido{{Playbooks: pbs}, {Playbooks: otro}})
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	for _, s := range lib {
		n[s.ID]++
	}
	if n["lib-cfg-ntp"] != 1 || n["lib-acme-a"] != 1 || n["lib-l2-stp"] != 1 {
		t.Fatalf("duplicados: cfg-ntp=%d acme-a=%d l2-stp=%d", n["lib-cfg-ntp"], n["lib-acme-a"], n["lib-l2-stp"])
	}
}

// Un script de biblioteca no tiene datos: los playbooks con params no se derivan.
func TestDerivedOmiteLosPlaybooksConDatos(t *testing.T) {
	pb := playbook.Playbook{ID: "wlc-9800/cli-x", Platform: "wlc-9800", Name: "Cliente · X",
		Params: []playbook.Param{{Name: "mac", Kind: "mac"}}, Commands: []playbook.Command{{Text: "show wireless client mac-address {mac} detail"}}}
	if d := Derived([]playbook.Playbook{pb}); len(d) != 0 {
		t.Fatalf("derivó %v", d)
	}
	if d := DerivedTexts([]playbook.Playbook{pb}); len(d) != 0 {
		t.Fatalf("textos %v", d)
	}
}

// Los playbooks cat9k y sda son contenido sobre ios-xe: su script derivado usa la plataforma de scripts ios-xe.
func TestDerivedCat9kSDAUsaIOSXE(t *testing.T) {
	for _, pl := range []string{"cat9k", "sda"} {
		pb := playbook.Playbook{ID: pl + "/plat-x", Platform: pl, Name: "X · Y", Commands: []playbook.Command{{Text: "show clock"}}}
		d := Derived([]playbook.Playbook{pb})
		if len(d) != 1 || d[0].Platform != "ios-xe" || d[0].ID != "lib-"+pl+"-plat-x" || d[0].Validate() != nil {
			t.Fatalf("%s: %+v", pl, d)
		}
	}
}
