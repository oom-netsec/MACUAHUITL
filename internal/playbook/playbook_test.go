package playbook

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

func TestLoadEmbedded(t *testing.T) {
	pbs, err := Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	// Los de ios-xe que salieron del binario viven en el paquete oficial packs/ios-xe: se siguen verificando aquí.
	pack, err := Load(os.DirFS("../../packs/ios-xe/playbooks"))
	if err != nil {
		t.Fatal(err)
	}
	pbs = append(pbs, pack...)
	ids := map[string]Playbook{}
	for _, p := range pbs {
		ids[p.ID] = p
		for _, c := range append(append([]string(nil), p.Pre...), cmds(p)...) {
			if strings.HasPrefix(c, "terminal ") {
				continue
			}
			if err := CheckDenied(p.Platform, c); err != nil {
				t.Errorf("%s: %v", p.ID, err)
			}
		}
	}
	for _, id := range []string{"ios-xe/tac-baseline", "ios-xe/cpu-alta", "ios-xe/errores-interfaz", "ios-xe/upgrade-check", "ios-xe/pre-post", "ios-xe/topologia", "ios-xe/flota", "ios-xe/metricas"} {
		if _, ok := ids[id]; !ok {
			t.Errorf("missing %s (have %v)", id, keys(ids))
		}
	}
	tb := ids["ios-xe/tac-baseline"]
	for _, want := range []string{"show version", "show running-config", "show tech-support"} {
		if !contains(cmds(tb), want) {
			t.Errorf("tac-baseline lacks %q", want)
		}
	}
	for _, c := range tb.Commands {
		if c.Text == "show tech-support" && (c.Timeout != 600*time.Second || !c.MaySecrets) {
			t.Errorf("show tech-support = %+v", c)
		}
	}
}

func TestInvalidYAMLNamed(t *testing.T) {
	for name, body := range map[string]string{
		"cisco/ios-xe/malo.yaml":   "id: x\nplatform: ios-xe\nname: x\ncommands: [{cmd: show clock, timeout: nada}]\n",
		"cisco/ios-xe/extra.yaml":  "id: x\nplatform: ios-xe\nname: x\nbogus: 1\ncommands: [{cmd: show clock}]\n",
		"cisco/ios-xe/vacio.yaml":  "id: x\nplatform: ios-xe\nname: x\ncommands: []\n",
		"cisco/ios-xe/config.yaml": "id: x\nplatform: ios-xe\nname: x\ncommands: [{cmd: conf t}]\n",
	} {
		_, err := Load(fstest.MapFS{name: {Data: []byte(body)}})
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v, want error naming the file", name, err)
		}
	}
}

func TestDefaultTimeout(t *testing.T) {
	pbs, err := Load(fstest.MapFS{"cisco/ios-xe/a.yaml": {Data: []byte("id: a\nplatform: ios-xe\nname: a\ncommands: [{cmd: show clock}]\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if pbs[0].Commands[0].Timeout != 60*time.Second || pbs[0].ID != "ios-xe/a" {
		t.Fatalf("got %+v", pbs[0])
	}
}

func TestEphemeralID(t *testing.T) {
	text := "show clock\n\n! comentario\n  show version  \n"
	a, err := Ephemeral("ios-xe", text)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Ephemeral("ios-xe", text)
	if a.ID != b.ID || !strings.HasPrefix(a.ID, "custom-") || len(a.ID) != len("custom-")+12 {
		t.Fatalf("ids %q %q", a.ID, b.ID)
	}
	if got := cmds(a); len(got) != 2 || got[0] != "show clock" || got[1] != "show version" {
		t.Fatalf("commands = %v", got)
	}
	if _, err := Ephemeral("ios-xe", "show clock\nwr mem\n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied command accepted: %v", err)
	}
	if _, err := Ephemeral("ios-xe", "\n! nada\n"); err == nil {
		t.Fatal("empty ephemeral accepted")
	}
}

func TestDenyVariants(t *testing.T) {
	for _, c := range []string{"conf t", "  CONF T", "configure terminal", "config t", "wr", "write mem", "copy run start", "copy tftp: flash:",
		"reload in 5", "clear counters", "debug ip packet", "undebug all", "delete flash:x", "erase startup-config", "format flash:",
		"test cable-diagnostics tdr int gi1/0/1", "install add file x", "request platform software", "license boot level", "Reload",
		"show logging profile wireless filter mac aaaa.bbbb.cccc to-file bootflash:ra.txt", "show logging process wncd to-file bootflash:x",
		"sh log prof wir to-f flash:x", "SHOW LOG TO-FILE flash:x", "show tech to- flash:x", "show tech to-fi flash:x"} {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
	for _, c := range []string{"show running-config", "show clock", "show configuration", "dir flash:", "show debug", "show license",
		"show topology", "show spanning-tree top", "show spanning-tree topology detail"} {
		if err := CheckDenied("ios-xe", c); err != nil {
			t.Errorf("%q denied: %v", c, err)
		}
	}
}

func cmds(p Playbook) []string {
	var out []string
	for _, c := range p.Commands {
		out = append(out, c.Text)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func keys(m map[string]Playbook) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCampoPlatformsPorComando(t *testing.T) {
	yaml := func(extra string) fstest.MapFS {
		return fstest.MapFS{"cisco/ios-xe/x.yaml": {Data: []byte("id: x\nplatform: ios-xe\nname: X\ncommands:\n  - cmd: show version\n  - cmd: \"dir bootflash:\"\n" + extra + "\n")}}
	}
	pbs, err := Load(yaml("    platforms: [ios-xe]"))
	if err != nil {
		t.Fatal(err)
	}
	var libre, solo Command
	for _, c := range pbs[0].Commands {
		if c.Text == "show version" {
			libre = c
		} else {
			solo = c
		}
	}
	if !libre.Applies("ios") || !libre.Applies("ios-xe") {
		t.Errorf("sin platforms corre en todas: %+v", libre)
	}
	if solo.Applies("ios") || !solo.Applies("ios-xe") {
		t.Errorf("platforms [ios-xe]: ios no, ios-xe sí: %+v", solo)
	}
	_, err = Load(yaml("    platforms: [ios-xe, ios-raro]"))
	if err == nil || !strings.Contains(err.Error(), "x.yaml") || !strings.Contains(err.Error(), "ios-raro") {
		t.Fatalf("plataforma desconocida debía fallar con el nombre del archivo: %v", err)
	}
}

func TestCompatible(t *testing.T) {
	for _, c := range []struct {
		det, pb string
		ok      bool
	}{{"ios-xe", "ios-xe", true}, {"ios", "ios-xe", true}, {"ios", "ios", true}, {"ios-xe", "ios", false}, {"nx-os", "ios-xe", false}, {"wlc-9800", "ios-xe", true}, {"wlc-9800", "wlc-9800", true}, {"ios-xe", "wlc-9800", false}, {"ios", "wlc-9800", false}} {
		if got := Compatible(c.det, c.pb); got != c.ok {
			t.Errorf("Compatible(%q, %q) = %v", c.det, c.pb, got)
		}
	}
}

// En un IOS clásico, el ios/<x> de oom/ios tapa al ios-xe/<x> del mismo nombre; el resto de ios-xe sigue visible.
func TestVisibleIOSTapaIOSXE(t *testing.T) {
	pbs := []Playbook{{ID: "ios-xe/cpu-alta", Platform: "ios-xe"}, {ID: "ios/cpu-alta", Platform: "ios"},
		{ID: "ios-xe/pre-post", Platform: "ios-xe"}, {ID: "nx-os/cpu-alta", Platform: "nx-os"}}
	ids := func(ps []Playbook) (out []string) {
		for _, p := range ps {
			out = append(out, p.ID)
		}
		return out
	}
	if got := ids(Visible("ios", pbs)); !slices.Equal(got, []string{"ios/cpu-alta", "ios-xe/pre-post"}) {
		t.Errorf("ios: %v", got)
	}
	if got := ids(Visible("ios-xe", pbs)); !slices.Equal(got, []string{"ios-xe/cpu-alta", "ios-xe/pre-post"}) {
		t.Errorf("ios-xe: %v", got)
	}
}

// El gemelo no cruza paquetes de terceros: solo entre oficiales (o base) o del mismo paquete.
func TestGemeloNoCruzaPaquetes(t *testing.T) {
	pbs := []Playbook{
		{ID: "ios-xe/a", Platform: "ios-xe"}, {ID: "ios/a", Platform: "ios", Pack: "oom/ios"},
		{ID: "ios-xe/acme-b", Platform: "ios-xe", Pack: "acme/x"}, {ID: "ios/acme-b", Platform: "ios", Pack: "otro/y"},
		{ID: "ios-xe/acme-c", Platform: "ios-xe", Pack: "acme/x"}, {ID: "ios/acme-c", Platform: "ios", Pack: "acme/x"},
	}
	for _, c := range []struct{ id, plat, want string }{
		{"ios-xe/a", "ios", "ios/a"},           // base + oficial
		{"ios-xe/acme-b", "ios", ""},           // dos terceros distintos
		{"ios-xe/acme-c", "ios", "ios/acme-c"}, // mismo paquete
		{"ios/a", "ios-xe", "ios-xe/a"},
	} {
		got := ""
		if tw := Twin(pbs, c.id, c.plat); tw != nil {
			got = tw.ID
		}
		if got != c.want {
			t.Errorf("Twin(%s,%s)=%q quiero %q", c.id, c.plat, got, c.want)
		}
	}
	// El ID elegido ya no existe: solo vale un gemelo oficial.
	if tw := Twin(pbs, "ios-xe/borrado", "ios"); tw != nil {
		t.Errorf("sin gemelo debía ser nil: %v", tw)
	}
	pbs = append(pbs, Playbook{ID: "ios/borrado", Platform: "ios", Pack: "oom/ios"}, Playbook{ID: "ios/ajeno", Platform: "ios", Pack: "acme/x"})
	if tw := Twin(pbs, "ios-xe/borrado", "ios"); tw == nil || tw.ID != "ios/borrado" {
		t.Errorf("gemelo oficial de un ID faltante: %v", tw)
	}
	if tw := Twin(pbs, "ios-xe/ajeno", "ios"); tw != nil {
		t.Errorf("gemelo de tercero para un ID faltante: %v", tw)
	}
	// Visible: un gemelo de otro tercero no tapa.
	got := []string{}
	for _, p := range Visible("ios", pbs) {
		got = append(got, p.ID)
	}
	if slices.Contains(got, "ios-xe/a") || !slices.Contains(got, "ios-xe/acme-b") || slices.Contains(got, "ios-xe/acme-c") {
		t.Errorf("Visible: %v", got)
	}
}

// Un 9800 ve los suyos y los genéricos de ios-xe; un switch no ve los del 9800.
func TestVisibleWLC9800(t *testing.T) {
	pbs := []Playbook{{ID: "ios-xe/cpu-alta", Platform: "ios-xe"}, {ID: "wlc-9800/ap-resumen", Platform: "wlc-9800"}, {ID: "nx-os/x", Platform: "nx-os"}}
	n := func(det string) int { return len(Visible(det, pbs)) }
	if n("wlc-9800") != 2 || n("ios-xe") != 1 || n("ios") != 1 {
		t.Errorf("%d %d %d", n("wlc-9800"), n("ios-xe"), n("ios"))
	}
}

// El error del timeout máximo conserva el texto en español del núcleo anterior y tiene versión en inglés.
func TestTimeoutMaximoEnEsYEn(t *testing.T) {
	_, err := Load(fstest.MapFS{"x.yaml": {Data: []byte("id: x\nplatform: ios-xe\nname: X\ncommands:\n  - cmd: show x\n    timeout: 31m\n")}})
	es := `playbook x.yaml: timeout "31m" de "show x" pasa el máximo de 30m0s`
	en := `playbook x.yaml: timeout "31m" of "show x" exceeds the maximum of 30m0s`
	if err == nil || err.Error() != es || i18n.In(i18n.En, err) != en {
		t.Fatalf("es %q\nen %q", err, i18n.In(i18n.En, err))
	}
}

// Nombres y comandos con caracteres de control o de formato (bidi, U+202E…) se rechazan: cambian cómo se ve el texto
// sin cambiar lo que dice (trojan source).
func TestLoadRechazaBidiYControl(t *testing.T) {
	for name, body := range map[string]string{
		"nombre":    "id: a\nplatform: ios-xe\nname: \"a\\u202eb\"\ncommands: [{cmd: show clock}]\n",
		"nombre_en": "id: a\nplatform: ios-xe\nname: a\nname_en: \"a\\u2066b\\u2069\"\ncommands: [{cmd: show clock}]\n",
		"comando":   "id: a\nplatform: ios-xe\nname: a\ncommands: [{cmd: \"show clock \\u200f\"}]\n",
		"pre":       "id: a\nplatform: ios-xe\nname: a\npre: [\"terminal length 0\\u202a\"]\ncommands: [{cmd: show clock}]\n",
		"control":   "id: a\nplatform: ios-xe\nname: \"a\\u0007\"\ncommands: [{cmd: show clock}]\n",
	} {
		if _, err := Load(fstest.MapFS{"cisco/ios-xe/a.yaml": {Data: []byte(body)}}); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
}

// Un nombre con caracteres de formato legítimos (emoji con ZWJ, guion suave) sigue cargando: solo se rechazan los
// controles de dirección (bidi). Un playbook propio que no carga tumbaría el arranque del núcleo.
func TestLoadAceptaFormatoLegitimoEnNombre(t *testing.T) {
	body := "id: a\nplatform: ios-xe\nname: \"STP \\U0001F468\\u200D\\U0001F4BB re\\u00ADvisión\"\ncommands: [{cmd: show clock}]\n"
	if _, err := Load(fstest.MapFS{"cisco/ios-xe/a.yaml": {Data: []byte(body)}}); err != nil {
		t.Fatal(err)
	}
}

// nx-os solo con nx-os: los genéricos de ios-xe y los de nx-os no se cruzan.
func TestCompatibleNXOS(t *testing.T) {
	for _, c := range []struct {
		detected, pb string
		want         bool
	}{{"nx-os", "nx-os", true}, {"nx-os", "ios-xe", false}, {"nx-os", "ios", false}, {"ios-xe", "nx-os", false}, {"ios", "nx-os", false}, {"wlc-9800", "nx-os", false}} {
		if Compatible(c.detected, c.pb) != c.want {
			t.Errorf("Compatible(%q, %q) != %v", c.detected, c.pb, c.want)
		}
	}
}

// Un ios-xe usa también los playbooks cat9k y sda (son paquetes de contenido sobre ios-xe); ios, wlc-9800 y nx-os no.
func TestCompatibleCat9kSDA(t *testing.T) {
	for _, det := range []string{"ios", "ios-xe", "wlc-9800", "nx-os"} {
		for _, pb := range []string{"ios", "ios-xe", "cat9k", "sda", "wlc-9800", "nx-os"} {
			want := det == pb ||
				pb == "ios-xe" && (det == "ios" || det == "wlc-9800") ||
				det == "ios-xe" && (pb == "cat9k" || pb == "sda")
			if got := Compatible(det, pb); got != want {
				t.Errorf("Compatible(%q, %q) = %v, quiero %v", det, pb, got, want)
			}
		}
	}
}

// cat9k/x y sda/x nunca son gemelos de ios/x ni de ios-xe/x aunque compartan el ID corto; un ios no los ve.
func TestCat9kSDANoSonGemelosDeIOS(t *testing.T) {
	pbs := []Playbook{
		{ID: "ios-xe/plat-salud", Platform: "ios-xe"}, {ID: "ios/plat-salud", Platform: "ios"},
		{ID: "cat9k/plat-salud", Platform: "cat9k"}, {ID: "sda/plat-salud", Platform: "sda"},
	}
	for _, id := range []string{"cat9k/plat-salud", "sda/plat-salud"} {
		for _, pl := range []string{"ios", "ios-xe"} {
			if tw := Twin(pbs, id, pl); tw != nil {
				t.Errorf("Twin(%s, %s) = %s", id, pl, tw.ID)
			}
		}
	}
	// ios-xe/x tampoco toma a cat9k/x por gemelo en otra plataforma
	for _, pl := range []string{"cat9k", "sda"} {
		if tw := Twin(pbs, "ios-xe/plat-salud", pl); tw != nil {
			t.Errorf("Twin(ios-xe/plat-salud, %s) = %s", pl, tw.ID)
		}
	}
	ids := func(det string) (out []string) {
		for _, p := range Visible(det, pbs) {
			out = append(out, p.ID)
		}
		return
	}
	if got := ids("ios"); len(got) != 1 || got[0] != "ios/plat-salud" {
		t.Errorf("ios ve %v", got)
	}
	if got := ids("ios-xe"); len(got) != 3 {
		t.Errorf("ios-xe ve %v", got)
	}
	if got := ids("wlc-9800"); len(got) != 1 || got[0] != "ios-xe/plat-salud" {
		t.Errorf("wlc-9800 ve %v", got)
	}
	if got := ids("nx-os"); len(got) != 0 {
		t.Errorf("nx-os ve %v", got)
	}
}
