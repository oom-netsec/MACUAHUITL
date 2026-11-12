package msgkb

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

func TestDefaultCargaYTodoVerifyEsLectura(t *testing.T) {
	kb, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	all := kb.Search("")
	if len(all) < 30 {
		t.Fatalf("la base trae %d entradas, esperaba 30 o más", len(all))
	}
	for _, e := range all {
		if e.Meaning == "" || e.Cause == "" || e.Action == "" || len(e.Verify) == 0 {
			t.Errorf("%s: faltan campos", e.ID)
		}
		for _, c := range e.Verify {
			if err := playbook.CheckDenied("ios", c); err != nil {
				t.Errorf("%s: verify %q no es de lectura: %v", e.ID, c, err)
			}
		}
	}
}

func TestLoadRechazaVerifyDeEscritura(t *testing.T) {
	for _, cmd := range []string{"configure terminal", "write memory", "show version | redirect flash:x", "clear counters", "show version\rreload"} {
		data := "- id: \"%SYS-2-MALLOCFAIL\"\n  meaning: m\n  cause: c\n  action: a\n  verify: [\"" + strings.ReplaceAll(cmd, "\r", `\r`) + "\"]\n"
		_, err := Load([]byte(data))
		if err == nil || !errors.Is(err, playbook.ErrDenied) {
			t.Errorf("%q: Load aceptó un comando que no es de lectura (%v)", cmd, err)
		}
	}
}

func TestLoadRechazaIDInvalidoYDuplicado(t *testing.T) {
	ok := "  meaning: m\n  cause: c\n  action: a\n  verify: [show version]\n"
	for name, data := range map[string]string{
		"sin %":      "- id: SYS-2-X\n" + ok,
		"severidad":  "- id: \"%SYS-9-X\"\n" + ok,
		"minúsculas": "- id: \"%sys-2-x\"\n" + ok,
		"duplicado":  "- id: \"%SYS-2-X\"\n" + ok + "- id: \"%SYS-2-X\"\n" + ok,
		"vacío":      "- id: \"%SYS-2-X\"\n",
		"yaml roto":  "- id: [",
	} {
		if _, err := Load([]byte(data)); err == nil {
			t.Errorf("%s: Load no falló", name)
		}
	}
}

func TestLookupExactoYComodinDeLaBase(t *testing.T) {
	kb, _ := Default()
	e, ok := kb.Lookup("%sys-2-mallocfail")
	if !ok || e.ID != "%SYS-2-MALLOCFAIL" || e.Severity != 2 {
		t.Fatalf("exacto: %+v %v", e, ok)
	}
	if e2, ok := kb.Lookup("SYS-2-MALLOCFAIL:"); !ok || e2.ID != e.ID {
		t.Fatalf("sin %% ni con dos puntos: %+v %v", e2, ok)
	}
	// Un mnemónico que la base no trae cae en el comodín de su familia.
	w, ok := kb.Lookup("%ILPOWER-7-DETECT_NOPE")
	if !ok || w.ID != "%ILPOWER-*" {
		t.Fatalf("comodín: %+v %v", w, ok)
	}
	if _, ok := kb.Lookup("%NOEXISTE-3-NADA"); ok {
		t.Fatal("encontró un mnemónico inexistente")
	}
}

func TestSearchComodin(t *testing.T) {
	kb, _ := Default()
	got := kb.Search("%SPANTREE-2-*")
	if len(got) < 2 {
		t.Fatalf("%d resultados", len(got))
	}
	for _, e := range got {
		if !strings.HasPrefix(e.ID, "%SPANTREE-2-") {
			t.Errorf("%s no coincide", e.ID)
		}
	}
	if len(kb.Search("%NOEXISTE-*")) != 0 {
		t.Fatal("resultados para un patrón sin coincidencias")
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"%A-*", "%A-1-X", true}, {"*", "", true}, {"*X", "%A-1-X", true}, {"%A-?-X", "%A-1-X", true},
		{"%A-?-X", "%A-12-X", false}, {"%A-*-X", "%A-1-Y", false}, {"a*b*c", "aXbYc", true}, {"a*b*c", "aXbY", false},
		{"**a**", "bab", true}, {"", "", true}, {"", "x", false},
	} {
		if got := glob(c.pat, c.s); got != c.want {
			t.Errorf("glob(%q,%q)=%v", c.pat, c.s, got)
		}
	}
	// Muchos asteriscos no deben explotar (tiempo lineal por la estrategia de retroceso mínimo).
	if glob(strings.Repeat("a*", 60)+"b", strings.Repeat("a", 5000)) {
		t.Fatal("coincidencia imposible")
	}
}

func TestMnemonic(t *testing.T) {
	for in, want := range map[string]string{
		"*Nov  4 09:58:12.345: %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down": "%LINK-3-UPDOWN",
		"<189>123: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU":                           "%SPANTREE-2-BLOCK_BPDUGUARD",
		"%PM-4-ERR_DISABLE":         "%PM-4-ERR_DISABLE",
		"sin mnemónico 100% seguro": "",
		"%X-9-Y no es severidad":    "",
	} {
		if got := Mnemonic(in); got != want {
			t.Errorf("Mnemonic(%q)=%q, quería %q", in, got, want)
		}
	}
}

func TestQueryTopesYEntradaHostil(t *testing.T) {
	kb, _ := Default()
	if _, err := kb.Query(strings.Repeat("*a", 200)); err == nil {
		t.Fatal("patrón enorme aceptado")
	}
	if _, err := kb.Query("%SYS-2-\x00\r\n*"); err == nil {
		t.Fatal("caracteres de control aceptados")
	}
	if es, err := kb.Query("%SYS-2-MALLOCFAIL"); err != nil || len(es) != 1 {
		t.Fatalf("exacto: %v %v", es, err)
	}
	if es, err := kb.Query(""); err != nil || len(es) < 30 {
		t.Fatalf("vacío debe listar todo: %d %v", len(es), err)
	}
}

func TestLookupPrefiereElComodinMasEspecifico(t *testing.T) {
	kb, err := Load([]byte(`
- {id: "%A-*", meaning: m, cause: c, action: a, verify: [show version]}
- {id: "%A-3-*", meaning: m, cause: c, action: a, verify: [show version]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := kb.Lookup("%A-3-X"); !ok || e.ID != "%A-3-*" {
		t.Fatalf("%+v %v", e, ok)
	}
	if e, ok := kb.Lookup("%A-4-X"); !ok || e.ID != "%A-*" {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestText(t *testing.T) {
	kb, _ := Default()
	es, _ := kb.Query("%SYS-2-MALLOCFAIL")
	out := Text(es)
	for _, w := range []string{"%SYS-2-MALLOCFAIL", "severidad 2 crítica", "Causa probable:", "show memory statistics", "sin validar en laboratorio"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q en:\n%s", w, out)
		}
	}
	if !strings.Contains(Text(nil), "sin coincidencias") {
		t.Fatal("sin coincidencias")
	}
}

func FuzzQuery(f *testing.F) {
	f.Add("%SYS-2-*")
	f.Add("*a*a*a*a*a*b")
	f.Add("")
	kb, _ := Default()
	f.Fuzz(func(t *testing.T, q string) { _, _ = kb.Query(q); _ = Mnemonic(q); _, _ = kb.ForLine(q) })
}

// Las fichas que sugieren acciones con efecto dicen quién las hace: la herramienta solo lee.
func TestFichasDeAccionesLasHaceUnHumano(t *testing.T) {
	k, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string][]string{
		"%ETHCNTR-3-LOOP_BACK_DETECTED": {"err-disable", "shutdown", "errdisable recovery"},
		"%SYS-5-CONFIG_I":               {"write memory", "humano"},
		"%SYS-2-MALLOCFAIL":             {"evidencia", "recarga", "humano"},
	} {
		e, ok := k.Lookup(id)
		if !ok {
			t.Fatalf("falta %s", id)
		}
		for _, w := range want {
			if !strings.Contains(strings.ToLower(e.Action), strings.ToLower(w)) {
				t.Errorf("%s: la acción no menciona %q: %s", id, w, e.Action)
			}
		}
	}
}
