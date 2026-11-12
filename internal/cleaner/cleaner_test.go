package cleaner

import (
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/sucia.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rules(r Result, rule string) []int {
	var out []int
	for _, c := range r.Changes {
		if c.Rule == rule {
			out = append(out, c.Line)
		}
	}
	return out
}

func eq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLimpiezaReportaCadaCambioConSuLinea(t *testing.T) {
	r := Clean(fixture(t), Options{})
	if got := rules(r, RuleBlank); !eq(got, []int{3, 8}) {
		t.Errorf("vacías = %v", got)
	}
	if got := rules(r, RuleBang); !eq(got, []int{5, 9}) {
		t.Errorf("! repetidos = %v", got)
	}
	if got := rules(r, RuleTrail); !eq(got, []int{6}) {
		t.Errorf("espacio final = %v", got)
	}
	if !strings.Contains(r.Output, "hostname SW1\n") || strings.Contains(r.Output, "SW1   ") {
		t.Errorf("no recortó el espacio final:\n%s", r.Output)
	}
	// El banner es texto: ni sus líneas vacías ni sus espacios se tocan.
	if !strings.Contains(r.Output, "Acceso   \n\n   restringido   \n^C\n") {
		t.Errorf("tocó el banner:\n%s", r.Output)
	}
	if strings.Contains(r.Output, "\n\n!\n\n") || strings.Contains(r.Output, "!\n!\n") {
		t.Errorf("quedaron separadores repetidos:\n%s", r.Output)
	}
	// Nada se borra en silencio: líneas de entrada = salida + eliminadas (sin contar las marcas).
	in, out := strings.Count(fixture(t), "\n"), strings.Count(r.Output, "\n")-len(r.Orphans)
	if removed := len(rules(r, RuleBlank)) + len(rules(r, RuleBang)); in-removed != out {
		t.Errorf("entrada %d - eliminadas %d != salida %d", in, removed, out)
	}
}

func TestHuerfanasSeMarcanYNoSeBorran(t *testing.T) {
	r := Clean(fixture(t), Options{})
	want := map[string]string{
		"neighbor 192.0.2.1 route-map RM-FALTA out": "route-map RM-FALTA",
		"ip access-group IN-FALTA in":               "ACL IN-FALTA",
		"class FANTASMA":                            "class-map FANTASMA",
		"service-policy output QOS-FALTA":           "policy-map QOS-FALTA",
		"class-map match-any VOZ":                   "sin uso",
	}
	got := map[string]string{}
	for _, o := range r.Orphans {
		got[o.Text] = o.Why
	}
	for text, why := range want {
		if !strings.Contains(got[text], why) {
			t.Errorf("%q: why = %q, quería %q (todas: %v)", text, got[text], why, got)
		}
	}
	for _, ok := range []string{"neighbor 192.0.2.1 route-map RM-OK in", "ip access-group OUT-FILTER out", "class USADA", "service-policy output QOS", "class-map match-any USADA"} {
		if _, bad := got[ok]; bad {
			t.Errorf("falso positivo: %q", ok)
		}
	}
	if len(r.Orphans) != len(want) {
		t.Errorf("huérfanas = %+v", r.Orphans)
	}
	// La línea sigue en la salida, con su marca justo arriba.
	if !strings.Contains(r.Output, "! HUERFANA: ACL IN-FALTA no existe (ip access-group)\n ip access-group IN-FALTA in\n") {
		t.Errorf("sin marca:\n%s", r.Output)
	}
	for _, o := range r.Orphans {
		if !strings.Contains(r.Output, o.Text) {
			t.Errorf("se borró la huérfana %q", o.Text)
		}
	}
}

func TestOrdenOpcionalDeBloquesIndependientes(t *testing.T) {
	in := "hostname R1\n!\ninterface GigabitEthernet1/0/10\n description diez\n!\ninterface GigabitEthernet1/0/2\n description dos\n!\naccess-list 10 permit 192.0.2.0 0.0.0.255\naccess-list 5 permit any\nip route 198.51.100.0 255.255.255.0 192.0.2.2\nip route 192.0.2.0 255.255.255.0 192.0.2.1\nend\n"
	if r := Clean(in, Options{}); strings.Index(r.Output, "1/0/10") > strings.Index(r.Output, "1/0/2") || rules(r, RuleSort) != nil {
		t.Fatalf("sin --sort no debe reordenar:\n%s", r.Output)
	}
	r := Clean(in, Options{Sort: true})
	i2, i10 := strings.Index(r.Output, "interface GigabitEthernet1/0/2\n"), strings.Index(r.Output, "interface GigabitEthernet1/0/10\n")
	if i2 < 0 || i10 < 0 || i2 > i10 {
		t.Errorf("interfaces sin orden natural:\n%s", r.Output)
	}
	// Cada bloque viaja con sus líneas.
	if !strings.Contains(r.Output, "interface GigabitEthernet1/0/2\n description dos\n!\ninterface GigabitEthernet1/0/10\n description diez\n!\n") {
		t.Errorf("bloques rotos:\n%s", r.Output)
	}
	if strings.Index(r.Output, "ip route 192.0.2.0") > strings.Index(r.Output, "ip route 198.51.100.0") {
		t.Errorf("rutas sin orden:\n%s", r.Output)
	}
	// Las ACL numeradas importan por orden: no se tocan.
	if strings.Index(r.Output, "access-list 10") > strings.Index(r.Output, "access-list 5") {
		t.Errorf("reordenó ACL:\n%s", r.Output)
	}
	if len(rules(r, RuleSort)) != 2 {
		t.Errorf("el reordenamiento debe constar en el reporte: %+v", r.Changes)
	}
	if !strings.HasSuffix(r.Output, "end\n") {
		t.Errorf("end debe quedar al final:\n%s", r.Output)
	}
}

func TestLimpioNoCambiaNada(t *testing.T) {
	in := "hostname R1\n!\ninterface Gi1\n shutdown\n!\nend\n"
	if r := Clean(in, Options{}); r.Output != in || len(r.Changes) != 0 || len(r.Orphans) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSaltosCRLF(t *testing.T) {
	r := Clean("hostname R1\r\n\r\n!\r\n", Options{})
	if r.Output != "hostname R1\n!\n" || len(rules(r, RuleBlank)) != 1 {
		t.Fatalf("%q %+v", r.Output, r.Changes)
	}
}

func TestTexto(t *testing.T) {
	txt := Clean(fixture(t), Options{}).Text()
	for _, w := range []string{"líneas vacías", "3, 8", "separadores !", "5, 9", "espacio final", "HUÉRFANAS", "ip access-group IN-FALTA in", "Las huérfanas solo se marcan"} {
		if !strings.Contains(txt, w) {
			t.Errorf("falta %q en:\n%s", w, txt)
		}
	}
}

// Los textos delimitados (banner, refuse/vacant-message, menu title/text) son texto: ni su cuerpo ni
// el espacio final de la línea de apertura se tocan.
func TestTextosDelimitadosSeProtegen(t *testing.T) {
	in := "banner login ^CBienvenido   \n  texto  \n\n^C\n" +
		"line vty 0 4\n vacant-message ^CLibre   \n\n hola   \n^C\n refuse-message ^CNo   \n\n^C\n" +
		"menu M title ^CMenu   \n\n x   \n^C\n" +
		"menu M text 1 ^CUno   \n\n^C\n"
	r := Clean(in, Options{})
	if r.Output != in || len(r.Changes) != 0 {
		t.Fatalf("tocó el texto:\n%q\n%+v", r.Output, r.Changes)
	}
}
