package ikedec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// casos son las entradas que fijan la regresión: cada fixture, el tope de SAs y una entrada sin reconocer.
func casos(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{"desconocida": "hola\nnada que ver"}
	files, _ := filepath.Glob("testdata/*.txt")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".txt")] = string(b)
	}
	var b strings.Builder
	for i := 0; i < 520; i++ {
		fmt.Fprintf(&b, " 10.%d.%d.1  10.0.0.2  QM_IDLE  %d ACTIVE\n", i/250, i%250, 1000+i)
	}
	out["limite-sas"] = b.String()
	out["psk-ausente-lifetime"] = "ISAKMP:(0): No pre-shared key with 192.0.2.9!\nISAKMP: lifetime mismatch not acceptable\n"
	sa := func(peer string, enc, dec int, spi bool) string {
		x := fmt.Sprintf("   local  ident (addr/mask/prot/port): (10.1.1.0/255.255.255.0/0/0)\n   remote ident (addr/mask/prot/port): (10.2.2.0/255.255.255.0/0/0)\n   current_peer %s port 500\n    #pkts encaps: %d, #pkts encrypt: %d\n    #pkts decaps: %d, #pkts decrypt: %d\n", peer, enc, enc, dec, dec)
		if spi {
			x += "      spi: 0x9F8E7D6C(2676915564)\n"
		}
		return x
	}
	out["ipsec-solo-entrada-sin-trafico"] = sa("192.0.2.2", 0, 5, true) + sa("192.0.2.3", 0, 0, true)
	return out
}

func viewIKE(r Report) map[string]string {
	j, _ := json.Marshal(r)
	return map[string]string{"json": string(j), "text": r.Text()}
}

// Regresión: el JSON y el texto en español de cada entrada son los de antes del catálogo (UPDATE_GOLDEN=1 los reescribe).
func TestTextoEspanolRegresion(t *testing.T) {
	got := map[string]map[string]string{}
	for n, in := range casos(t) {
		got[n] = viewIKE(Decode(in))
	}
	const file = "testdata/text_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for n, g := range got {
		for _, k := range []string{"json", "text"} {
			if g[k] != want[n][k] {
				t.Errorf("%s/%s cambió:\n got: %s\nwant: %s", n, k, g[k], want[n][k])
			}
		}
	}
}

// Lo estructurado dice lo mismo que el texto: el español del catálogo para cada clave es el texto de siempre, y con
// en todo sale en inglés (título, explicación, acción, fases, propuestas, significado de los estados y etiquetas).
func TestEnInglesYEstructuradoCoincide(t *testing.T) {
	spanish := regexp.MustCompile(`(?i)\b(el par|la fase|propuestas? |hallazgos?|acción|detectado|establecida|rechazada|aceptada|nota:|sin respuesta|se omitieron|tráfico|revisa|configura|verifica|no hay|falla)\b`)
	codes := map[string]bool{}
	for n, in := range casos(t) {
		r := Decode(in)
		for _, f := range r.Findings {
			codes[f.Code] = true
			es := f.In(i18n.Es)
			if es.Title != f.Title || es.Explanation != f.Explanation || es.Action != f.Action || !slices.Equal(es.Evidence, f.Evidence) {
				t.Errorf("%s/%s: el catálogo en español no es el texto", n, f.Code)
			}
			en := f.In(i18n.En)
			for _, x := range []string{en.Title, en.Explanation, en.Action} {
				if x == "" || spanish.MatchString(x) {
					t.Errorf("%s/%s: %q sin traducir", n, f.Code, x)
				}
			}
			if !strings.HasPrefix(f.Key(), "ike.finding.") || f.ExplanationKey() == "" || len(en.Evidence) != len(f.Evidence) {
				t.Errorf("%s/%s: clave %q", n, f.Code, f.Key())
			}
		}
		for i, p := range r.In(i18n.En).Proposals {
			if p.Source == r.Proposals[i].Source || p.Detail != r.Proposals[i].Detail || p.Result == r.Proposals[i].Result && p.Result != "" {
				t.Errorf("%s: propuesta %+v", n, p)
			}
		}
		txt := r.TextIn(i18n.En)
		if spanish.MatchString(strings.ReplaceAll(txt, "Fase", "")) && n != "desconocida" {
			t.Errorf("%s: texto en inglés con español:\n%s", n, firstSpanish(spanish, txt))
		}
		if r.TextIn(i18n.Es) != r.Text() {
			t.Errorf("%s: Text y TextIn(es) difieren", n)
		}
		if len(r.Detected) > 0 && !strings.HasPrefix(txt, "Detected: ") || len(r.Detected) == 0 && !strings.HasPrefix(txt, "No IKE/IPsec output") {
			t.Errorf("%s: %q", n, txt[:40])
		}
	}
	if len(codes) < 19 {
		t.Errorf("solo %d códigos de hallazgo cubiertos", len(codes))
	}
}

func firstSpanish(re *regexp.Regexp, s string) string {
	for _, l := range strings.Split(s, "\n") {
		if re.MatchString(l) {
			return l
		}
	}
	return ""
}

// Variantes dinámicas: atributos que no coinciden, PFS rechazado, límite de SAs y significado de los estados.
func TestVariantesEn(t *testing.T) {
	c := casos(t)
	p1 := Decode(c["ikev1_p1_mismatch"]).In(i18n.En)
	var f1 Finding
	for _, f := range p1.Findings {
		if f.Code == "p1-propuesta" {
			f1 = f
		}
	}
	if !strings.Contains(f1.Explanation, "Attributes that do not match according to the device: encryption, ") || !strings.Contains(f1.Explanation, "DH group") {
		t.Errorf("%s", f1.Explanation)
	}
	if f := Decode(c["ikev1_p1_mismatch"]).Findings[0]; f.Args()["attrs"] == "" || !strings.HasPrefix(f.Args()["attrs"], "ike.val.attr.") {
		t.Errorf("args: %v", f.Args())
	}
	for _, f := range Decode(c["ikev1_p2_transform_pfs"]).In(i18n.En).Findings {
		if f.Code == "pfs" && (f.Severity != "aviso" || !strings.HasPrefix(f.Explanation, "The peer proposes PFS")) {
			t.Errorf("pfs: %+v", f)
		}
	}
	for _, f := range Decode(c["limite-sas"]).In(i18n.En).Findings {
		if f.Code == "limite-sas" && f.Explanation != "The result lists at most 500 IKE SAs and 500 IPsec SAs; 20 IKE SAs and 0 IPsec SAs were omitted." {
			t.Errorf("límite: %s", f.Explanation)
		}
	}
	for _, f := range Decode(c["show_sa_tables"]).In(i18n.En).Findings {
		if f.Code == "sa-estado" && !strings.Contains(strings.Join(f.Evidence, "\n"), "  → phase 1 stalled in the first exchange") {
			t.Errorf("evidencia: %v", f.Evidence)
		}
	}
}

// In(es) no cambia nada: el servicio la usa siempre, así que el JSON en español debe quedar igual.
func TestInEspanolEsIdentidad(t *testing.T) {
	for n, in := range casos(t) {
		r := Decode(in)
		a, _ := json.Marshal(r)
		b, _ := json.Marshal(r.In(i18n.Es))
		if string(a) != string(b) {
			t.Errorf("%s: In(es) cambia el JSON", n)
		}
	}
}
