package pcapan

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// escenarios son los informes que cubren todas las secciones y avisos que imprime Text.
func escenarios(t *testing.T) map[string]Report {
	t.Helper()
	out := map[string]Report{}
	run := func(name, path string, o Options) {
		r, err := Analyze(context.Background(), path, o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r.File = "F" // la ruta es temporal
		out[name] = r
	}
	run("caso", scenario(t), Options{})
	p := scenario(t)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, b[:len(b)-30], 0o600)
	run("truncado", p, Options{})
	c := newCapture(t)
	for i := 0; i < 50; i++ {
		c.tcp(time.Duration(i)*ms, "10.0.1.1", uint16(41000+i), "10.0.2.2", 80, 1, "S", 1000, nil)
	}
	run("limite", c.write("scan.pcap"), Options{MaxFlows: 10})
	return out
}

func view(r Report) map[string]string {
	b, _ := json.Marshal(r)
	return map[string]string{"json": string(b), "text": r.Text()}
}

// Regresión: el texto en español del informe es el de antes del catálogo (UPDATE_GOLDEN=1 lo reescribe).
func TestTextoEspanolRegresion(t *testing.T) {
	got := map[string]map[string]string{}
	for n, r := range escenarios(t) {
		got[n] = view(r)
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
		for k, v := range g {
			if want[n][k] != v {
				t.Errorf("%s/%s cambió\n got: %s\nwant: %s", n, k, v, want[n][k])
			}
		}
	}
	_ = strings.Contains
}
