package tacacstest

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"testing"
)

var volatile = regexp.MustCompile(`[0-9]+\.[0-9] ms|"RTTMillis":[0-9.]+|127\.0\.0\.1:[0-9]+|(task_id|start_time|stop_time)=[0-9]+`)

// escenarios corre las pruebas contra el servidor de mentira; cubren todos los hallazgos y errores que imprime Text.
func escenarios(t *testing.T) map[string]Report {
	t.Helper()
	out := map[string]Report{}
	run := func(name string, d Dialer, c Config) {
		r, err := Run(context.Background(), d, c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = r
	}
	h, p := fake(t, FakeConfig{})
	run("ascii", direct, base(h, p))
	c := base(h, p)
	c.AuthenType = "pap"
	run("pap", direct, c)
	c = base(h, p)
	c.Password, c.Command = []byte("mala"), "configure terminal"
	run("fail", direct, c)
	c = base(h, p)
	c.Password, c.Command, c.Accounting = []byte("pw-admin"), "configure terminal", false
	run("author-fail", direct, c)
	run("cerrado", direct, base("127.0.0.1", 1))
	run("sin-red", func(context.Context, string, string, uint16) (net.Conn, error) {
		return nil, errors.New("dial: network is unreachable")
	}, base("127.0.0.1", 49))
	synth := Report{Server: "10.0.0.1:49", Steps: []Step{{Kind: "authentication", Status: "ERROR", ServerMsg: "m"}, {Kind: "authorization", Status: "FOLLOW"}}}
	synth.findings()
	out["estado"] = synth
	return out
}

func view(r Report) map[string]string {
	b, _ := json.Marshal(r)
	return map[string]string{"json": volatile.ReplaceAllString(string(b), "X"), "text": volatile.ReplaceAllString(r.Text(), "X")}
}

// Regresión: el texto en español de cada prueba es el de antes del catálogo (UPDATE_GOLDEN=1 lo reescribe).
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
}

// Fase 30c-A: los code de hallazgo son identificadores cerrados en inglés.
func TestCodigosDeHallazgoEnIngles(t *testing.T) {
	closed := map[string]bool{"secret": true, "no_response": true, "authen_fail": true, "author_fail": true, "status": true}
	seen := map[string]bool{}
	for n, r := range escenarios(t) {
		for _, f := range r.Findings {
			if !closed[f.Code] {
				t.Errorf("%s: code %q fuera del conjunto cerrado", n, f.Code)
			}
			seen[f.Code] = true
		}
	}
	for c := range closed {
		if !seen[c] && c != "secret" { // «secret» lo produce un secreto distinto: lo cubre TestWrongSecretIsDiagnosed
			t.Errorf("ningún escenario produce %q", c)
		}
	}
}
