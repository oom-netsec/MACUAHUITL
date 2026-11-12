package radiustest

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"testing"
)

var volatile = regexp.MustCompile(`[0-9]+\.[0-9] ms|"RTTMillis":[0-9.]+|127\.0\.0\.1:[0-9]+|puertos? [0-9]+`)

// escenarios corre las pruebas contra el servidor de mentira y devuelve cada reporte; cubren todos los
// hallazgos y errores que imprime Text.
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
	h, p, _ := fake(t, FakeConfig{Reply: AuthzReply()})
	c := base(h, p)
	c.Accounting = true
	run("accept-acct", direct, c)
	c.Method = "mschapv2"
	c.Accounting = false
	run("mschapv2", direct, c)
	c.Method, c.Password = "pap", []byte("mala")
	run("reject", direct, c)
	c = base(h, p)
	c.StatusServer = true
	run("status-server", direct, c)
	h, p, _ = fake(t, FakeConfig{Reply: AuthzReply(), NoReplyMA: true})
	run("sin-ma", direct, base(h, p))
	h, p, _ = fake(t, FakeConfig{Reply: AuthzReply(), ReplySecret: "otro"})
	run("secreto-distinto", direct, base(h, p))
	h, p, _ = fake(t, FakeConfig{ChallengeUser: "alice"})
	run("challenge", direct, base(h, p))
	c = base("127.0.0.1", 9)
	c.Accounting = true
	run("cerrado", direct, c)
	run("sin-red", func(context.Context, string, string, uint16) (net.Conn, error) {
		return nil, errors.New("dial: network is unreachable")
	}, base("127.0.0.1", 9))
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
