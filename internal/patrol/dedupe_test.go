package patrol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func pbsDup() []playbook.Playbook {
	c := func(t string) playbook.Command { return playbook.Command{Text: t} }
	return []playbook.Playbook{
		{ID: "ios-xe/a", Platform: "ios-xe", Pre: []string{"terminal length 0"}, Commands: []playbook.Command{c("show clock"), c("show version"), c("show a")}},
		{ID: "ios-xe/b", Platform: "ios-xe", Pre: []string{"terminal length 0"}, Commands: []playbook.Command{c("show b"), c("show version"), c("show clock")}},
	}
}

func texts(cs []playbook.Command) []string {
	var o []string
	for _, c := range cs {
		o = append(o, c.Text)
	}
	return o
}

func TestDedupeUnaVezEnOrdenDePrimeraAparicion(t *testing.T) {
	s := Spec{PlaybookIDs: []string{"ios-xe/a", "ios-xe/b"}, CustomCommands: "show clock\nshow custom\n"}
	out, _, req, err := plan(s, "ios-xe", pbsDup(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"terminal length 0", "show clock", "show version", "show a", "show b", "show custom"}
	if !reflect.DeepEqual(texts(out), want) {
		t.Fatalf("got %v", texts(out))
	}
	// Requested: solo lo que pidió más de un playbook; el pegado no es playbook
	if len(req) != 3 || !reflect.DeepEqual(req["show version"], []string{"ios-xe/a", "ios-xe/b"}) || req["terminal length 0"] == nil || req["show clock"] == nil {
		t.Fatalf("requested %v", req)
	}
	// dos equipos del mismo trabajo: cada uno recibe su lista completa
	out2, _, _, _ := plan(s, "ios-xe", pbsDup(), nil)
	if !reflect.DeepEqual(texts(out2), want) {
		t.Fatal("segundo equipo")
	}
}

func TestDedupeTimeoutMayorYSecretosOR(t *testing.T) {
	out, req := Dedupe([]Item{
		{playbook.Command{Text: "x", Timeout: 10 * time.Second}, "a"},
		{playbook.Command{Text: "x", Timeout: 90 * time.Second, MaySecrets: true}, "b"},
		{playbook.Command{Text: "x", Timeout: 30 * time.Second}, "b"},
	})
	if len(out) != 1 || out[0].Timeout != 90*time.Second || !out[0].MaySecrets || !reflect.DeepEqual(req["x"], []string{"a", "b"}) {
		t.Fatalf("%+v %v", out, req)
	}
}

// Misma base con otra expansión (otra interfaz) son comandos distintos.
func TestDedupeExpansionesDistintasNoSeFusionan(t *testing.T) {
	out, req := Dedupe([]Item{
		{playbook.Command{Text: "show interfaces Gi0/1"}, "a"},
		{playbook.Command{Text: "show interfaces Gi0/2"}, "b"},
	})
	if len(out) != 2 || req != nil {
		t.Fatalf("%+v %v", out, req)
	}
}

func TestEvidenciaSinRepetidosYManifestRequested(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	c := func(t string) playbook.Command { return playbook.Command{Text: t} }
	e.d.Playbooks = append(e.d.Playbooks,
		playbook.Playbook{ID: "ios-xe/da", Platform: "ios-xe", Commands: []playbook.Command{c("show version"), c("show ip interface brief")}},
		playbook.Playbook{ID: "ios-xe/db", Platform: "ios-xe", Commands: []playbook.Command{c("show ip interface brief"), c("show version")}})
	e.spec.PlaybookIDs, e.spec.CustomCommands = []string{"ios-xe/da", "ios-xe/db"}, ""
	dir, m := runJob(t, e, 1)
	if m.Devices[0].Commands != 2 {
		t.Fatalf("commands = %d", m.Devices[0].Commands)
	}
	if got := m.Devices[0].Requested["show version"]; !reflect.DeepEqual(got, []string{"ios-xe/da", "ios-xe/db"}) {
		t.Fatalf("requested %v", m.Devices[0].Requested)
	}
	if !grepDir(t, dir, "· show version =====") {
		t.Fatal("falta show version")
	}
	b, _ := json.Marshal(m.Devices[0])
	if !strings.Contains(string(b), `"Requested"`) {
		t.Fatalf("%s", b)
	}
}
