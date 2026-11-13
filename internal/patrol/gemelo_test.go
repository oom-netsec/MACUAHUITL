package patrol

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func gemelos() []playbook.Playbook {
	cmd := func(s string) []playbook.Command { return []playbook.Command{{Text: s}} }
	return []playbook.Playbook{
		{ID: "ios-xe/cpu", Platform: "ios-xe", Commands: cmd("show xe")},
		{ID: "ios/cpu", Platform: "ios", Pack: "oom/ios", Commands: cmd("show clasico")},
		{ID: "ios/solo", Platform: "ios", Pack: "oom/ios", Commands: cmd("show solo")},
		{ID: "ios-xe/acme-x", Platform: "ios-xe", Pack: "acme/p", Commands: cmd("show acme")},
		{ID: "ios/acme-x", Platform: "ios", Pack: "otro/q", Commands: cmd("show otro")},
	}
}

// Si el usuario elige los dos del par, el equipo corre el playbook una sola vez.
func TestGemeloElegidoDosVecesCorreUnaVez(t *testing.T) {
	for _, det := range []string{"ios", "ios-xe"} {
		for _, ids := range [][]string{{"ios-xe/cpu", "ios/cpu"}, {"ios/cpu", "ios-xe/cpu"}} {
			out, _, err := commands(Spec{PlaybookIDs: ids}, det, gemelos(), nil)
			if err != nil || len(out) != 1 {
				t.Errorf("%s %v: %v %v", det, ids, out, err)
			}
		}
	}
}

// Un ID guardado que ya no existe usa su gemelo oficial (trabajo con ios-xe/x y solo oom/ios instalado).
func TestIDFaltanteUsaGemelo(t *testing.T) {
	pbs := gemelos()
	out, _, err := commands(Spec{PlaybookIDs: []string{"ios-xe/solo"}}, "ios", pbs, nil)
	if err != nil || len(out) != 1 || out[0].Text != "show solo" {
		t.Fatalf("commands: %v %v", out, err)
	}
	if _, _, err := commands(Spec{PlaybookIDs: []string{"ios-xe/solo"}}, "ios-xe", pbs, nil); err == nil { // en IOS-XE no hay gemelo: no existe
		t.Error("ios-xe/solo en ios-xe debía fallar")
	}
	if _, _, err := commands(Spec{PlaybookIDs: []string{"ios-xe/nada"}}, "ios", pbs, nil); err == nil {
		t.Error("sin gemelo debía fallar")
	}
	e := newEnv(t, simulator.Config{})
	e.spec.PlaybookIDs = []string{"ios-xe/solo"}
	if err := ValidateWith(e.spec, pbs, e.d.Vault, nil); err != nil {
		t.Errorf("ValidateWith con gemelo: %v", err)
	}
	e.spec.PlaybookIDs = []string{"ios-xe/nada"}
	if err := ValidateWith(e.spec, pbs, e.d.Vault, nil); err == nil {
		t.Error("ValidateWith sin gemelo debía fallar")
	}
}

// El gemelo de otro paquete de terceros no se usa.
func TestGemeloNoCruzaTerceros(t *testing.T) {
	out, _, err := commands(Spec{PlaybookIDs: []string{"ios-xe/acme-x"}}, "ios", gemelos(), nil)
	if err != nil || len(out) != 1 || out[0].Text != "show acme" {
		t.Fatalf("%v %v", out, err)
	}
}

// El manifest registra lo que de verdad corrió en cada equipo, sin tocar el resto del JSON.
func TestManifestRegistraElGemelo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.d.Playbooks = gemelos()
	e.spec.PlaybookIDs = []string{"ios-xe/cpu"}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := DeviceResult{State: "completed", Ran: []string{"ios/cpu"}}
	m, err := Finish(context.Background(), e.d, w, e.spec, 1, []DeviceResult{res})
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, p := range m.Playbooks {
		ids = append(ids, p.ID)
	}
	if !slices.Equal(ids, []string{"ios-xe/cpu", "ios/cpu"}) {
		t.Errorf("playbooks %v", ids)
	}
	b, _ := json.Marshal(m)
	if !strings.Contains(string(b), `"Ran":["ios/cpu"]`) {
		t.Errorf("sin Ran en el JSON: %s", b)
	}
	b, _ = json.Marshal(DeviceResult{State: "completed"})
	if strings.Contains(string(b), "Ran") {
		t.Errorf("Ran vacío no debe serializarse: %s", b)
	}
}
