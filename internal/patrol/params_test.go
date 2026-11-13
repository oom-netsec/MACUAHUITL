package patrol

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

func pbConMAC() []playbook.Playbook {
	return []playbook.Playbook{
		{ID: "ios-xe/cli", Platform: "ios-xe", Params: []playbook.Param{{Name: "mac", Kind: "mac"}},
			Commands: []playbook.Command{{Text: "show wireless client mac-address {mac} detail"}}},
		{ID: "ios-xe/plano", Platform: "ios-xe", Commands: []playbook.Command{{Text: "show clock"}}},
	}
}

func specParams(t *testing.T, ids []string, p map[string]string) Spec {
	return Spec{Targets: []Target{{Address: "192.0.2.1"}}, DefaultCredentialID: "c", WindowHours: 1, OutputDir: t.TempDir(), PlaybookIDs: ids, Params: p}
}

func TestValidateWithParams(t *testing.T) {
	pbs := pbConMAC()
	ok := specParams(t, []string{"ios-xe/cli", "ios-xe/plano"}, map[string]string{"mac": "AA:BB:CC:DD:EE:FF"})
	if err := ValidateWith(ok, pbs, nil, nil); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Spec{
		"falta":                  specParams(t, []string{"ios-xe/cli"}, nil),
		"desconocido":            specParams(t, []string{"ios-xe/cli"}, map[string]string{"mac": "aabb.ccdd.eeff", "ap": "x"}),
		"sin playbook con datos": specParams(t, []string{"ios-xe/plano"}, map[string]string{"mac": "aabb.ccdd.eeff"}),
		"inyección":              specParams(t, []string{"ios-xe/cli"}, map[string]string{"mac": "aabb.ccdd.eeff\nconf t"}),
	} {
		err := ValidateWith(s, pbs, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "params") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCommandsExpandParams(t *testing.T) {
	pbs := pbConMAC()
	s := Spec{PlaybookIDs: []string{"ios-xe/cli", "ios-xe/plano"}, Params: map[string]string{"mac": "AA-BB-CC-DD-EE-FF"}}
	out, _, err := commands(s, "ios-xe", pbs, nil)
	if err != nil || len(out) != 2 || out[0].Text != "show wireless client mac-address aabb.ccdd.eeff detail" || out[1].Text != "show clock" {
		t.Fatalf("%v %v", out, err)
	}
	// sin el dato nunca sale un comando con {mac} literal
	out, _, err = commands(Spec{PlaybookIDs: []string{"ios-xe/cli"}}, "ios-xe", pbs, nil)
	if err == nil || len(out) != 0 {
		t.Fatalf("%v %v", out, err)
	}
	// sin datos, idéntico a hoy
	out, _, err = commands(Spec{PlaybookIDs: []string{"ios-xe/plano"}}, "ios-xe", pbs, nil)
	if err != nil || len(out) != 1 {
		t.Fatal(err)
	}
}

// El Spec se guarda como JSON (core.persistJob): los datos viajan, y sin datos el JSON es el de siempre.
func TestSpecParamsJSON(t *testing.T) {
	b, _ := json.Marshal(Spec{Name: "x"})
	if strings.Contains(string(b), "Params") {
		t.Fatal(string(b))
	}
	b, _ = json.Marshal(Spec{Params: map[string]string{"mac": "aabb.ccdd.eeff"}})
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil || s.Params["mac"] != "aabb.ccdd.eeff" {
		t.Fatal(err, s.Params)
	}
}

// ios/cli solo existe por su gemelo ios-xe/cli: la MAC va al gemelo y no es param_unknown.
func TestValidateWithParamsGemelo(t *testing.T) {
	pbs := pbConMAC()
	s := specParams(t, []string{"ios/cli"}, map[string]string{"mac": "AA:BB:CC:DD:EE:FF"})
	if err := ValidateWith(s, pbs, nil, nil); err != nil {
		t.Fatal(err)
	}
	s = specParams(t, []string{"ios/cli"}, nil)
	if err := ValidateWith(s, pbs, nil, nil); err == nil {
		t.Fatal("falta el dato del gemelo y pasó")
	}
	s = specParams(t, []string{"ios/cli"}, map[string]string{"mac": "mal"})
	if err := ValidateWith(s, pbs, nil, nil); err == nil {
		t.Fatal("dato inválido pasó")
	}
}
