package drift

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type golden struct{ JSON, Text string }

func gold(v any, text string) golden {
	b, _ := json.Marshal(v)
	return golden{string(b), text}
}

// regCases arma informes de deriva; solo usa lo que ya existía antes de la fase 30c.
func regCases(t *testing.T) (map[string]golden, map[string]any) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]any{}
	add := func(name string, r Report) {
		out[name], ptrs[name] = gold(r, r.Text()), &r
	}
	r1, _ := os.ReadFile("testdata/ronda1.txt")
	r2, _ := os.ReadFile("testdata/ronda2.txt")
	cs, ign := Compare(string(r1), string(r2))
	d := NewDevice("SW1", 1, 2, cs, ign)
	none := NewDevice("SW2", 1, 2, nil, nil)
	add("con-deriva", Report{Dir: "d", From: 1, To: 2, Devices: []DeviceDrift{d, none}, Warnings: []string{"SW3: sin dos rondas con running-config (tiene [2])"}})
	add("enmascarada", Report{Dir: "d", Devices: []DeviceDrift{d}, Masked: true, Warnings: []string{}})
	add("sin-deriva", Report{Dir: "d", Devices: []DeviceDrift{none}, Warnings: []string{}})
	add("vacia", Report{Dir: "d", Warnings: []string{}})
	cs2, ign2 := Compare("hostname A\nntp clock-period 1\n! Last configuration change at 1\n", "hostname B\nntp clock-period 2\n")
	add("volatiles", Report{Dir: "d", Devices: []DeviceDrift{NewDevice("SW9", 3, 4, cs2, ign2)}, Warnings: []string{}})
	return out, ptrs
}

func TestRegresionEs(t *testing.T) {
	got, _ := regCases(t)
	const file = "testdata/regresion_es.golden.json"
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
	var want map[string]golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, got[n], want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("casos: %d vs %d", len(got), len(want))
	}
}
