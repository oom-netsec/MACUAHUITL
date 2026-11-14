package assist

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// Fase 30e: los motivos de la restauración por diff y los errores del plan en es son los de siempre, byte por byte.
// El golden se generó con el código de antes del cambio (GOLDEN_UPDATE=1 solo para regenerarlo a propósito).
const goldenRestoreFile = "testdata/restore_es.json"

func restoreEs(t *testing.T) map[string][]string {
	out := map[string][]string{}
	run := func(kind string, cases []struct{ name, backup, want string }) {
		for _, tc := range cases {
			for _, partial := range []bool{false, true} {
				p, err := reviewPlan(t, tc.backup, func(c *RestoreChange) { c.Partial = partial })
				k := kind + "/" + tc.name
				if partial {
					k += "/parcial"
				}
				var l []string
				if err != nil {
					l = append(l, "ERR "+err.Error())
				}
				for _, r := range p.Refused {
					l = append(l, r.Path+" | "+r.Line+" | "+r.Why)
				}
				out[k] = l
			}
		}
	}
	run("refusal", refusalCases())
	run("closed", closedCases())
	return out
}

func TestRestoreEsGolden(t *testing.T) {
	got := restoreEs(t)
	if os.Getenv("GOLDEN_UPDATE") == "1" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(goldenRestoreFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(goldenRestoreFile)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string][]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(got) != len(want) {
		t.Fatalf("%d casos, golden %d", len(got), len(want))
	}
	for _, k := range keys {
		g, w := got[k], want[k]
		if len(g) != len(w) {
			t.Errorf("%s: %q != %q", k, g, w)
			continue
		}
		for i := range w {
			if g[i] != w[i] {
				t.Errorf("%s[%d]: %q != %q", k, i, g[i], w[i])
			}
		}
	}
}
