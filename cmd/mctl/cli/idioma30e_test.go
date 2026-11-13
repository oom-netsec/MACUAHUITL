package cli

import (
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Fase 30e: los textos propios de la ejecución asistida salen en el idioma de mctl; con es, los de siempre.
func TestAsistidoEsYEn(t *testing.T) {
	t.Cleanup(func() { SetLang("") })
	st := &v1.AssistRunState{RunId: "r1", State: "failed", Active: true, Devices: []string{"a"}, Changed: []string{"a"}}
	plan := &v1.AssistPlan{WriteMemory: true, Devices: []*v1.AssistDevicePlan{{Device: "sw", Pre: []string{"show x"}, Notes: []string{"n"},
		Expect: []*v1.AssistExpect{{Command: "c", Line: "l", Present: false}}}}}
	for lang, want := range map[string][]string{
		"":   {"(viva)", "equipos=a", "Plan para sw", "Pre-check (lectura)", "REVERSA (restaura lo capturado)", "  Avisos:", "  Se espera ver:", "(NO debe aparecer)", "write memory"},
		"en": {"(live)", "devices=a", "Plan for sw", "Pre-check (read-only)", "ROLLBACK (restores what was captured)", "  Warnings:", "  Expected to see:", "(must NOT appear)", "write memory"},
	} {
		SetLang(lang)
		var b strings.Builder
		PrintPlan(&b, plan)
		got := StateLine(st) + "\n" + b.String()
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%q: falta %q en\n%s", lang, w, got)
			}
		}
	}
	SetLang("en")
	if _, _, err := SplitHost("h:abc"); err == nil || err.Error() != `invalid port "abc"` {
		t.Errorf("%v", err)
	}
	SetLang("")
	if _, _, err := SplitHost("h:abc"); err == nil || err.Error() != `puerto inválido "abc"` {
		t.Errorf("%v", err)
	}
}
