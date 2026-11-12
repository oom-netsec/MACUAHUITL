package core

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// auditEntries lee la bitácora completa como entradas {action, detail}.
func (h *harness) auditEntries(t *testing.T) (out []struct{ Action, Detail string }) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSpace(h.auditText(t)), "\n") {
		var e struct{ Action, Detail string }
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		out = append(out, e)
	}
	return out
}

// El detalle de auditoría va siempre en inglés: accept-language no lo cambia.
func TestAuditoriaDetalleNoDependeDelIdioma(t *testing.T) {
	details := map[string][]string{}
	for _, lang := range []string{"", "es", "en"} {
		h := newHarness(t, nil)
		cred := h.ready(t)
		cj, err := h.patrol.CreateJob(con(t, lang), &v1.CreateJobRequest{Spec: h.spec(cred)})
		if err != nil {
			t.Fatal(err)
		}
		s, err := h.patrol.LoginTest(con(t, lang), &v1.LoginTestRequest{JobId: cj.JobId})
		if err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := s.Recv(); err != nil {
				break
			}
		}
		if _, err := h.vault.Lock(con(t, lang), &v1.LockRequest{}); err != nil {
			t.Fatal(err)
		}
		for _, e := range h.auditEntries(t) {
			if e.Action == "job.logintest" || e.Action == "vault.lock" {
				details[e.Action] = append(details[e.Action], e.Detail)
			}
		}
	}
	for action, want := range map[string]string{"job.logintest": "passed=0 of 1", "vault.lock": "reason=user"} {
		if got := details[action]; len(got) != 3 || got[0] != want || got[1] != want || got[2] != want {
			t.Errorf("%s: %q, quería %q en los tres idiomas", action, got, want)
		}
	}
}

// Una sesión completa (bóveda, trabajo, armado, rondas, cierre, respaldo) no deja español en el detalle.
// Los textos de error sin código quedan tal cual (ver el plan 30a-2), así que las acciones de falla no se revisan.
func TestAuditoriaDeUnaSesionSinEspanol(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	h.waitJob(t, job, "closed")
	if _, err := h.vault.Lock(ctx(t), &v1.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range h.auditEntries(t) {
		seen[e.Action] = true
		if strings.HasSuffix(e.Action, "_failed") || strings.HasSuffix(e.Action, ".failed") || strings.HasSuffix(e.Action, ".warning") {
			continue
		}
		if w := servicetest.SpanishWords(e.Detail); len(w) > 0 {
			t.Errorf("%s: español %v en %q", e.Action, w, e.Detail)
		}
	}
	for _, a := range []string{"vault.create", "job.create", "job.logintest", "job.arm", "power.inhibit", "device.round", "job.finish", "vault.lock"} {
		if !seen[a] {
			t.Errorf("la sesión no ejerció %s", a)
		}
	}
}
