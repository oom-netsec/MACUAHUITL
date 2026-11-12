package assist

import (
	"context"
	"strings"
	"testing"
)

// modoRun arma una ejecución real del motor sobre el modelo iosDev: planea modo-puerto, y cuando el apply llega al equipo, afterApply
// cambia lo que el equipo muestra (lo que haría un enlace que rebota o un vecino que negocia).
func modoRun(t *testing.T, cfg []string, mode string, afterApply func(d *iosDev)) (*Run, *fakeExec, *iosDev) {
	t.Helper()
	dev := newDev(map[string][]string{gi1: cfg})
	dp, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": mode}, dev)
	if err != nil {
		t.Fatal(err)
	}
	ex := &fakeExec{}
	ex.readFunc = func(_, cmd string) string { return dev.read([]string{cmd})[cmd] }
	first := true
	ex.onConfigure = func(_ string, lines []string) {
		dev.apply(lines)
		if first && afterApply != nil {
			afterApply(dev)
		}
		first = false
	}
	r, err := NewRun(Options{ID: "run1", Plan: Plan{Function: SnippetPortMode.Name, Devices: []DevicePlan{dp}}, Fn: SnippetPortMode, Assisted: true, Exec: ex, Audit: func(a, b, c string) {}})
	if err != nil {
		t.Fatal(err)
	}
	r.Start(context.Background())
	pending(t, r, "apply-1")
	return r, ex, dev
}

// El Operational Mode cambia solo (el rebote que avisa la nota: down -> static access): la reversa no puede quedar bloqueada por eso.
func TestModoPuertoRollbackSurvivesOperationalModeChange(t *testing.T) {
	for name, c := range map[string]struct {
		cfg  []string
		mode string
	}{
		"desirable a auto":    {[]string{"switchport mode dynamic desirable"}, "dynamic auto"},
		"desirable a fábrica": {[]string{"switchport mode dynamic desirable"}, "fabrica"},
	} {
		r, ex, _ := modoRun(t, c.cfg, c.mode, func(d *iosDev) { d.oper = map[string]string{gi1: "static access"} })
		r.Confirm("apply-1")
		pending(t, r, "close")
		if err := r.Rollback(); err != nil {
			t.Fatal(err)
		}
		pending(t, r, "rollback-1")
		r.Confirm("rollback-1")
		wait(t, r, RolledBack)
		n := 0
		for _, call := range ex.Calls() {
			if strings.HasPrefix(call, "cfg") && strings.Contains(call, "switchport mode") {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%s: líneas de modo mandadas = %d (apply y reversa)", name, n)
		}
	}
}

// Un vecino que negocia un trunk por DTP tras el cambio no pasa el post-check, y se propone la reversa.
func TestModoPuertoPostCheckSeesNegotiatedTrunk(t *testing.T) {
	for name, c := range map[string]struct {
		cfg  []string
		mode string
	}{
		"access a desirable":  {accessGi(), "dynamic desirable"},
		"access a auto":       {accessGi(), "dynamic auto"},
		"access a fábrica":    {accessGi(), "fabrica"},
		"fábrica a desirable": {nil, "dynamic desirable"},
	} {
		r, _, _ := modoRun(t, c.cfg, c.mode, func(d *iosDev) { d.oper = map[string]string{gi1: "trunk"} })
		r.Confirm("apply-1")
		wait(t, r, Failed)
		if !strings.Contains(r.FailReason(), "Operational Mode: trunk") {
			t.Errorf("%s: motivo %q", name, r.FailReason())
		}
		if err := r.Rollback(); err != nil {
			t.Fatal(err)
		}
		pending(t, r, "rollback-1")
		r.Confirm("rollback-1")
		wait(t, r, RolledBack)
	}
}

// Pasar a access no negocia nada: no se lee el switchport en Post.
func TestModoPuertoAccessTargetDoesNotReadSwitchportInPost(t *testing.T) {
	dp, _ := modoRT(t, "access", nil)
	for _, c := range dp.Post {
		if strings.Contains(c, "switchport") {
			t.Errorf("Post lee %q", c)
		}
	}
}
