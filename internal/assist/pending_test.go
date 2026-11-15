package assist

import (
	"strings"
	"testing"
)

func TestRollbackPlanSwapsApplyAndRollbackAndVerifiesTheStateBefore(t *testing.T) {
	const before, left = "interface Gi1\n switchport access vlan 10\n", "interface Gi1\n switchport access vlan 20\n"
	cmd := "show running-config interface Gi1"
	l := Leftover{Function: "ports", Devices: []LeftDevice{
		{Device: "A", Apply: []string{"interface Gi1", "switchport access vlan 20"}, Rollback: []string{"interface Gi1", "switchport access vlan 10"},
			Baseline: map[string]string{cmd: before}, State: map[string]string{cmd: left}, Secrets: []string{"s3"}},
		{Device: "B", Apply: []string{"vlan 5"}, Rollback: []string{"no vlan 5"}, Baseline: map[string]string{cmd: before}, State: map[string]string{cmd: left}},
	}}
	plan, fn, err := RollbackPlan(l)
	if err != nil {
		t.Fatal(err)
	}
	if plan.WriteMemory || plan.Devices[0].Device != "B" || plan.Devices[1].Device != "A" { // del último al primero que se aplicó
		t.Fatalf("plan = %+v", plan)
	}
	a := plan.Devices[1]
	if strings.Join(a.Apply, "|") != "interface Gi1|switchport access vlan 10" || strings.Join(a.Rollback, "|") != "interface Gi1|switchport access vlan 20" ||
		a.Baseline[cmd] != left || a.Secrets[0] != "s3" {
		t.Fatalf("equipo A = %+v", a)
	}
	if err := Validate(plan, fn); err != nil {
		t.Fatal(err)
	}
	// La lista cerrada es exactamente lo guardado.
	if fn.allows("vlan 6") || !fn.allows("no vlan 5") {
		t.Fatal("la lista cerrada no es la guardada")
	}
	// Post/Expect: el estado de antes cumple, el que dejó la ejecución no.
	if f := evalExpect(a.Expect, map[string]string{cmd: before}); len(f) != 0 {
		t.Fatalf("el estado de antes debía cumplir: %v", f)
	}
	if f := evalExpect(a.Expect, map[string]string{cmd: left}); len(f) != 1 {
		t.Fatalf("el estado sin revertir debía fallar: %v", f)
	}
}

func TestRollbackPlanRefusesWhatItCannotVerify(t *testing.T) {
	d := LeftDevice{Device: "A", Apply: []string{"vlan 5"}, Rollback: []string{"no vlan 5"}, Baseline: map[string]string{"show vlan id 5": "x"}}
	if _, _, err := RollbackPlan(Leftover{Devices: []LeftDevice{d}}); err == nil { // sin estado guardado
		t.Fatal("sin estado guardado no hay pre-check")
	}
	d.State = map[string]string{"show vlan id 5": "y"}
	d.Baseline = nil
	if _, _, err := RollbackPlan(Leftover{Devices: []LeftDevice{d}}); err == nil { // sin estado de antes
		t.Fatal("sin estado de antes no hay cómo verificar la vuelta")
	}
}

func TestRollbackPlanRefusesAPartialState(t *testing.T) {
	c1, c2 := "show running-config interface Gi1", "show running-config interface Gi2"
	d := LeftDevice{Device: "A", Apply: []string{"interface Gi1", "shutdown"}, Rollback: []string{"interface Gi1", "no shutdown"},
		Post: []string{c1, c2}, Baseline: map[string]string{c1: "a", c2: "b"}, State: map[string]string{c1: "a2"}} // se cortó la lectura de Gi2
	if _, _, err := RollbackPlan(Leftover{Devices: []LeftDevice{d}}); err == nil || !strings.Contains(err.Error(), "A") {
		t.Fatalf("un State a medias dejaría Gi2 sin pre-check: %v", err)
	}
	d.State[c2] = "b2"
	if _, _, err := RollbackPlan(Leftover{Devices: []LeftDevice{d}}); err != nil {
		t.Fatal(err)
	}
}

// Los comandos operativos y de estado no entran a la verificación de la vuelta; si solo hay de esos, no es verificable.
func TestRollbackPlanVerifiesOnlyConfigurationCommands(t *testing.T) {
	run, sw, st := "show running-config interface Gi1", "show interfaces Gi1 switchport", "show interfaces Gi1 status"
	d := LeftDevice{Device: "A", Apply: []string{"vlan 5"}, Rollback: []string{"no vlan 5"}, Post: []string{run, sw, st},
		Baseline: map[string]string{run: "cfg", sw: "oper", st: "st"}, State: map[string]string{run: "cfg2", sw: "oper2", st: "st2"}}
	plan, _, err := RollbackPlan(Leftover{Devices: []LeftDevice{d}})
	if err != nil {
		t.Fatal(err)
	}
	if e := plan.Devices[0].Expect; len(e) != 1 || e[0].Command != run {
		t.Fatalf("Expect = %+v", e)
	}
	d.Baseline = map[string]string{sw: "oper", st: "st"}
	d.State = map[string]string{sw: "oper2", st: "st2"}
	if _, _, err := RollbackPlan(Leftover{Devices: []LeftDevice{d}}); err == nil {
		t.Fatal("sin configuración que comparar no es verificable")
	}
}

func TestRollbackPlanWarnsWhenTheOriginalRunWroteMemory(t *testing.T) {
	cmd := "show running-config"
	l := Leftover{WriteMemory: true, Devices: []LeftDevice{{Device: "A", Apply: []string{"vlan 5"}, Rollback: []string{"no vlan 5"}, Post: []string{cmd},
		Baseline: map[string]string{cmd: "a"}, State: map[string]string{cmd: "b"}}}}
	plan, _, err := RollbackPlan(l)
	if err != nil || len(plan.Devices[0].Notes) != 1 || !strings.Contains(plan.Devices[0].Notes[0], "write memory") || plan.WriteMemory {
		t.Fatalf("%v %+v", err, plan)
	}
	l.WriteMemory = false
	if plan, _ = func() (Plan, error) { p, _, e := RollbackPlan(l); return p, e }(); len(plan.Devices[0].Notes) != 0 {
		t.Fatal("sin write memory no hay aviso")
	}
}
