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
