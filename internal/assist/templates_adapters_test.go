package assist

import (
	"reflect"
	"testing"
)

// Los snippets que ya existían entran al catálogo sin cambiar su lógica: el plan de la plantilla es el de la función de siempre.
func TestAdaptersPlanLikeTheOriginalFunctions(t *testing.T) {
	plan := func(id string, v Values, outs map[string]string) (DevicePlan, error) {
		tpl, ok := TemplateByID(id)
		if !ok {
			t.Fatalf("no hay plantilla %s", id)
		}
		if err := ValidateValues(tpl, v); err != nil {
			t.Fatal(err)
		}
		pre, err := tpl.Pre(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range pre {
			if _, ok := outs[c]; !ok {
				t.Fatalf("%s: el fixture no trae la salida de %q", id, c)
			}
		}
		return tpl.Plan("SW1", v, outs)
	}
	check := func(id string, got, want DevicePlan, gerr, werr error) {
		t.Helper()
		if gerr != nil || werr != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: plantilla %+v (%v), función %+v (%v)", id, got, gerr, want, werr)
		}
	}

	vlanOut := withID(vlanOuts(vtpTransparent), 30, "")
	got, gerr := plan("vlan", Values{"id": "30", "name": "Cuarentena"}, vlanOut)
	want, werr := VlanPlan("SW1", VlanChange{ID: 30, Name: "Cuarentena"}, vlanOut)
	check("vlan", got, want, gerr, werr)
	if err := Validate(Plan{Function: SnippetVlan.Name, Devices: []DevicePlan{got}}, SnippetVlan); err != nil {
		t.Error(err)
	}

	trOut := trunkOuts(gi1, trunkCfg(gi1, "switchport mode trunk", "switchport trunk allowed vlan 10,20"), swTrunk)
	got, gerr = plan("trunk", Values{"interface": gi1, "op": "add", "vlan": "30"}, trOut)
	want, werr = TrunkPlan("SW1", TrunkChange{Interface: gi1, Op: "add", Vlan: 30}, trOut)
	check("trunk", got, want, gerr, werr)

	sviOut := sviOuts(noIface, "Vlan1                  unassigned      YES unset  up                    down\n")
	d := "Servidores"
	got, gerr = plan("svi", Values{"vlan": "99", "description": d, "address": "10.9.9.1", "mask": "255.255.255.0"}, sviOut)
	want, werr = SVIPlan("SW1", SVIChange{VlanID: 99, Description: &d, Address: "10.9.9.1", Mask: "255.255.255.0"}, sviOut)
	check("svi", got, want, gerr, werr)
	got, gerr = plan("svi", Values{"vlan": "99", "address": "10.9.9.1", "mask": "255.255.255.0"}, sviOut)
	want, werr = SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.9.9.1", Mask: "255.255.255.0"}, sviOut)
	check("svi sin descripción", got, want, gerr, werr)

	pOut := outsOf(map[string]string{gi1: cfgOf(gi1, "description Impresora", "switchport mode access"), gi2: cfgOf(gi2, "switchport mode access")})
	for _, c := range []string{showSwitchport(gi1), showSwitchport(gi2), showStatus(gi1), showStatus(gi2)} {
		pOut[c] = "Name: x\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n"
	}
	got, gerr = plan("descripcion", Values{"interfaces": gi1 + "," + gi2, "description": "Telefono"}, pOut)
	want, werr = PortsPlan("SW1", []string{gi1, gi2}, PortChange{Description: str("Telefono")}, pOut)
	check("descripcion", got, want, gerr, werr)
	got, gerr = plan("descripcion", Values{"interfaces": gi1, "remove": "true"}, pOut)
	want, werr = PortsPlan("SW1", []string{gi1}, PortChange{Description: str("")}, pOut)
	check("descripcion (quitar)", got, want, gerr, werr)
	if err := Validate(Plan{Function: Ports.Name, Devices: []DevicePlan{got}}, Ports); err != nil {
		t.Error(err)
	}

	// La descripción es una de dos: ponerla o quitarla, nunca las dos ni ninguna.
	tpl, _ := TemplateByID("descripcion")
	for _, v := range []Values{{"interfaces": gi1}, {"interfaces": gi1, "description": "x", "remove": "true"}} {
		if _, err := tpl.Plan("SW1", v, pOut); err == nil {
			t.Errorf("%v aceptado", v)
		}
	}
}

// Los rechazos de las funciones de siempre siguen valiendo a través de la plantilla.
func TestAdaptersKeepTheirRefusals(t *testing.T) {
	tpl, _ := TemplateByID("trunk")
	outs := trunkOuts(gi1, trunkCfg(gi1, "switchport mode access"), "Name: x\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n")
	if _, err := tpl.Plan("SW1", Values{"interface": gi1, "op": "add", "vlan": "30"}, outs); err == nil {
		t.Error("un puerto de acceso no es trunk")
	}
	if err := ValidateValues(tpl, Values{"interface": gi1, "op": "set", "vlan": "30"}); err == nil {
		t.Error("op set aceptada")
	}
	vt, _ := TemplateByID("vlan")
	for _, id := range []string{"1", "1003", "4095"} {
		if err := ValidateValues(vt, Values{"id": id}); err == nil {
			if _, err := vt.Plan("SW1", Values{"id": id}, withID(vlanOuts(vtpTransparent), 1, "")); err == nil {
				t.Errorf("VLAN %s aceptada", id)
			}
		}
	}
}
