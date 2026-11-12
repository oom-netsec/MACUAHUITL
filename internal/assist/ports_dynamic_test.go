package assist

import (
	"errors"
	"strings"
	"testing"
)

// switchportOut imita show interfaces X switchport (forma de IOS 15.2 en Catalyst 3560CX).
func switchportOut(admin, oper string) string {
	return "Name: Gi0/11\nSwitchport: Enabled\nAdministrative Mode: " + admin + "\nOperational Mode: " + oper + "\nAdministrative Trunking Encapsulation: negotiate\nNegotiation of Trunking: On\nAccess Mode VLAN: 1 (default)\n"
}

// Un puerto dynamic auto/desirable que no está en troncal se pasa a acceso, y la reversa lo deja como estaba.
func TestPortsPlanDynamicPortBecomesAccess(t *testing.T) {
	for name, c := range map[string]struct {
		cfg        []string // líneas de la captura (el dynamic auto de fábrica no aparece en el running-config)
		admin      string
		oper       string
		wantRevert string
	}{
		"auto de fábrica, caído":       {[]string{"description libre"}, "dynamic auto", "down", "no switchport mode"},
		"auto de fábrica, acceso":      {[]string{"description libre"}, "dynamic auto", "static access", "no switchport mode"},
		"desirable explícito, acceso":  {[]string{"switchport mode dynamic desirable"}, "dynamic desirable", "static access", "switchport mode dynamic desirable"},
		"auto explícito en la captura": {[]string{"switchport mode dynamic auto"}, "dynamic auto", "down", "switchport mode dynamic auto"},
	} {
		o := cfgOnly(map[string]string{gi1: cfgOf(gi1, c.cfg...)})
		o[showSwitchport(gi1)] = switchportOut(c.admin, c.oper)
		dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, o)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := []string{"interface " + gi1, "switchport mode access", "switchport access vlan 20"}; strings.Join(dp.Apply, "|") != strings.Join(want, "|") {
			t.Errorf("%s: apply = %q", name, dp.Apply)
		}
		if want := []string{"interface " + gi1, "no switchport access vlan", c.wantRevert}; strings.Join(dp.Rollback, "|") != strings.Join(want, "|") {
			t.Errorf("%s: rollback = %q", name, dp.Rollback)
		}
		var ex []Expect
		for _, e := range dp.Expect {
			if e.Line == "switchport mode access" && e.Present && e.Command == showCfg(gi1) {
				ex = append(ex, e)
			}
		}
		if len(ex) != 1 {
			t.Fatalf("%s: falta el Expect de switchport mode access: %+v", name, dp.Expect)
		}
		if f := EvalExpect(ex, map[string]string{showCfg(gi1): cfgOf(gi1, "switchport mode access")}); len(f) != 0 {
			t.Errorf("%s: %v", name, f)
		}
		if f := EvalExpect(ex, map[string]string{showCfg(gi1): cfgOf(gi1, "description libre")}); len(f) == 0 {
			t.Errorf("%s: sin la línea debería fallar", name)
		}
	}
}

// Si el puerto negoció troncal (o no se sabe), no se toca: cambiarlo podría cortar tráfico.
func TestPortsPlanDynamicPortOperationalTrunkRefused(t *testing.T) {
	for name, sw := range map[string]string{
		"auto, trunk":      switchportOut("dynamic auto", "trunk"),
		"desirable, trunk": switchportOut("dynamic desirable", "trunk"),
		"auto, sin oper":   "Name: Gi0/11\nSwitchport: Enabled\nAdministrative Mode: dynamic auto\n",
		"auto, oper raro":  switchportOut("dynamic auto", "private-vlan host"),
	} {
		o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "description libre")})
		o[showSwitchport(gi1)] = sw
		_, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, o)
		if !errors.Is(err, ErrPortRefused) {
			t.Errorf("%s: err = %v", name, err)
		} else if want := map[string]string{"auto, trunk": "negoció", "desirable, trunk": "negoció", "auto, sin oper": "Operational Mode",
			"auto, oper raro": "private-vlan host"}[name]; !strings.Contains(err.Error(), want) {
			t.Errorf("%s: el mensaje no da el motivo (%q): %v", name, want, err)
		}
	}
}

// El static access sigue igual: ni switchport mode access en el apply ni modo que restaurar.
func TestPortsPlanStaticAccessUnchangedByDynamicSupport(t *testing.T) {
	o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "description libre")})
	o[showSwitchport(gi1)] = switchportOut("static access", "static access")
	dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dp.Apply, "|") != "interface "+gi1+"|switchport access vlan 20" || strings.Join(dp.Rollback, "|") != "interface "+gi1+"|no switchport access vlan" {
		t.Errorf("apply %q rollback %q", dp.Apply, dp.Rollback)
	}
}

// Un modo administrativo que no es dynamic (trunk, private-vlan) se rechaza aunque el puerto esté caído.
func TestPortsPlanNonDynamicAdminRefusedEvenIfDown(t *testing.T) {
	for _, admin := range []string{"trunk", "private-vlan host"} {
		o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "description libre")})
		o[showSwitchport(gi1)] = switchportOut(admin, "down")
		if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, o); !errors.Is(err, ErrPortRefused) {
			t.Errorf("%s: err = %v", admin, err)
		}
	}
}

// El modo operativo de un puerto dynamic entra en la línea base: si entre el plan y el aplicar un vecino
// negocia un trunk (DTP no cambia el running-config), el motor ve el cambio y no aplica nada.
// Un puerto en static access no lo necesita y no lo lleva (su enlace puede subir o bajar sin afectar el plan).
func TestPortsPlanDynamicPortBaselinesSwitchport(t *testing.T) {
	o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "description libre"), gi2: cfgOf(gi2, "switchport mode access")})
	o[showSwitchport(gi1)] = switchportOut("dynamic auto", "down")
	o[showSwitchport(gi2)] = switchportOut("static access", "static access")
	dp, err := PortsPlan("SW1", []string{gi1, gi2}, PortChange{Vlan: 20}, o)
	if err != nil {
		t.Fatal(err)
	}
	if dp.Baseline[showSwitchport(gi1)] != o[showSwitchport(gi1)] {
		t.Errorf("falta show interfaces switchport de %s en la línea base: %v", gi1, dp.Baseline)
	}
	if _, ok := dp.Baseline[showSwitchport(gi2)]; ok {
		t.Errorf("%s ya es de acceso y no debería llevar su switchport en la línea base", gi2)
	}
	if want := []string{"interface " + gi1, "switchport mode access", "switchport access vlan 20", "interface " + gi2, "switchport access vlan 20"}; strings.Join(dp.Apply, "|") != strings.Join(want, "|") {
		t.Errorf("apply = %q", dp.Apply)
	}
}

// Descripción o shut/no shut en un puerto dynamic no cambian su modo: ni switchport mode en el apply ni en la reversa,
// ni su switchport en la línea base. Con VLAN de acceso o de voz sí se pasa a acceso.
func TestPortsPlanDynamicPortKeepsModeWithoutVlan(t *testing.T) {
	for name, c := range map[string]struct {
		ch         PortChange
		wantAccess bool
	}{
		"descripción":     {PortChange{Description: str("uplink")}, false},
		"quitar descrip.": {PortChange{Description: str("")}, false},
		"shutdown":        {PortChange{Shutdown: yes(true)}, false},
		"no shutdown":     {PortChange{Shutdown: yes(false)}, false},
		"VLAN de acceso":  {PortChange{Vlan: 20}, true},
		"VLAN de voz":     {PortChange{Voice: 120}, true},
	} {
		o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "description libre")})
		o[showSwitchport(gi1)] = switchportOut("dynamic auto", "down")
		dp, err := PortsPlan("SW1", []string{gi1}, c.ch, o)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got := strings.Contains(joined(dp.Apply), "switchport mode")
		if got != c.wantAccess || strings.Contains(joined(dp.Rollback), "switchport mode") != c.wantAccess {
			t.Errorf("%s: apply %q rollback %q (¿modo? %v)", name, dp.Apply, dp.Rollback, c.wantAccess)
		}
		if _, ok := dp.Baseline[showSwitchport(gi1)]; ok != c.wantAccess {
			t.Errorf("%s: línea base del switchport = %v, esperaba %v", name, ok, c.wantAccess)
		}
		for _, e := range dp.Expect {
			if strings.HasPrefix(e.Line, "switchport mode") && !c.wantAccess {
				t.Errorf("%s: Expect de modo sin cambiar el modo: %+v", name, e)
			}
		}
	}
}
