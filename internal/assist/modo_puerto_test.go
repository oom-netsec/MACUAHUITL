package assist

import (
	"slices"
	"strings"
	"testing"
)

// Modelo de IOS sin validar en laboratorio: dynamic auto es el valor de fábrica y no sale en el running-config (ni aun escrito a mano);
// access y dynamic desirable sí salen como «switchport mode ...».

func modoRT(t *testing.T, mode string, cfg []string) (DevicePlan, *iosDev) {
	t.Helper()
	dev := newDev(map[string][]string{gi1: cfg})
	return roundTrip(t, "modo-puerto", Values{"interfaces": gi1, "mode": mode}, dev), dev
}

func TestModoPuertoApplyAndRollbackPerMode(t *testing.T) {
	for name, c := range map[string]struct {
		mode  string
		cfg   []string
		apply string
		back  string
	}{
		"fábrica a access":    {"access", []string{"description x"}, "switchport mode access", "no switchport mode"},
		"fábrica a desirable": {"dynamic desirable", nil, "switchport mode dynamic desirable", "no switchport mode"},
		"access a auto":       {"dynamic auto", accessGi(), "switchport mode dynamic auto", "switchport mode access"},
		"access a desirable":  {"dynamic desirable", accessGi(), "switchport mode dynamic desirable", "switchport mode access"},
		"desirable a access":  {"access", []string{"switchport mode dynamic desirable"}, "switchport mode access", "switchport mode dynamic desirable"},
		"desirable a auto":    {"dynamic auto", []string{"switchport mode dynamic desirable"}, "switchport mode dynamic auto", "switchport mode dynamic desirable"},
		"access a fábrica":    {"fabrica", accessGi(), "no switchport mode", "switchport mode access"},
		"desirable a fábrica": {"fabrica", []string{"switchport mode dynamic desirable"}, "no switchport mode", "switchport mode dynamic desirable"},
	} {
		dp, _ := modoRT(t, c.mode, c.cfg)
		if want := "interface " + gi1 + "|" + c.apply; joined(dp.Apply) != want {
			t.Errorf("%s: apply = %q", name, dp.Apply)
		}
		if want := "interface " + gi1 + "|" + c.back; joined(dp.Rollback) != want {
			t.Errorf("%s: rollback = %q", name, dp.Rollback)
		}
		if len(dp.Expect) == 0 {
			t.Errorf("%s: sin Expect", name)
		}
	}
}

// El Expect distingue el modo pedido del contrario sobre la salida de Post.
func TestModoPuertoExpects(t *testing.T) {
	dp, _ := modoRT(t, "access", []string{"description x"})
	if f := EvalExpect(dp.Expect, map[string]string{showCfg(gi1): cfgOf(gi1, "description x")}); len(f) == 0 {
		t.Error("access sin la línea debería fallar")
	}
	dp, _ = modoRT(t, "dynamic auto", accessGi())
	sw := func(admin string) map[string]string {
		return map[string]string{showCfg(gi1): cfgOf(gi1), showSwitchportMode(gi1): "Administrative Mode: " + admin + "\nOperational Mode: down\n"}
	}
	if f := EvalExpect(dp.Expect, sw("dynamic auto")); len(f) != 0 {
		t.Errorf("auto: %v", f)
	}
	if f := EvalExpect(dp.Expect, sw("static access")); len(f) == 0 {
		t.Error("auto con el puerto aún en acceso debería fallar")
	}
	if !slices.Contains(dp.Post, showSwitchportMode(gi1)) || slices.Contains(dp.Post, showSwitchport(gi1)) {
		t.Errorf("Post debe leer el switchport: %v", dp.Post)
	}
	dp, _ = modoRT(t, "fabrica", accessGi())
	bad := map[string]string{showCfg(gi1): cfgOf(gi1, "switchport mode access"), showSwitchportMode(gi1): "Administrative Mode: dynamic auto\nOperational Mode: down\n"}
	if f := EvalExpect(dp.Expect, bad); len(f) == 0 {
		t.Error("fábrica con la línea todavía en el running debería fallar")
	}
}

// Un puerto dynamic lleva su switchport en la línea base (DTP no toca el running); uno en access no.
func TestModoPuertoBaselinesSwitchportOnlyForDynamic(t *testing.T) {
	dp, _ := modoRT(t, "access", nil)
	if _, ok := dp.Baseline[showSwitchport(gi1)]; !ok {
		t.Error("dynamic: falta el switchport en la línea base")
	}
	dp, _ = modoRT(t, "dynamic desirable", accessGi())
	if _, ok := dp.Baseline[showSwitchport(gi1)]; ok {
		t.Error("access: no debería llevar el switchport en la línea base")
	}
}

func TestModoPuertoSkipsPortsAlreadyInMode(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi(), gi2: {"description x"}})
	dp := roundTrip(t, "modo-puerto", Values{"interfaces": gi1 + "," + gi2, "mode": "access"}, dev)
	if joined(dp.Apply) != "interface "+gi2+"|switchport mode access" {
		t.Errorf("apply = %q", dp.Apply)
	}
	if n := strings.Join(dp.Notes, "\n"); !strings.Contains(n, "ya estaba") || !strings.Contains(n, gi1) || strings.Contains(strings.ReplaceAll(n, gi1, ""), gi2+": ya") {
		t.Errorf("notas = %q", dp.Notes)
	}
	// Dynamic auto de fábrica pedido como dynamic auto: nada que hacer en ese puerto; todos iguales: no hay plan.
	for _, mode := range []string{"dynamic auto", "fabrica"} {
		if _, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": mode}, newDev(map[string][]string{gi1: {"description x"}})); err == nil {
			t.Errorf("%s sobre un puerto de fábrica no cambia nada", mode)
		}
	}
	// Un dynamic auto que el running sí muestre se quita con fabrica y la reversa lo restaura tal cual (el modelo de iosDev no lo muestra jamás: solo se planea).
	dp, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": "fabrica"}, newDev(map[string][]string{gi1: {"switchport mode dynamic auto"}}))
	if err != nil || joined(dp.Apply) != "interface "+gi1+"|no switchport mode" || joined(dp.Rollback) != "interface "+gi1+"|switchport mode dynamic auto" {
		t.Errorf("fabrica sobre dynamic auto explícito: %v %+v", err, dp)
	}
}

func TestModoPuertoRefusals(t *testing.T) {
	v := Values{"interfaces": gi1, "mode": "access"}
	for name, cfg := range map[string][]string{
		"trunk":              {"switchport mode trunk"},
		"líneas trunk":       {"switchport trunk allowed vlan 10", "switchport mode access"},
		"canal":              accessGi("channel-group 1 mode active"),
		"ruteado":            {"no switchport", "ip address 10.0.0.1 255.255.255.0"},
		"capa 3":             {"ip address 10.0.0.1 255.255.255.0"},
		"private-vlan":       {"switchport mode private-vlan host"},
		"private-vlan línea": {"switchport private-vlan host-association 100 101"},
		"túnel":              {"switchport mode dot1q-tunnel"},
	} {
		wantRefused(t, name, "modo-puerto", v, newDev(map[string][]string{gi1: cfg}))
	}
	wantRefused(t, "inexistente", "modo-puerto", v, newDev(map[string][]string{gi2: accessGi()}))
	// dynamic que opera como trunk: cambiarlo corta tráfico, también si ya estuviera en el modo pedido.
	for _, mode := range []string{"access", "dynamic desirable", "dynamic auto"} {
		dev := newDev(map[string][]string{gi1: nil})
		dev.oper = map[string]string{gi1: "trunk"}
		wantRefused(t, "dynamic operando como trunk -> "+mode, "modo-puerto", Values{"interfaces": gi1, "mode": mode}, dev)
		if _, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": mode}, dev); err == nil || !strings.Contains(err.Error(), "opera como trunk") {
			t.Errorf("el motivo debe decir que opera como trunk: %v", err)
		}
	}
	dev := newDev(map[string][]string{gi1: nil})
	dev.oper = map[string]string{gi1: "private-vlan host"}
	wantRefused(t, "dynamic con otro modo operativo", "modo-puerto", v, dev)
	// Sin línea de modo y con otro modo administrativo, la reversa no sabría restaurarlo.
	tpl, _ := TemplateByID("modo-puerto")
	pre, _ := tpl.Pre(v)
	for name, sw := range map[string]string{
		"static access sin línea": switchportOut("static access", "down"),
		"sin switchport":          "% Invalid input\n",
		"dynamic sin oper":        "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: dynamic auto\n",
	} {
		outs := newDev(map[string][]string{gi1: {"description x"}}).read(pre)
		outs[showSwitchport(gi1)] = sw
		if _, err := tpl.Plan("SW1", v, outs); err == nil || !strings.Contains(err.Error(), ErrSnippetRefused.Error()) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestModoPuertoNeverAllowsTrunk(t *testing.T) {
	for _, l := range []string{"switchport mode trunk", "switchport mode dynamic", "switchport mode dot1q-tunnel", "switchport mode private-vlan host", "switchport nonegotiate",
		"no switchport mode access", "no switchport mode trunk", "no switchport", "switchport", "interface Port-channel1", "interface Gi1/0/1 Gi1/0/2", "shutdown", "switchport mode"} {
		if err := SnippetPortMode.configLine(l); err == nil {
			t.Errorf("aceptó %q", l)
		}
	}
	for _, l := range []string{"interface " + gi1, "switchport mode access", "switchport mode dynamic auto", "switchport mode dynamic desirable", "no switchport mode"} {
		if err := SnippetPortMode.configLine(l); err != nil {
			t.Errorf("rechazó %q: %v", l, err)
		}
	}
}

func TestModoPuertoCheckDeviceRejectsATornReversa(t *testing.T) {
	dev := newDev(map[string][]string{gi1: accessGi(), gi2: {"switchport mode dynamic desirable"}})
	good, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1 + "," + gi2, "mode": "dynamic auto"}, dev)
	if err != nil {
		t.Fatal(err)
	}
	check := func(d DevicePlan) error {
		return Validate(Plan{Function: SnippetPortMode.Name, Devices: []DevicePlan{d}}, SnippetPortMode)
	}
	if err := check(good); err != nil {
		t.Fatalf("el plan bueno no valida: %v", err)
	}
	for name, mod := range map[string]func(d *DevicePlan){
		"no restaura lo capturado": func(d *DevicePlan) {
			d.Rollback[slices.Index(d.Rollback, "switchport mode access")] = "switchport mode dynamic auto"
		},
		"manda no donde había modo": func(d *DevicePlan) {
			d.Rollback[slices.Index(d.Rollback, "switchport mode access")] = "no switchport mode"
		},
		"restaura donde no había":  func(d *DevicePlan) { d.Rollback = append(d.Rollback, "switchport mode access") },
		"otro puerto primero":      func(d *DevicePlan) { d.Rollback[0] = "interface " + gi1 },
		"sin reversa de un puerto": func(d *DevicePlan) { d.Rollback = d.Rollback[:2] },
	} {
		d := good
		d.Apply, d.Rollback = slices.Clone(good.Apply), slices.Clone(good.Rollback)
		mod(&d)
		if err := check(d); err == nil {
			t.Errorf("%s: la reversa torcida pasó Validate", name)
		}
	}
	// Sin línea que restaurar, la reversa debe ser exactamente «no switchport mode».
	d := good
	d.Rollback = slices.Clone(good.Rollback)
	d.Baseline = map[string]string{showCfg(gi1): cfgOf(gi1, "switchport mode access"), showCfg(gi2): cfgOf(gi2)}
	if err := check(d); err == nil {
		t.Error("la línea base dice que gi2 no tenía modo y la reversa le restaura uno")
	}
}

func TestModoPuertoNotesWarnAboutDTP(t *testing.T) {
	dp, _ := modoRT(t, "dynamic desirable", accessGi())
	if n := strings.Join(dp.Notes, " "); !strings.Contains(n, "DTP") || !strings.Contains(n, "trunk") {
		t.Errorf("notas = %q", dp.Notes)
	}
}

func TestModoPuertoFieldsAndCatalog(t *testing.T) {
	tpl, ok := TemplateByID("modo-puerto")
	if !ok || tpl.Tech != "l2" || tpl.Name != "Modo del puerto (acceso o dinámico)" {
		t.Fatalf("plantilla = %+v", tpl)
	}
	var mode Field
	for _, f := range tpl.Fields {
		if f.Name == "mode" {
			mode = f
		}
		if f.Name == "interfaces" && (f.Type != TypeInterfaces || !f.Required) {
			t.Errorf("interfaces = %+v", f)
		}
	}
	if !slices.Equal(mode.Choices, []string{"access", "dynamic auto", "dynamic desirable", "fabrica"}) || !mode.Required {
		t.Errorf("mode = %+v", mode)
	}
	for _, bad := range []string{"trunk", "dynamic", "ACCESS"} {
		if err := ValidateValues(tpl, Values{"interfaces": gi1, "mode": bad}); err == nil {
			t.Errorf("mode=%s pasó la validación", bad)
		}
	}
}

// IOS rechaza el modo dynamic en un puerto con nonegotiate, port-security o autenticación de puerto: se detecta al planear, no a mitad del apply.
func TestModoPuertoDynamicRefusesIncompatibleLines(t *testing.T) {
	for _, l := range []string{"switchport nonegotiate", "switchport port-security", "switchport port-security maximum 2",
		"authentication port-control auto", "dot1x pae authenticator"} {
		for _, mode := range []string{"dynamic auto", "dynamic desirable", "fabrica"} {
			cfg := []string{"switchport mode access", l}
			dev := newDev(map[string][]string{gi1: cfg})
			_, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": mode}, dev)
			if err == nil || !strings.Contains(err.Error(), ErrSnippetRefused.Error()) || !strings.Contains(err.Error(), l) {
				t.Errorf("%s con %q: err = %v", mode, l, err)
			}
		}
		// Pasar a access sí se puede: lo que molesta es el modo dynamic.
		if _, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": "access"}, newDev(map[string][]string{gi1: {"description x", l}})); err != nil {
			t.Errorf("access con %q: %v", l, err)
		}
	}
}

// La reversa necesita la línea base del puerto para saber qué restaurar: sin ella (o ilegible) no pasa, ni siquiera «no switchport mode».
func TestModoPuertoCheckDeviceNeedsReadableBaseline(t *testing.T) {
	good, err := templatePlan(t, "modo-puerto", Values{"interfaces": gi1, "mode": "access"}, newDev(map[string][]string{gi1: {"description x"}}))
	if err != nil {
		t.Fatal(err)
	}
	check := func(d DevicePlan) error {
		return Validate(Plan{Function: SnippetPortMode.Name, Devices: []DevicePlan{d}}, SnippetPortMode)
	}
	if err := check(good); err != nil {
		t.Fatal(err)
	}
	for name, base := range map[string]map[string]string{
		"sin línea base":     {},
		"línea base nil":     nil,
		"captura ilegible":   {showCfg(gi1): "% Invalid input detected at '^' marker.\n"},
		"otra interfaz":      {showCfg(gi2): cfgOf(gi2)},
		"captura de otro if": {showCfg(gi1): cfgOf(gi2)},
	} {
		d := good
		d.Baseline = base
		if err := check(d); err == nil {
			t.Errorf("%s: pasó Validate", name)
		}
	}
}
