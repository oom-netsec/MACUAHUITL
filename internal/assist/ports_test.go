package assist

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

const (
	gi1 = "GigabitEthernet1/0/1"
	gi2 = "GigabitEthernet1/0/2"
)

func cfgOf(name string, body ...string) string {
	return "Building configuration...\n\nCurrent configuration : 100 bytes\n!\ninterface " + name + "\n " + strings.Join(body, "\n ") + "\nend\n"
}

func str(s string) *string { return &s }
func yes(b bool) *bool     { return &b }

func vlanOut(id int) string {
	return fmt.Sprintf("VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n%d   VLAN%04d                         active    Gi1/0/1\n", id, id)
}

// withVlans completa una captura por interfaz con las salidas de show vlan id de las VLAN dadas.
func withVlans(m map[string]string, ids ...int) map[string]string {
	for _, id := range ids {
		m[showVlan(id)] = vlanOut(id)
	}
	return m
}

// outsOf indexa una captura {interfaz: running-config} por comando, como la entrega el servicio.
func outsOf(m map[string]string) map[string]string {
	out := map[string]string{}
	for n, t := range m {
		out[showCfg(n)] = t
	}
	return withVlans(out, 1, 20, 30, 120)
}

func captured() map[string]string {
	return outsOf(map[string]string{
		gi1: cfgOf(gi1, "description Impresora", "switchport access vlan 10", "switchport mode access", "switchport voice vlan 110", "shutdown"),
		gi2: cfgOf(gi2, "switchport mode access"), // sin VLAN, descripción ni shutdown
	})
}

func cfgOnly(m map[string]string) map[string]string {
	out := map[string]string{}
	for n, t := range m {
		out[showCfg(n)] = t
	}
	return withVlans(out, 1, 20, 30, 120)
}

func TestPortsPrePlansReadOnlyCommands(t *testing.T) {
	pre, err := PortsPre([]string{gi1, gi2}, PortChange{Vlan: 20, Voice: 120})
	want := []string{showCfg(gi1), showStatus(gi1), showSwitchport(gi1), showCfg(gi2), showStatus(gi2), showSwitchport(gi2), "show vlan id 20", "show vlan id 120"}
	if err != nil || strings.Join(pre, "|") != strings.Join(want, "|") {
		t.Fatalf("%v %v", pre, err)
	}
	for _, bad := range []string{"Port-channel1", "Vlan10", "Loopback0", gi1 + ".10", "Gi1/0/1, Gi1/0/2", "range Gi1/0/1", "GigabitEthernet1/0/1\nreload", ""} {
		if _, err := PortsPre([]string{bad}, PortChange{}); err == nil {
			t.Errorf("%q aceptada", bad)
		}
	}
	if _, err := PortsPre(nil, PortChange{}); err == nil {
		t.Error("sin interfaces")
	}
	if _, err := PortsPre([]string{gi1}, PortChange{Vlan: 4095}); err == nil {
		t.Error("VLAN fuera de rango")
	}
}

// Las escrituras distintas de una misma interfaz se deduplican; si Vlan y Voice son iguales, se verifica una vez.
func TestPortsPreDedupesInterfacesAndVlans(t *testing.T) {
	pre, err := PortsPre([]string{gi1, strings.ToLower(gi1), "Gi1/0/1", gi2}, PortChange{Vlan: 20, Voice: 20})
	if err != nil || len(pre) != 7 || pre[0] != showCfg(gi1) || pre[3] != showCfg(gi2) || pre[6] != "show vlan id 20" {
		t.Fatalf("%v %v", pre, err)
	}
	dp, err := PortsPlan("SW1", []string{gi1, "gi1/0/1", gi2}, PortChange{Vlan: 20}, captured())
	if err != nil || strings.Count(strings.Join(dp.Apply, "|"), "interface "+gi1) != 1 {
		t.Fatalf("%v %v", dp.Apply, err)
	}
}

func TestPortsPlanRollbackRestoresCapturedValues(t *testing.T) {
	ch := PortChange{Vlan: 20, Voice: 120, Description: str("Telefono"), Shutdown: yes(false)}
	dp, err := PortsPlan("SW1", []string{gi1, gi2}, ch, captured())
	if err != nil {
		t.Fatal(err)
	}
	wantApply := []string{"interface " + gi1, "switchport access vlan 20", "switchport voice vlan 120", "description Telefono", "no shutdown",
		"interface " + gi2, "switchport access vlan 20", "switchport voice vlan 120", "description Telefono", "no shutdown"}
	if strings.Join(dp.Apply, "|") != strings.Join(wantApply, "|") {
		t.Fatalf("Apply = %q", dp.Apply)
	}
	// La reversa sale del running-config capturado: valores exactos donde había, "no ..." donde no.
	// Ninguna de las dos tenía portfast: la reversa quita el que IOS agrega solo con la VLAN de voz.
	wantRoll := []string{"interface " + gi2, "no switchport access vlan", "no switchport voice vlan", "no spanning-tree portfast", "no description", "no shutdown",
		"interface " + gi1, "switchport access vlan 10", "switchport voice vlan 110", "no spanning-tree portfast", "description Impresora", "shutdown"}
	if strings.Join(dp.Rollback, "|") != strings.Join(wantRoll, "|") {
		t.Fatalf("Rollback = %q", dp.Rollback)
	}
	if len(dp.Pre) != 8 || len(dp.Post) != 4 || len(dp.Expect) != 12 || len(dp.Baseline) != 2 {
		t.Fatalf("pre=%d post=%d expect=%d base=%d", len(dp.Pre), len(dp.Post), len(dp.Expect), len(dp.Baseline))
	}
	if err := Validate(Plan{Function: "ports", Devices: []DevicePlan{dp}}, Ports); err != nil {
		t.Fatal(err)
	}
	// El Expect verifica el estado nuevo, no el viejo.
	after := map[string]string{"show running-config interface " + gi2: cfgOf(gi2, "switchport access vlan 20", "switchport voice vlan 120", "description Telefono"),
		showStatus(gi2): statusOut(gi2, "connected")}
	var forGi2 []Expect
	for _, e := range dp.Expect {
		if e.Command == "show running-config interface "+gi2 || e.Command == showStatus(gi2) {
			forGi2 = append(forGi2, e)
		}
	}
	if f := EvalExpect(forGi2, after); len(f) != 0 {
		t.Fatalf("estado nuevo rechazado: %v", f)
	}
	before := map[string]string{"show running-config interface " + gi2: captured()[showCfg(gi2)], showStatus(gi2): statusOut(gi2, "connected")}
	if f := EvalExpect(forGi2, before); len(f) == 0 {
		t.Fatal("el estado viejo pasó el Expect")
	}
}

func TestPortsPlanRejectsTrunkChannelAndRouted(t *testing.T) {
	for name, body := range map[string][]string{
		"trunk":          {"switchport mode trunk"},
		"trunk sin modo": {"switchport trunk allowed vlan 10,20"},
		"canal":          {"channel-group 1 mode active"},
		"ruteado":        {"no switchport", "ip address 10.0.0.1 255.255.255.0"},
	} {
		_, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, cfgOnly(map[string]string{gi1: cfgOf(gi1, body...)}))
		if !errors.Is(err, ErrPortRefused) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Una interfaz mala frena todo el plan, no solo ella.
	c := captured()
	c[showCfg(gi2)] = cfgOf(gi2, "switchport mode trunk")
	if _, err := PortsPlan("SW1", []string{gi1, gi2}, PortChange{Vlan: 20}, c); !errors.Is(err, ErrPortRefused) {
		t.Fatalf("err = %v", err)
	}
	for _, n := range []string{"Port-channel1", "Po1", "Vlan1"} {
		if _, err := PortsPlan("SW1", []string{n}, PortChange{Vlan: 20}, cfgOnly(map[string]string{n: cfgOf(n, "switchport mode access")})); err == nil {
			t.Errorf("%s aceptada", n)
		}
	}
}

func TestPortsPlanInputErrors(t *testing.T) {
	c := captured()
	cases := map[string]struct {
		ch  PortChange
		cap map[string]string
	}{
		"sin cambios":            {PortChange{}, c},
		"vlan fuera de rango":    {PortChange{Vlan: 4095}, c},
		"voz fuera de rango":     {PortChange{Voice: 5000}, c},
		"descripción con ?":      {PortChange{Description: str("a?b")}, c},
		"descripción larga":      {PortChange{Description: str(strings.Repeat("x", 300))}, c},
		"sin captura":            {PortChange{Vlan: 20}, withVlans(map[string]string{}, 20)},
		"captura no es interfaz": {PortChange{Vlan: 20}, withVlans(map[string]string{showCfg(gi1): "% Invalid input detected at '^' marker.\n", showCfg(gi2): c[showCfg(gi2)]}, 20)},
		// La reversa no podría restaurar una descripción con '?': el plan no se genera.
		"reversa imposible": {PortChange{Description: str("x")}, withVlans(map[string]string{showCfg(gi1): cfgOf(gi1, "description a?b"), showCfg(gi2): c[showCfg(gi2)]}, 20)},
	}
	for name, tc := range cases {
		if _, err := PortsPlan("SW1", []string{gi1, gi2}, tc.ch, tc.cap); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
	// Descripción vacía = quitarla, y la reversa la restaura.
	dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Description: str("")}, c)
	if err != nil || dp.Apply[1] != "no description" || dp.Rollback[1] != "description Impresora" {
		t.Fatalf("%+v %v", dp, err)
	}
}

func statusOut(port, st string) string {
	return "Port      Name               Status       Vlan       Duplex  Speed Type\n" +
		fmt.Sprintf("%-9s %-18s %-12s %-10s a-full  a-1000 10/100/1000BaseTX\n", iosxe.ShortIf(port), "Telefono", st, "20")
}

// Hallazgo 2: se exige un puerto de acceso; los ruteados sin "no switchport" y los de administración se rechazan.
func TestPortsPlanRequiresAccessPort(t *testing.T) {
	for name, body := range map[string][]string{
		"mgmt vrf":        {"vrf forwarding Mgmt-vrf", "ip address 10.1.1.2 255.255.255.0"},
		"router nat":      {"ip address 192.0.2.1 255.255.255.0", "ip nat outside"},
		"solo ip address": {"ip address 192.0.2.1 255.255.255.0"},
		"acceso con ip":   {"switchport mode access", "ip address 192.0.2.1 255.255.255.0"},
		"acceso con vrf":  {"switchport mode access", "vrf forwarding X"},
		"dynamic auto":    {"switchport mode dynamic auto"},
		"sin modo":        {"description algo"},
		"vlan dinámica":   {"switchport mode access", "switchport access vlan dynamic"},
	} {
		_, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, cfgOnly(map[string]string{gi1: cfgOf(gi1, body...)}))
		if !errors.Is(err, ErrPortRefused) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Sin modo en la captura, show interfaces X switchport con static access lo acepta; con dynamic auto no.
	o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "description algo")})
	o[showSwitchport(gi1)] = "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\n"
	if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, o); err != nil {
		t.Errorf("static access: %v", err)
	}
	o[showSwitchport(gi1)] = "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: dynamic auto\n"
	if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, o); !errors.Is(err, ErrPortRefused) {
		t.Errorf("dynamic auto: %v", err)
	}
}

// Hallazgo 3: la VLAN de voz dot1p/untagged/none se restaura tal cual.
func TestPortsPlanRollbackKeepsVoiceVlanKeyword(t *testing.T) {
	for _, v := range []string{"dot1p", "untagged", "none"} {
		o := cfgOnly(map[string]string{gi1: cfgOf(gi1, "switchport mode access", "switchport voice vlan "+v)})
		dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Voice: 120}, o)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if dp.Rollback[1] != "switchport voice vlan "+v {
			t.Errorf("%s: reversa %q", v, dp.Rollback)
		}
	}
}

// Hallazgo 4: la VLAN 1 es el valor por defecto y IOS no muestra la línea.
func TestPortsPlanVlan1ExpectsNoAccessVlanLine(t *testing.T) {
	dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 1}, captured())
	if err != nil {
		t.Fatal(err)
	}
	cfg := showCfg(gi1)
	var ex []Expect
	for _, e := range dp.Expect {
		if e.Command == cfg {
			ex = append(ex, e)
		}
	}
	// El equipo, ya en VLAN 1, no muestra la línea: pasa. Si siguiera en la 10, falla.
	if f := EvalExpect(ex, map[string]string{cfg: cfgOf(gi1, "switchport mode access")}); len(f) != 0 {
		t.Fatalf("VLAN 1 rechazada: %v", f)
	}
	if f := EvalExpect(ex, map[string]string{cfg: cfgOf(gi1, "switchport mode access", "switchport access vlan 10")}); len(f) == 0 {
		t.Fatal("el puerto siguió en VLAN 10 y pasó")
	}
	// Reversa hacia VLAN 1 (el puerto estaba sin la línea): se quita la línea.
	dp, err = PortsPlan("SW1", []string{gi2}, PortChange{Vlan: 20}, captured())
	if err != nil || dp.Rollback[1] != "no switchport access vlan" {
		t.Fatalf("%v %v", dp.Rollback, err)
	}
}

// Hallazgo 5: una VLAN inexistente se rechaza antes de planear; el estado del puerto se evalúa.
func TestPortsPlanRejectsMissingVlan(t *testing.T) {
	o := captured()
	o[showVlan(99)] = "VLAN id 99 not found in current VLAN database\n"
	_, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 99}, o)
	if !errors.Is(err, ErrPortRefused) || !strings.Contains(err.Error(), "no existe") {
		t.Fatalf("err = %v", err)
	}
	o[showVlan(98)] = "98   VLAN0098                         suspend   \n"
	if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Voice: 98}, o); !errors.Is(err, ErrPortRefused) {
		t.Fatalf("VLAN suspendida: %v", err)
	}
	if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 77}, captured()); err == nil {
		t.Fatal("sin la salida de show vlan id")
	}
}

func TestPortsPlanExpectsPortNotInactiveNorErrDisabled(t *testing.T) {
	dp, err := PortsPlan("SW1", []string{gi1}, PortChange{Vlan: 20}, captured())
	if err != nil {
		t.Fatal(err)
	}
	if !contains(dp.Post, showStatus(gi1)) {
		t.Fatalf("Post sin el estado: %v", dp.Post)
	}
	cfg := showCfg(gi1)
	good := map[string]string{cfg: cfgOf(gi1, "switchport mode access", "switchport access vlan 20"), showStatus(gi1): statusOut(gi1, "notconnect")}
	if f := EvalExpect(dp.Expect, good); len(f) != 0 {
		t.Fatalf("notconnect debe pasar: %v", f)
	}
	for _, st := range []string{"inactive", "err-disabled"} {
		bad := map[string]string{cfg: good[cfg], showStatus(gi1): statusOut(gi1, st)}
		if f := EvalExpect(dp.Expect, bad); len(f) != 1 || !strings.Contains(f[0], st) {
			t.Errorf("%s: %v", st, f)
		}
	}
	// Un nombre de puerto con la palabra "inactive" no confunde: se lee la columna Status.
	tricky := "Port      Name               Status       Vlan       Duplex  Speed Type\nGi1/0/1   inactive           connected    20         a-full  a-1000 10/100/1000BaseTX\n"
	if f := EvalExpect(dp.Expect, map[string]string{cfg: good[cfg], showStatus(gi1): tricky}); len(f) != 0 {
		t.Fatalf("descripción inactive: %v", f)
	}
	if f := EvalExpect(dp.Expect, map[string]string{cfg: good[cfg], showStatus(gi1): "% Invalid input detected at '^' marker.\n"}); len(f) == 0 {
		t.Fatal("sin tabla de estado no puede pasar")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// QA 3560CX: IOS agrega solo «spanning-tree portfast edge» al poner la VLAN de voz y no lo quita al quitarla; la reversa lo quita.
func TestPortsPlanVoiceRollbackRemovesAutoPortfast(t *testing.T) {
	o := cfgOnly(map[string]string{gi2: cfgOf(gi2, "switchport mode access")})
	dp, err := PortsPlan("SW1", []string{gi2}, PortChange{Voice: 120}, o)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"interface " + gi2, "no switchport voice vlan", "no spanning-tree portfast"}; strings.Join(dp.Rollback, "|") != strings.Join(want, "|") {
		t.Fatalf("reversa %q", dp.Rollback)
	}
	// Con portfast en la línea base, o sin tocar la voz, la reversa no toca spanning-tree.
	for name, c := range map[string]struct {
		cfg string
		ch  PortChange
	}{
		"portfast previo": {cfgOf(gi2, "switchport mode access", "spanning-tree portfast edge"), PortChange{Voice: 120}},
		"portfast viejo":  {cfgOf(gi2, "switchport mode access", "spanning-tree portfast"), PortChange{Voice: 120}},
		"sin voz":         {cfgOf(gi2, "switchport mode access"), PortChange{Vlan: 20}},
	} {
		dp, err := PortsPlan("SW1", []string{gi2}, c.ch, cfgOnly(map[string]string{gi2: c.cfg}))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(strings.Join(dp.Rollback, "|"), "spanning-tree") {
			t.Errorf("%s: reversa %q", name, dp.Rollback)
		}
	}
	// Solo esa línea exacta: nada más de spanning-tree pasa la lista cerrada.
	for _, l := range []string{"no spanning-tree portfast bpduguard", "spanning-tree portfast", "no spanning-tree bpduguard"} {
		p := okPlan()
		p.Devices[0].Rollback = append(p.Devices[0].Rollback, l)
		if err := Validate(p, Ports); err == nil {
			t.Errorf("%q aceptada", l)
		}
	}
}
