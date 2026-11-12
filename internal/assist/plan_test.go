package assist

import (
	"errors"
	"strings"
	"testing"
)

func okPlan() Plan {
	return Plan{Function: "ports", Devices: []DevicePlan{{
		Device:   "SW1",
		Pre:      []string{"show running-config interface GigabitEthernet1/0/1"},
		Apply:    []string{"interface GigabitEthernet1/0/1", "switchport access vlan 20"},
		Rollback: []string{"interface GigabitEthernet1/0/1", "switchport access vlan 10"},
		Post:     []string{"show running-config interface GigabitEthernet1/0/1"},
		Expect:   []Expect{{Command: "show running-config interface GigabitEthernet1/0/1", Line: "switchport access vlan 20", Present: true}},
	}}}
}

func TestValidateAcceptsCompletePlan(t *testing.T) {
	if err := Validate(okPlan(), Ports); err != nil {
		t.Fatal(err)
	}
}

// Regla 2: sin reversa (o con cualquier pieza faltante) el plan se rechaza.
func TestValidateRejectsIncompletePlan(t *testing.T) {
	cases := map[string]func(*DevicePlan){
		"sin reversa":          func(d *DevicePlan) { d.Rollback = nil },
		"reversa en blanco":    func(d *DevicePlan) { d.Rollback = []string{"  ", ""} },
		"sin pre":              func(d *DevicePlan) { d.Pre = nil },
		"sin post":             func(d *DevicePlan) { d.Post = nil },
		"sin expect":           func(d *DevicePlan) { d.Expect = nil },
		"sin apply":            func(d *DevicePlan) { d.Apply = nil },
		"expect fuera de post": func(d *DevicePlan) { d.Expect[0].Command = "show version" },
		"sin nombre":           func(d *DevicePlan) { d.Device = "" },
	}
	for name, mut := range cases {
		p := okPlan()
		mut(&p.Devices[0])
		if err := Validate(p, Ports); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := Validate(Plan{Function: "ports"}, Ports); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("sin equipos: %v", err)
	}
	p := okPlan()
	p.Function = "otra"
	if err := Validate(p, Ports); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("función distinta: %v", err)
	}
}

// Regla 3: lista cerrada por función, más una lista negra que gana aunque la lista permita.
func TestValidateClosedList(t *testing.T) {
	bad := []string{
		"snmp-server community x RO", "ip route 0.0.0.0 0.0.0.0 1.1.1.1", "interface Port-channel1",
		"interface Vlan1", "switchport access vlan 5000", "switchport access vlan abc",
		"switchport mode trunk", "SWITCHPORT TRUNK allowed vlan 1", "shutdown now", "switchport access vlans 20",
		"description a?b", "description x\nreload", "end", "exit", "do reload", "do show run", "configure terminal",
		"no switchport mode trunk", "no switchport mode access", "switchport mode", "switchport mode dynamic",
	}
	for _, l := range bad {
		p := okPlan()
		p.Devices[0].Apply = append(p.Devices[0].Apply, l)
		if err := Validate(p, Ports); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("Apply %q aceptada: %v", l, err)
		}
		p = okPlan()
		p.Devices[0].Rollback = append(p.Devices[0].Rollback, l)
		if err := Validate(p, Ports); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("Rollback %q aceptada: %v", l, err)
		}
	}
}

func TestDenyListWinsOverAllowList(t *testing.T) {
	deny := []string{"reload", "reload in 5", "write erase", "erase startup-config", "format flash:", "delete flash:x",
		"boot system flash:x.bin", "crypto key zeroize rsa", "no username admin", "no aaa new-model", "tclsh",
		"event manager applet X", "Reload", "  RELOAD  ", "rel", "wr er", "del flash:x", "no  username  x", "no aaa"}
	allowAll := Function{Name: "x", Allowed: append([]string{"reload", "write", "erase", "format", "delete", "boot", "crypto", "no", "tclsh", "event", "rel", "wr", "del"}, deny...)}
	for _, l := range deny {
		p := okPlan()
		p.Function = "x"
		p.Devices[0].Apply = []string{l}
		if err := Validate(p, allowAll); !errors.Is(err, ErrInvalidPlan) || !strings.Contains(err.Error(), "prohibid") {
			t.Errorf("%q: err = %v", l, err)
		}
	}
}

func TestValidateChecksPreAndPostAreReadOnly(t *testing.T) {
	for _, c := range []string{"configure terminal", "reload", "write memory", "show run | redirect flash:x", "copy run tftp:"} {
		p := okPlan()
		p.Devices[0].Pre = []string{c}
		if err := Validate(p, Ports); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("Pre %q aceptado", c)
		}
		p = okPlan()
		p.Devices[0].Post = []string{c}
		p.Devices[0].Expect[0].Command = c
		if err := Validate(p, Ports); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("Post %q aceptado", c)
		}
	}
}

func TestEvalExpect(t *testing.T) {
	out := map[string]string{"show x": "interface Gi1\n switchport access vlan 20\n description lab uno\n shutdown\n"}
	ok := []Expect{
		{Command: "show x", Line: "switchport access vlan 20", Present: true},
		{Command: "show x", Line: "description ", Prefix: true, Present: true},
		{Command: "show x", Line: "switchport voice vlan", Prefix: true, Present: false},
		{Command: "show x", Line: "no shutdown", Present: false},
	}
	if f := EvalExpect(ok, out); len(f) != 0 {
		t.Fatalf("fallas inesperadas: %v", f)
	}
	bad := []Expect{
		{Command: "show x", Line: "switchport access vlan 30", Present: true},
		{Command: "show x", Line: "shutdown", Present: false},
		{Command: "show x", Line: "description", Prefix: true, Present: false},
		{Command: "show y", Line: "x", Present: true}, // comando que no corrió
	}
	if f := EvalExpect(bad, out); len(f) != 4 {
		t.Fatalf("fallas = %v", f)
	}
}

// La lista de prefijos sola (sin Check) ya rechaza lo que no declara.
func TestAllowedPrefixesAloneRejectOthers(t *testing.T) {
	fn := Function{Name: "ports", Allowed: Ports.Allowed}
	for _, l := range []string{"snmp-server community x RO", "switchport access vlans 20", "interfaces Gi1"} {
		p := okPlan()
		p.Devices[0].Apply = []string{l}
		if err := Validate(p, fn); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%q aceptada", l)
		}
	}
}

// IOS con exec-character-bits 7 quita el bit alto: Í (C3 8D) llega como 'C' + CR y Ê (C3 8A) como LF.
// Toda línea con una runa fuera de 0x20-0x7e se rechaza, en las cuatro listas.
func TestValidateRejectsNonPrintableASCII(t *testing.T) {
	for _, bad := range []string{"description cafÍ", "description xÊ", "description x\r", "description x\ty", "description ñ", "description x\u007f", "description x\n"} {
		for name, mut := range map[string]func(*DevicePlan, string){
			"Apply":    func(d *DevicePlan, l string) { d.Apply = append(d.Apply, l) },
			"Rollback": func(d *DevicePlan, l string) { d.Rollback = append(d.Rollback, l) },
			"Pre":      func(d *DevicePlan, l string) { d.Pre = append(d.Pre, "show "+l) },
			"Post":     func(d *DevicePlan, l string) { d.Post = append(d.Post, "show "+l) },
		} {
			p := okPlan()
			mut(&p.Devices[0], bad)
			err := Validate(p, Ports)
			if !errors.Is(err, ErrInvalidPlan) || !strings.Contains(err.Error(), "fuera de ASCII imprimible") {
				t.Errorf("%s %q: err = %v", name, bad, err)
			}
		}
	}
}

func TestPortsPlanRejectsNonASCIIValues(t *testing.T) {
	for _, d := range []string{"Teléfono", "xÍ", "xÊ", "x\r"} {
		if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Description: str(d)}, captured()); err == nil {
			t.Errorf("descripción %q aceptada", d)
		}
	}
	// Una descripción previa no ASCII haría imposible una reversa segura.
	c := map[string]string{gi1: cfgOf(gi1, "description Teléfono")}
	if _, err := PortsPlan("SW1", []string{gi1}, PortChange{Description: str("ok")}, c); err == nil {
		t.Error("reversa con descripción no ASCII aceptada")
	}
}
