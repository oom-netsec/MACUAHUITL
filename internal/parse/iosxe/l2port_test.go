package iosxe

import (
	"reflect"
	"testing"
)

// Formato de show running-config interface X de la documentación de Cisco (IOS 15.2E e IOS-XE 17.x). Sin validar en laboratorio.
const l2PortSample = `Building configuration...

Current configuration : 400 bytes
!
interface GigabitEthernet1/0/5
 switchport access vlan 10
 switchport mode access
 switchport port-security maximum 3
 switchport port-security
 speed 100
 duplex full
 storm-control broadcast level 20.00 10.00
 storm-control multicast level bps 1m
 storm-control action trap
 storm-control action shutdown
 spanning-tree portfast edge
 spanning-tree bpduguard enable
end
`

func TestParseL2Port(t *testing.T) {
	c, ok := ParseInterfaceConfig(l2PortSample)
	if !ok {
		t.Fatal("no se leyó la interfaz")
	}
	got := ParseL2Port(c)
	want := L2Port{Speed: "100", Duplex: "full",
		Storm:        map[string]string{"broadcast": "level 20.00 10.00", "multicast": "level bps 1m"},
		StormActions: []string{"trap", "shutdown"}, HasPortfast: true, Portfast: "edge", Bpduguard: "enable",
		PortSecurity: []string{"switchport port-security maximum 3", "switchport port-security"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	// Sin nada de eso, todo queda vacío; `spanning-tree portfast` sin variante no es lo mismo que sin la línea.
	c, _ = ParseInterfaceConfig("interface Gi1/0/6\n spanning-tree portfast\n spanning-tree bpduguard disable\nend\n")
	got = ParseL2Port(c)
	if !got.HasPortfast || got.Portfast != "" || got.Bpduguard != "disable" || got.Speed != "" || len(got.Storm) != 0 || len(got.PortSecurity) != 0 {
		t.Fatalf("%+v", got)
	}
	// Lo que no cabe en la forma conocida se guarda entero para que la plantilla lo rechace, no se pierde.
	c, _ = ParseInterfaceConfig("interface Gi1/0/8\n speed auto 10 100\n duplex\n spanning-tree bpduguard\n storm-control action filter\nend\n")
	got = ParseL2Port(c)
	if got.Speed != "auto 10 100" || got.Bpduguard == "" || !reflect.DeepEqual(got.StormActions, []string{"filter"}) {
		t.Fatalf("%+v", got)
	}
	c, _ = ParseInterfaceConfig("interface Gi1/0/7\n switchport mode access\nend\n")
	if got = ParseL2Port(c); got.HasPortfast || got.Bpduguard != "" {
		t.Fatalf("%+v", got)
	}
}

func TestParseErrdisableRecovery(t *testing.T) {
	r, ok := ParseErrdisableRecovery("errdisable recovery cause bpduguard\nerrdisable recovery cause link-flap\nerrdisable recovery interval 600\n")
	if !ok || !reflect.DeepEqual(r.Causes, []string{"bpduguard", "link-flap"}) || r.Interval != "600" {
		t.Fatalf("%+v %v", r, ok)
	}
	// Sin coincidencias IOS no imprime nada: es un equipo sin recuperación, no una lectura fallida.
	if r, ok = ParseErrdisableRecovery(""); !ok || len(r.Causes) != 0 || r.Interval != "" {
		t.Fatalf("%+v %v", r, ok)
	}
	// Una causa que no conoce se toma como activa: el equipo no se rechaza por eso.
	r, ok = ParseErrdisableRecovery("errdisable recovery cause channel-misconfig (STP)\nerrdisable recovery cause udld\n")
	if !ok || len(r.Causes) != 2 || r.Causes[1] != "udld" {
		t.Fatalf("%+v %v", r, ok)
	}
	for _, bad := range []string{"% Invalid input detected at '^' marker.\n", "errdisable recovery cause\n", "errdisable recovery interval abc\n"} {
		if _, ok := ParseErrdisableRecovery(bad); ok {
			t.Errorf("%q aceptada", bad)
		}
	}
}
