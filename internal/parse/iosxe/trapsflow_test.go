package iosxe

import (
	"slices"
	"testing"
)

// Fixtures armadas a mano con el formato de la documentación de Cisco (sin validar en laboratorio).
const snmpHostsFixture = `snmp-server community pub RO
snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart
snmp-server enable traps config
snmp-server host 10.1.1.5 version 2c Zx9Secreta
snmp-server host 10.1.1.6 informs version 2c Otra udp-port 1162
snmp-server host 10.1.1.7 vrf Mgmt traps version 3 priv usr
snmp-server host 10.1.1.8 oldcomm
`

func TestParseSNMPHosts(t *testing.T) {
	hs, ok := ParseSNMPHosts(snmpHostsFixture)
	if !ok || len(hs) != 4 {
		t.Fatalf("%v %v", ok, hs)
	}
	want := []SNMPHost{{Addr: "10.1.1.5", Port: 162}, {Addr: "10.1.1.6", Port: 1162}, {Addr: "10.1.1.7", Port: 162}, {Addr: "10.1.1.8", Port: 162}}
	if !slices.Equal(hs, want) {
		t.Errorf("%+v", hs)
	}
	if _, ok := ParseSNMPHosts("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("salida con error leída como válida")
	}
}

func TestParseSNMPTraps(t *testing.T) {
	tr, ok := ParseSNMPTraps(snmpHostsFixture)
	if !ok || tr.All || !tr.HasSnmp("linkdown") || !tr.HasSnmp("coldstart") || !tr.HasSnmp("warmstart") || !tr.HasConfig() {
		t.Errorf("%+v %v", tr, ok)
	}
	tr, _ = ParseSNMPTraps("snmp-server enable traps snmp authentication\n")
	if tr.HasSnmp("linkdown") || !tr.HasSnmp("authentication") || tr.HasConfig() {
		t.Errorf("%+v", tr)
	}
	tr, _ = ParseSNMPTraps("snmp-server enable traps snmp\n") // sin argumentos: todos los de snmp
	if !tr.HasSnmp("linkup") || tr.HasConfig() {
		t.Errorf("%+v", tr)
	}
	tr, _ = ParseSNMPTraps("snmp-server enable traps\n") // todos
	if !tr.HasSnmp("linkdown") || !tr.HasConfig() {
		t.Errorf("%+v", tr)
	}
	if _, ok := ParseSNMPTraps("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("salida con error leída como válida")
	}
}

const flowFixture = `flow record MX-REC
 match ipv4 protocol
 collect counter bytes long
flow exporter OTRO
 destination 10.9.9.9
flow monitor MON2
 record MX-REC
`

func TestParseFlowObjects(t *testing.T) {
	f, ok := ParseFlowObjects(flowFixture)
	if !ok || !slices.Equal(f.Records, []string{"MX-REC"}) || !slices.Equal(f.Exporters, []string{"OTRO"}) || !slices.Equal(f.Monitors, []string{"MON2"}) {
		t.Errorf("%+v %v", f, ok)
	}
	if f, ok := ParseFlowObjects(""); !ok || len(f.Records) != 0 {
		t.Errorf("vacío: %+v %v", f, ok)
	}
	if _, ok := ParseFlowObjects("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("salida con error leída como válida")
	}
}
