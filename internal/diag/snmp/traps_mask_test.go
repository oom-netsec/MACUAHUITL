package snmp

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Un trap con el texto de un syslog (clogHistMsgText) sale enmascarado en todas las salidas.
func TestTrapTextoSyslogEnmascarado(t *testing.T) {
	msg := "User:admin  logged command:username backup privilege 15 secret Cl4veTrap99"
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "c"}
	pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "c", PDUType: gosnmp.SNMPv2Trap, Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)},
		{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.9.41.2.0.1"},
		{Name: ".1.3.6.1.4.1.9.9.41.1.2.3.1.5.77", Type: gosnmp.OctetString, Value: []byte(msg)},
	}}
	b, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := decodeTrap(x, b)
	for _, f := range []string{"texto", "crudo", "jsonl"} {
		line := string(tr.Line(f))
		t.Logf("%s: %s", f, line)
		if strings.Contains(line, "Cl4veTrap99") {
			t.Errorf("secreto en claro en formato %s", f)
		}
	}
}

// Un byte que no es UTF-8 en el texto hace que el valor salga en hex: el secreto tampoco queda ahí (decodificable).
func TestTrapTextoNoUTF8Enmascarado(t *testing.T) {
	msg := "logged command:username backup privilege 15 secret Cl4veTrap99 description caf\xe9"
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "c"}
	pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "c", PDUType: gosnmp.SNMPv2Trap, Variables: []gosnmp.SnmpPDU{
		{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.9.41.2.0.1"},
		{Name: ".1.3.6.1.4.1.9.9.41.1.2.3.1.5.77", Type: gosnmp.OctetString, Value: []byte(msg)},
	}}
	b, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := decodeTrap(x, b)
	for _, f := range []string{"texto", "crudo", "jsonl"} {
		line := string(tr.Line(f))
		if strings.Contains(line, "Cl4veTrap99") || strings.Contains(line, hex.EncodeToString([]byte("Cl4veTrap99"))) {
			t.Errorf("secreto (o su hex) en formato %s: %s", f, line)
		}
	}
}

// Un valor binario (la MAC de port-security, BITS) no se toca: el enmascarado solo cambia algo si de verdad tapa un secreto.
func TestTrapBinarioIntacto(t *testing.T) {
	mac := []byte{0x00, 0x0a, 0x20, 0x01, 0x02, 0x03}
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "c"}
	pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "c", PDUType: gosnmp.SNMPv2Trap, Variables: []gosnmp.SnmpPDU{
		{Name: oidSnmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.9.315.0.0.1"},
		{Name: ".1.3.6.1.4.1.9.9.315.1.2.1.1.10.5", Type: gosnmp.OctetString, Value: mac},
		{Name: ".1.3.6.1.4.1.9.9.315.1.2.1.1.11.5", Type: gosnmp.OctetString, Value: []byte{0x0a}},
	}}
	b, err := pkt.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := decodeTrap(x, b)
	got := map[string]any{}
	for _, v := range tr.Vars {
		got[v.OID] = v.Value
	}
	if got[".1.3.6.1.4.1.9.9.315.1.2.1.1.10.5"] != string(mac) || got[".1.3.6.1.4.1.9.9.315.1.2.1.1.11.5"] != "\n" {
		t.Errorf("el valor binario cambió: %q", got)
	}
}
