package snmp

import (
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
