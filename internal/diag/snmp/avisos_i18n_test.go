package snmp

import (
	"regexp"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func avisosSNMP() map[string]string {
	out := map[string]string{}
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
	t, _ := decodeTrap(x, []byte{0x30, 0x01})
	out["trap-basura"] = t.Error
	t, _ = decodeTrap(x, nil)
	out["trap-vacio"] = t.Error
	prev := &Sample{Time: time.Unix(100, 0), Uptime: 5000}
	cur := &Sample{Time: time.Unix(110, 0), Uptime: 100}
	rates(prev, cur)
	out["reinicio"] = cur.Errors[0]
	return out
}

func TestAvisosSNMPEspanolRegresion(t *testing.T) {
	i18ntest.Golden(t, "testdata/avisos_es.golden.json", avisosSNMP())
}

var palabrasEsAv = regexp.MustCompile(`(?i)[áéíóúñ]|\b(paquete|vacío|tasas|reinició|sin decodificar|malformado)`)

func TestAvisosSNMPEn(t *testing.T) {
	cur := &Sample{Time: time.Unix(110, 0), Uptime: 100}
	rates(&Sample{Time: time.Unix(100, 0), Uptime: 5000}, cur)
	if got := cur.Localize("en").Errors[0]; palabrasEsAv.MatchString(got) || got == "" {
		t.Errorf("poll: %q", got)
	}
	if cur.Localize("es").Errors[0] != cur.Errors[0] {
		t.Error("es cambió")
	}
	tr := trapErr("snmp.trap.empty")
	tr.ErrorText = i18n.Tx("snmp.trap.v3_raw", "bytes", 9).With("error", tr.ErrorText)
	tr.Error = tr.ErrorText.In(i18n.Es)
	if tr.Error != "v3 sin decodificar (9 bytes): paquete vacío" || tr.Localize("en").Error != "undecoded v3 (9 bytes): empty packet" {
		t.Errorf("trap: %q / %q", tr.Error, tr.Localize("en").Error)
	}
	m := trapErr("snmp.trap.malformed", "detail", "boom")
	if m.Error != "paquete malformado: boom" || m.Localize("en").Error != "malformed packet: boom" {
		t.Errorf("malformed: %q", m.Localize("en").Error)
	}
}
