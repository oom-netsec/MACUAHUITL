package flows

import (
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func erroresFlows() map[string]error {
	m := map[string]error{}
	d := NewDecoder()
	dec := func(n string, b []byte) { _, m[n] = d.Decode("10.0.0.1:2055", b) }
	dec("corto", []byte{0, 5})
	dec("version", []byte{0, 7, 0, 0})
	v5 := netflowV5(2)
	v5[3] = 31
	dec("v5-registros", v5)
	dec("v5-truncado", netflowV5(2)[:20])
	dec("v9-sin-plantilla", netflowV9(false, 1))
	v9 := netflowV9(true, 1)
	v9[21] = 1 // largo del primer set inválido
	v9[23] = 1
	dec("v9-set", v9)
	d.MaxExporters = 0
	dec("exportadores", netflowV9(true, 2))
	d = NewDecoder()
	d.MaxTotal = 0
	dec("global", netflowV9(true, 3))
	d = NewDecoder()
	d.MaxTemplates = 0
	dec("por-exportador", netflowV9(true, 4))
	sf := sflow()
	sf[7] = 9 // tipo de dirección de agente
	dec("sflow-agente", sf)
	dec("sflow-truncado", sflow()[:40])
	a := NewAggregator(5)
	a.Error("10.0.0.1", m["version"])
	m["ultimo-error"] = errString(a.Snapshot(3).LastError)
	return m
}

type errString string

func (e errString) Error() string { return string(e) }

func TestErroresFlowsEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresFlows() {
		if e == nil {
			got[k] = "<nil>"
			continue
		}
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ¿]|\b(inválid|no soportad|truncad|plantilla|límite|registros|exportador|desconocid|versión|sin )`)

func TestErroresFlowsEn(t *testing.T) {
	for k, e := range erroresFlows() {
		if e == nil || k == "ultimo-error" {
			continue
		}
		if m := palabrasEs.FindString(i18n.English(e)); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, i18n.English(e))
		}
	}
}

func TestUltimoErrorEn(t *testing.T) {
	a := NewAggregator(5)
	_, err := NewDecoder().Decode("10.0.0.1:2055", []byte{0, 7, 0, 0})
	a.Error("10.0.0.1", err)
	if got := a.Snapshot(3).Localize("en").LastError; got != "10.0.0.1: version 7 not supported (NetFlow v5/v9, IPFIX, sFlow v5)" {
		t.Errorf("%q", got)
	}
	if a.Snapshot(3).Localize("es").LastError != "10.0.0.1: versión 7 no soportada (NetFlow v5/v9, IPFIX, sFlow v5)" {
		t.Error("es cambió")
	}
}
