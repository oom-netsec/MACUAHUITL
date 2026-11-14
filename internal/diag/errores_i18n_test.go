package diag

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func erroresDiag() map[string]error {
	out := map[string]error{}
	b := func(n string, r Request) { _, _, out[n] = Build(r) }
	b("destino-vacio", Request{Tool: Ping, Targets: []string{"-x"}})
	b("cidr", Request{Tool: Ping, Targets: []string{"10.0.0.0/24"}})
	b("prefijo", Request{Tool: Nmap, Targets: []string{"a/b"}})
	b("no-es-ip", Request{Tool: Ping, Targets: []string{"a b"}})
	b("un-destino", Request{Tool: Ping})
	b("opcion", Request{Tool: Ping, Targets: []string{"1.1.1.1"}, Options: map[string]string{"zz": "1"}})
	b("uno-de", Request{Tool: Nmap, Targets: []string{"1.1.1.1"}, Options: map[string]string{"scan": "x"}})
	b("numero", Request{Tool: Ping, Targets: []string{"1.1.1.1"}, Options: map[string]string{"count": "9999"}})
	b("ports", Request{Tool: Nmap, Targets: []string{"1.1.1.1"}, Options: map[string]string{"ports": "x"}})
	b("iperf", Request{Tool: Iperf3})
	b("pcap-destino", Request{Tool: Pcap, Targets: []string{"1.1.1.1"}})
	b("pcap-carpeta", Request{Tool: Pcap})
	b("pcap-iface", Request{Tool: Pcap, OutputDir: "/tmp"})
	b("herramienta", Request{Tool: "x"})
	_, out["run-build"] = Runner{}.Run(context.Background(), Request{Tool: Ping}, nil)
	_, out["no-instalado"] = Runner{LookPath: func(string) (string, error) { return "", os.ErrNotExist }}.Run(context.Background(), Request{Tool: Ping, Targets: []string{"1.1.1.1"}}, nil)
	return out
}

func TestErroresDiagEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresDiag() {
		if e == nil {
			t.Fatalf("%s: debió fallar", k)
		}
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ¿«]|\b(inválid|no existe|debe ser|necesita|desconocid|herramienta|destino|opción|sin |falta|usa )`)

func TestErroresDiagEn(t *testing.T) {
	for k, e := range erroresDiag() {
		if m := palabrasEs.FindString(i18n.In(i18n.En, e)); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, i18n.In(i18n.En, e))
		}
		if strings.Contains(i18n.In(i18n.Es, e), "%!") {
			t.Errorf("%s: formato roto", k)
		}
	}
}
