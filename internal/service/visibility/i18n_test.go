package visibility

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// visibilidadCasos recorre los errores de validación de visibilidad; ctx fija el idioma.
func visibilidadCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = "ERROR: " + err.Error()
		}
	}
	d := servicetest.New(t)
	s := &visibilitySvc{d: d}
	_, err := s.BuildTopology(ctx, &v1.BuildTopologyRequest{})
	put("topo_vacio", err)
	_, err = s.BuildTopology(ctx, &v1.BuildTopologyRequest{Dir: "relativa"})
	put("topo_relativa", err)
	_, err = s.BuildTopology(ctx, &v1.BuildTopologyRequest{PcapPath: "x.pcap"})
	put("topo_pcap_relativa", err)
	_, err = s.SnmpGet(ctx, &v1.SnmpGetRequest{})
	put("snmp_sin_destino", err)
	_, err = s.SnmpGet(ctx, &v1.SnmpGetRequest{Target: &v1.SnmpTarget{Host: "-x"}})
	put("snmp_host", err)
	_, err = s.SnmpGet(ctx, &v1.SnmpGetRequest{Target: &v1.SnmpTarget{Host: "192.0.2.1", Port: 70000}})
	put("snmp_puerto", err)
	_, err = s.SnmpGet(ctx, &v1.SnmpGetRequest{Target: &v1.SnmpTarget{Host: "192.0.2.1"}})
	put("snmp_sin_boveda", err)
	_, perr := d.CreateVault().Put(vault.Credential{Label: "snmp", Username: "snmp", Password: secret.New([]byte("x")), Enable: secret.New(nil), SSHKey: secret.New(nil)})
	if perr != nil {
		t.Fatal(perr)
	}
	_, err = s.SnmpGet(ctx, &v1.SnmpGetRequest{Target: &v1.SnmpTarget{Host: "192.0.2.1"}})
	put("snmp_sin_credencial", err)
	_, err = s.SnmpWalk(ctx, &v1.SnmpWalkRequest{Target: &v1.SnmpTarget{Host: "192.0.2.1", CredentialId: "no-existe"}})
	put("snmp_credencial_mala", err)
	_, err = s.GnmiGet(ctx, &v1.GnmiGetRequest{})
	put("gnmi_sin_destino", err)
	_, err = s.GnmiGet(ctx, &v1.GnmiGetRequest{Target: &v1.GnmiTarget{Host: "-x"}})
	put("gnmi_host", err)
	_, err = s.GnmiGet(ctx, &v1.GnmiGetRequest{Target: &v1.GnmiTarget{Host: "192.0.2.1", CaPath: "ca.pem"}})
	put("gnmi_ca_relativa", err)
	return out
}

func TestVisibilidadRegresionEs(t *testing.T) {
	base := visibilidadCasos(t, i18n.WithLocale(context.Background(), "es"))
	i18ntest.Golden(t, "testdata/visibilidad_es.golden.json", base)
	for _, loc := range []string{"es", "es-MX"} {
		for k, v := range visibilidadCasos(t, i18n.WithLocale(i18n.WithLocale(context.Background(), "es"), loc)) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de es", k, loc)
			}
		}
	}
}

func TestVisibilidadEnSinEspanol(t *testing.T) {
	for k, v := range visibilidadCasos(t, i18n.WithLocale(context.Background(), "en")) {
		if strings.ContainsAny(v, "áéíóúñ¿") || strings.Contains(v, "indica") || strings.Contains(v, "falta") || strings.Contains(v, "inválido") {
			t.Errorf("%s: queda español: %q", k, v)
		}
	}
}
