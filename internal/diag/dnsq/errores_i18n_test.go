package dnsq

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// erroresDNS arma consultas y trazas que fallan de cada forma que escribe un error en el informe.
func erroresDNS(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}
	ctx := context.Background()
	// servidor sin nadie escuchando (el laboratorio no conoce 127.0.0.77)
	l, roots, _ := hierarchy(t, false)
	dead := Server{Transport: "udp", Host: "127.0.0.77", Port: 53}
	out["compare-muerto"] = Compare(ctx, l.dial, []Server{dead, {Transport: "udp", Host: "127.0.0.4", Port: 53}}, "www.ejemplo.lab", dns.TypeA, opts())
	out["compare-transporte"] = Compare(ctx, l.dial, []Server{{Transport: "quic", Host: "127.0.0.4", Port: 53}}, "www.ejemplo.lab", dns.TypeA, opts())
	tr, err := Trace(ctx, l.dial, "www.ejemplo.lab", dns.TypeA, []Root{{Name: "a.root.lab.", IP: "127.0.0.77"}}, opts())
	if err == nil {
		t.Fatal("la traza debió fallar")
	}
	out["trace-muerto"] = tr
	out["trace-muerto-error"] = err.Error()
	_, err = CheckDNSSEC(ctx, l.dial, "ejemplo.lab", roots, []string{"esto no es un DS"}, opts())
	out["dnssec-ancla"] = err.Error()
	return out
}

func TestErroresDNSEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, v := range erroresDNS(t) {
		b, _ := json.Marshal(v)
		got[n] = volatileDNS.ReplaceAllString(string(b), "X")
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

// Con en, el error de cada respuesta, paso, sondeo y servidor sale en inglés; con es, Localize no cambia el JSON.
func TestErroresDNSEn(t *testing.T) {
	r := erroresDNS(t)
	cmp := Localize(r["compare-transporte"], "en").(CompareResult)
	if got := cmp.Answers[0].Error; !strings.HasSuffix(got, `unknown transport "quic"`) {
		t.Errorf("compare: %q", got)
	}
	te := i18n.New("dns.trace.err.no_servers", i18n.A("zone", "lab."))
	st := TraceResult{Steps: []Step{{Error: te.Error(), ErrorText: i18n.FromErr(te)}}}
	if got := Localize(st, "en").(TraceResult).Steps[0].Error; got != "dnsq: there are no servers for lab." {
		t.Errorf("traza: %q", got)
	}
	for n, v := range r {
		switch v.(type) {
		case CompareResult, TraceResult:
			if a, b := viewDNS(v), viewDNS(Localize(v, "es")); a != b {
				t.Errorf("%s: Localize(es) cambia el JSON", n)
			}
		}
	}
	// el sondeo y el servidor de zona
	zs := ZoneReport{Servers: []ZoneServer{{Name: "ns9", Error: "sin dirección", ErrorText: i18n.Tx("dns.zone.no_address")}}}
	if got := Localize(zs, "en").(ZoneReport).Servers[0].Error; got != "no address" {
		t.Errorf("zona: %q", got)
	}
	e := i18n.Wrap("dns.exch.wrap", i18n.New("dns.exch.doh_http", i18n.A("status", 502)), i18n.A("server", "https://x"))
	tp := TransportReport{Probes: []Probe{{Error: e.Error(), ErrorText: i18n.FromErr(e)}}}
	if got := Localize(tp, "en").(TransportReport).Probes[0].Error; got != "dnsq: https://x: DoH answered HTTP 502" {
		t.Errorf("sondeo: %q", got)
	}
	if e.Error() != "dnsq: https://x: DoH respondió HTTP 502" {
		t.Errorf("es: %q", e.Error())
	}
}
