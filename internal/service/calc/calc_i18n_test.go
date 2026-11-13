package calc

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func u32(v uint32) *uint32   { return &v }
func f64(v float64) *float64 { return &v }

type call func(ctx context.Context) (*v1.CalcResult, error)

// llamadas arma, por calculadora, entradas válidas (tablas, notas y valores) y una inválida.
func llamadas() map[string]call {
	s := calcSvc{}
	subnet := func(p string) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Subnet(c, &v1.SubnetRequest{Prefix: p})
			return r.GetResult(), err
		}
	}
	wc := func(a, v string) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Wildcard(c, &v1.WildcardRequest{Address: a, Value: v})
			return r.GetResult(), err
		}
	}
	v6 := func(a, m string) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Ipv6(c, &v1.Ipv6Request{Address: a, Mac: m})
			return r.GetResult(), err
		}
	}
	mtu := func(p uint32, v6 bool, l ...string) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Mtu(c, &v1.MtuRequest{Physical: p, Layers: l, InnerIpv6: v6})
			return r.GetResult(), err
		}
	}
	tcp := func(q *v1.TcpRequest) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Tcp(c, q)
			return r.GetResult(), err
		}
	}
	dscp := func(q, f string) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Dscp(c, &v1.DscpRequest{Query: q, Field: f})
			return r.GetResult(), err
		}
	}
	optics := func(q *v1.OpticsRequest) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Optics(c, q)
			return r.GetResult(), err
		}
	}
	bgp := func(o *v1.BgpRequest) call {
		return func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Bgp(c, o)
			return r.GetResult(), err
		}
	}
	m := map[string]call{
		"subnet-v4":      subnet("10.1.2.3/24"),
		"subnet-31":      subnet("10.1.2.3/31"),
		"subnet-32":      subnet("10.1.2.3/32"),
		"subnet-privada": subnet("192.168.1.10/26"),
		"subnet-v6":      subnet("2001:db8::1/64"),
		"subnet-error":   subnet("10.0.0.1"),
		"vlsm": func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Vlsm(c, &v1.VlsmRequest{Network: "10.0.0.0/24", Needs: []*v1.VlsmNeed{{Name: "A", Hosts: 100}, {Hosts: 50}, {Name: "C", Hosts: 500}}})
			return r.GetResult(), err
		},
		"vlsm-error": func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Vlsm(c, &v1.VlsmRequest{Network: "10.0.0.0/24"})
			return r.GetResult(), err
		},
		"summarize": func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Summarize(c, &v1.SummarizeRequest{Prefixes: []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.3.0/24"}})
			return r.GetResult(), err
		},
		"summarize-error": func(c context.Context) (*v1.CalcResult, error) {
			r, err := s.Summarize(c, &v1.SummarizeRequest{Prefixes: []string{"10.0.0.0/24", "2001:db8::/32"}})
			return r.GetResult(), err
		},
		"wildcard-acl":     wc("10.1.2.0", "0.0.0.255"),
		"wildcard-par":     wc("10.1.2.0", "0.0.254.0"),
		"wildcard-impar":   wc("10.1.2.1", "0.0.0.254"),
		"wildcard-mixta":   wc("10.1.2.0", "0.0.0.85"),
		"wildcard-conv":    wc("", "255.255.255.0"),
		"wildcard-conv-w":  wc("", "0.0.0.255"),
		"wildcard-conv-n":  wc("", "/30"),
		"wildcard-error":   wc("x", "0.0.0.1"),
		"ipv6-global":      v6("2001:db8::1", ""),
		"ipv6-linklocal":   v6("fe80::1", ""),
		"ipv6-multicast":   v6("ff02::1", ""),
		"ipv6-ula":         v6("fd00::1/48", ""),
		"ipv6-loopback":    v6("::1", ""),
		"ipv6-mapped":      v6("::ffff:10.0.0.1", ""),
		"ipv6-eui":         v6("2001:db8:0:1::/64", "00:11:22:33:44:55"),
		"ipv6-eui-default": v6("", "aa-bb-cc-dd-ee-ff"),
		"ipv6-error":       v6("", ""),
		"mtu-gre":          mtu(1500, false, "gre"),
		"mtu-esp":          mtu(1500, false, "esp-tunnel:aes-cbc:sha1"),
		"mtu-esp-gcm":      mtu(1500, false, "esp-transport:aes-gcm", "gre"),
		"mtu-natt":         mtu(1500, false, "nat-t", "esp-tunnel:aes-gcm"),
		"mtu-getvpn":       mtu(1500, true, "getvpn:aes-cbc:sha256:tbar"),
		"mtu-pila":         mtu(1500, false, "vxlan", "dot1q", "mpls:3", "qinq", "pppoe", "lisp"),
		"mtu-tag-externo":  mtu(1500, false, "dot1q", "gre"),
		"mtu-ipv6-min":     mtu(1400, true, "gre", "gre"),
		"mtu-error":        mtu(1500, false, "foo"),
		"tcp":              tcp(&v1.TcpRequest{Bandwidth: "1g", RttMs: 50, LossPercent: 0.1}),
		"tcp-ventana":      tcp(&v1.TcpRequest{Bandwidth: "10g", RttMs: 100, Window: "64k"}),
		"tcp-enlace":       tcp(&v1.TcpRequest{Bandwidth: "10m", RttMs: 1, Window: "4m"}),
		"tcp-error":        tcp(&v1.TcpRequest{Bandwidth: "1g"}),
		"dscp-tabla":       dscp("", ""),
		"dscp-nombre":      dscp("EF", ""),
		"dscp-af":          dscp("af21", "name"),
		"dscp-numero":      dscp("46", ""),
		"dscp-cos":         dscp("5", "cos"),
		"dscp-tos":         dscp("0xb8", "tos"),
		"dscp-error":       dscp("zz", "dscp"),
		"optics-ok":        optics(&v1.OpticsRequest{TxDbm: -3, RxSensitivityDbm: -18, Km: 10, Fiber: "smf-1310", Connectors: 2, ConnectorLossDb: 0.5, Splices: 2, SpliceLossDb: 0.1, MarginDb: 3}),
		"optics-corto":     optics(&v1.OpticsRequest{TxDbm: 0, RxSensitivityDbm: -14, RxOverloadDbm: f64(-3), Km: 1, Fiber: "smf-1550"}),
		"optics-largo":     optics(&v1.OpticsRequest{TxDbm: -5, RxSensitivityDbm: -14, Km: 80, Fiber: "smf-1550", Connectors: 4, ConnectorLossDb: 0.75, MarginDb: 3}),
		"optics-mmf":       optics(&v1.OpticsRequest{TxDbm: -4, RxSensitivityDbm: -11, RxOverloadDbm: f64(0), Km: 0.3, Fiber: "mmf-850", LossPerKm: 3}),
		"optics-sin-rx":    optics(&v1.OpticsRequest{TxDbm: 3, RxSensitivityDbm: -10, RxOverloadDbm: f64(-1), Km: 2, Fiber: "smf-1310"}),
		"optics-dbm":       optics(&v1.OpticsRequest{Convert: "-3dBm"}),
		"optics-mw":        optics(&v1.OpticsRequest{Convert: "0.5mW"}),
		"optics-error":     optics(&v1.OpticsRequest{Fiber: "x"}),
		"optics-error-p":   optics(&v1.OpticsRequest{Convert: "5"}),
		"bgp-error":        bgp(&v1.BgpRequest{Routes: []*v1.BgpRoute{{Name: "a"}}}),
	}
	// BGP: un par de rutas por cada paso del algoritmo, más opciones.
	pares := map[string][2]*v1.BgpRoute{
		"weight":       {{Name: "a", Weight: 10}, {Name: "b", Weight: 20}},
		"localpref":    {{Name: "a", LocalPref: u32(200)}, {Name: "b"}},
		"local":        {{Name: "a"}, {Name: "b", LocallyOriginated: true}},
		"aspath":       {{Name: "a", AsPath: "1 2 3"}, {Name: "b", AsPath: "1 2"}},
		"origin":       {{Name: "a", Origin: "?"}, {Name: "b", Origin: "e"}},
		"med":          {{Name: "a", AsPath: "65001", Med: u32(50)}, {Name: "b", AsPath: "65001", Med: u32(10)}},
		"ebgp":         {{Name: "a", Ebgp: false}, {Name: "b", Ebgp: true}},
		"igp":          {{Name: "a", IgpMetric: 20}, {Name: "b", IgpMetric: 10}},
		"edad":         {{Name: "a", Ebgp: true, AgeSeconds: 10}, {Name: "b", Ebgp: true, AgeSeconds: 99}},
		"routerid":     {{Name: "a", RouterId: "2.2.2.2"}, {Name: "b", RouterId: "1.1.1.1"}},
		"cluster":      {{Name: "a", RouterId: "1.1.1.1", ClusterListLength: 3}, {Name: "b", RouterId: "1.1.1.1", ClusterListLength: 1}},
		"neighbor":     {{Name: "a", RouterId: "1.1.1.1", Neighbor: "10.0.0.9"}, {Name: "b", RouterId: "1.1.1.1", Neighbor: "10.0.0.2"}},
		"sin-nombre":   {{Weight: 1}, {Weight: 2}},
		"inalcanzable": {{Name: "a", NextHopUnreachable: true}, {Name: "b"}},
		"empate":       {{Name: "a", AsPath: "65001 { 1 2 } (65002)"}, {Name: "b", AsPath: "65001"}},
	}
	for n, p := range pares {
		m["bgp-"+n] = bgp(&v1.BgpRequest{Routes: []*v1.BgpRoute{p[0], p[1]}})
		m["bgp-"+n+"-opciones"] = bgp(&v1.BgpRequest{Routes: []*v1.BgpRoute{p[0], p[1], {Name: "c", AsPath: "65009", Med: u32(5)}}, AlwaysCompareMed: true, DeterministicMed: true, MultipathRelax: true, MaximumPaths: 2})
	}
	return m
}

func TestCalcEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, c := range llamadas() {
		r, err := c(context.Background())
		j, tx := "", ""
		if r != nil {
			j, tx = r.Json, r.Text
			b, _ := json.Marshal(r.Notes)
			tx += "\n" + string(b)
		}
		got[n] = i18ntest.Dump(j, tx, err)
	}
	i18ntest.Golden(t, "testdata/calc_es.json", got)
}

var palabraEs = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(indica|inválid\w*|dirección|máscara|prefijo|capa|capas|cifrado|desconocid\w*|fuera|rango|ruta|rutas|pide|debe|mayor|pérdida|pérdidas|ventana|campo|nada|coincide|potencia|unidad|fibra|negativos|segmento|ninguna|accesible|enlace|sí|pares|impares|valores|de|con|sin|el|la|los|las|para|por|se|es|un|una|del|al|más|menos|ancho|banda|redes|máximo|mínimo|ninguno|hasta|desde|cuando|porque|solo|límite|limita|lo)\b`)

func TestCalcSinEspanolEnIngles(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), i18n.En)
	for n, c := range llamadas() {
		r, err := c(ctx)
		var vis []string
		if err != nil {
			vis = append(vis, err.Error())
		}
		if r != nil {
			vis = append(vis, r.Text)
			vis = append(vis, r.Notes...)
			for _, tb := range r.Tables {
				vis = append(vis, tb.Title)
				vis = append(vis, tb.Head...)
				for _, row := range tb.Rows {
					vis = append(vis, row.Cells...)
				}
			}
		}
		for _, v := range vis {
			if loc := palabraEs.FindString(v); loc != "" {
				t.Errorf("%s: queda español (%q) en en: %q", n, loc, strings.TrimSpace(v))
			}
		}
	}
}
