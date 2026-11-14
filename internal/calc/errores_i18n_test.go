package calc

import (
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// erroresCalc provoca cada error de las calculadoras con una entrada inválida.
func erroresCalc() map[string]error {
	out := map[string]error{}
	put := func(name string, err error) { out[name] = err }
	one := func(_ any, err error) error { return err }
	r := func(name string, lp *uint32) Route { return Route{Name: name, LocalPref: lp} }

	// Subnet / parsePrefix
	put("subnet-sin-prefijo", one(Subnet("10.0.0.1")))
	put("subnet-direccion", one(Subnet("999.0.0.1/24")))
	put("subnet-mascara-invalida", one(Subnet("10.0.0.1 hola")))
	put("subnet-mascara-no-contigua", one(Subnet("10.0.0.1 255.0.255.0")))
	put("subnet-longitud", one(Subnet("10.0.0.1/33")))
	// VLSM
	put("vlsm-sin-necesidades", one(VLSM("10.0.0.0/24", nil)))
	put("vlsm-cero-hosts", one(VLSM("10.0.0.0/24", []Need{{Name: "A", Hosts: 0}})))
	put("vlsm-red", one(VLSM("x", []Need{{Name: "A", Hosts: 5}})))
	// Summarize
	put("sum-mezcla", one(Summarize([]string{"10.0.0.0/24", "2001:db8::/32"})))
	put("sum-vacio", one(Summarize(nil)))
	put("sum-invalido", one(Summarize([]string{"10.0.0.0/99"})))
	// Wildcard
	put("wc-direccion", one(Wildcard("x", "0.0.0.255")))
	put("wc-wildcard", one(Wildcard("10.0.0.1", "x")))
	put("wc-conv-no-es", one(Wildcard("", "hola")))
	put("wc-conv-no-contigua", one(Wildcard("", "0.255.0.255")))
	put("wc-conv-rango", one(Wildcard("", "/40")))
	// IPv6
	put("ipv6-vacio", one(IPv6("", "")))
	put("ipv6-mac-corta", one(IPv6("", "aa:bb")))
	put("ipv6-mac-hex", one(IPv6("", "zz:bb:cc:dd:ee:ff")))
	put("ipv6-eui-prefijo", one(IPv6("2001:db8::/48", "aa:bb:cc:dd:ee:ff")))
	put("ipv6-direccion", one(IPv6("hola", "")))
	put("ipv6-prefijo", one(IPv6("2001:db8::1/200", "")))
	// MTU
	put("mtu-rango", one(MTU(10, []string{"gre"}, false)))
	put("mtu-sin-capas", one(MTU(1500, nil, false)))
	put("mtu-no-cabe", one(MTU(100, []string{"gre", "gre", "gre"}, false)))
	put("mtu-nat-t", one(MTU(1500, []string{"nat-t"}, false)))
	put("mtu-transporte", one(MTU(1500, []string{"esp-transport:aes-cbc:sha1", "pppoe"}, false)))
	put("mtu-mpls", one(MTU(1500, []string{"mpls:99"}, false)))
	put("mtu-mpls-capa", one(MTU(1500, []string{"mpls:1:2"}, false)))
	put("mtu-cifrado", one(MTU(1500, []string{"esp-tunnel:rot13"}, false)))
	put("mtu-ya-autentica", one(MTU(1500, []string{"esp-tunnel:aes-gcm:sha1"}, false)))
	put("mtu-autenticacion", one(MTU(1500, []string{"esp-tunnel:aes-cbc:xx"}, false)))
	put("mtu-esp-capa", one(MTU(1500, []string{"esp-tunnel:aes-cbc:sha1:a:b"}, false)))
	put("mtu-esp-no-cabe", one(MTU(70, []string{"esp-tunnel:aes-cbc:sha1"}, false)))
	put("mtu-desconocida", one(MTU(1500, []string{"foo"}, false)))
	// TCP
	put("tcp-ancho", one(TCP("hola", 10, "", 0, 0)))
	put("tcp-rtt", one(TCP("1g", 0, "", 0, 0)))
	put("tcp-perdida", one(TCP("1g", 10, "", 100, 0)))
	put("tcp-ventana", one(TCP("1g", 10, "hola", 0, 0)))
	// DSCP
	put("dscp-valor", one(DSCP("zz", "dscp")))
	put("dscp-campo", one(DSCP("10", "foo")))
	put("dscp-nada", one(DSCP("nadaquecoincida", "name")))
	// Optics / Power
	put("optics-fibra", one(Optics(OpticsInput{Fiber: "x"})))
	put("optics-negativo", one(Optics(OpticsInput{Fiber: "smf-1310", Km: -1})))
	put("power-dbm", one(Power("xdBm")))
	put("power-mw", one(Power("-1mW")))
	put("power-unidad", one(Power("5")))
	// BGP
	put("bgp-pocas", one(BGPBestPath([]Route{r("a", nil)}, BGPOptions{})))
	put("bgp-origin", one(BGPBestPath([]Route{{Name: "a", Origin: "z"}, {Name: "b"}}, BGPOptions{})))
	put("bgp-aspath-anidado", one(BGPBestPath([]Route{{Name: "a", ASPath: "{ { 1 } }"}, {Name: "b"}}, BGPOptions{})))
	put("bgp-aspath-cierre", one(BGPBestPath([]Route{{Name: "a", ASPath: "1 }"}, {Name: "b"}}, BGPOptions{})))
	put("bgp-aspath-as", one(BGPBestPath([]Route{{Name: "a", ASPath: "1 x"}, {Name: "b"}}, BGPOptions{})))
	put("bgp-aspath-abierto", one(BGPBestPath([]Route{{Name: "a", ASPath: "1 { 2"}, {Name: "b"}}, BGPOptions{})))
	put("bgp-direccion", one(BGPBestPath([]Route{{Name: "a", RouterID: "x"}, {Name: "b"}}, BGPOptions{})))
	put("bgp-sin-nexthop", one(BGPBestPath([]Route{{Name: "a", NextHopUnreachable: true}, {Name: "b", NextHopUnreachable: true}}, BGPOptions{})))
	return out
}

func TestErroresCalcEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, err := range erroresCalc() {
		if err == nil {
			t.Fatalf("%s: debió fallar", n)
		}
		got[n] = err.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.json", got)
}

var palabraEs = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(indica|inválid\w*|dirección|máscara|prefijo|capa|capas|cifrado|desconocid\w*|fuera de rango|no cabe|ruta|rutas|pide|hosts? de|debe ser|mayor que|pérdida|ventana|campo|nada coincide|potencia|unidad|fibra|negativos|segmento|nunca|ninguna|accesible|y|o)\b`)

func TestErroresCalcSinEspanolEnIngles(t *testing.T) {
	for n, err := range erroresCalc() {
		en := i18n.In(i18n.En, err)
		if palabraEs.MatchString(en) {
			t.Errorf("%s: queda español en en: %q", n, en)
		}
		if _, ok := err.(i18n.Coded); !ok {
			t.Errorf("%s: el error no lleva código: %q", n, err.Error())
		}
	}
}
