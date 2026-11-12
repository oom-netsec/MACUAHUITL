package acl

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var spanish = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(línea|origen|destino|regla|puerto|puertos|máscara|dirección|falta|inválido|inválida|desconocido|soportado|esperaba|ninguna|sin|el|los|del|con)\b`)

// Cada error de importación, validación y generación: el español es el de siempre, con en sale sin español y
// con el mismo código.
func TestErroresDeAclEsYEn(t *testing.T) {
	asa := func(body string) error { _, err := Parse("asa", "access-list A extended "+body+"\n"); return err }
	ios := func(text string) error { _, err := Parse("ios-xe", text); return err }
	nx := func(text string) error { _, err := Parse("nx-os", text); return err }
	r := func(mod func(*Rule)) error {
		x := Rule{Action: Permit, Protocol: "ip", Src: mustPrefix("10.0.0.0/8"), Dst: mustPrefix("0.0.0.0/0")}
		mod(&x)
		return x.Validate()
	}
	gen := func(v string, a ACL) error { _, err := Generate(v, a); return err }
	okRule := Rule{Action: Permit, Protocol: "ip", Src: mustPrefix("10.0.0.0/8"), Dst: mustPrefix("0.0.0.0/0")}
	for _, c := range []struct {
		name   string
		err    error
		es, en string
	}{
		{"vendor", func() error { _, err := Parse("junos", ""); return err }(), `acl: fabricante "junos" no soportado (ios-xe, nx-os, asa)`, `acl: vendor "junos" not supported (ios-xe, nx-os, asa)`},
		{"std", ios("access-list 10 permit any\n"), "línea 1: ACL estándar no soportada; usa una extendida", "line 1: standard ACL not supported; use an extended one"},
		{"fragments", nx("ip access-list X\nfragments permit-all\n"), "línea 2: 'fragments' cambia el trato de fragmentos y no se puede traducir; quítalo o tradúcelo a mano", "line 2: 'fragments' changes how fragments are handled and cannot be translated; remove it or translate it by hand"},
		{"asa_form", asa(""), "", ""},
		{"no_header", ios("permit ip any any\n"), "línea 1: falta el encabezado de la ACL", "line 1: the ACL header is missing"},
		{"none", ios(""), "línea 1: no se encontró ninguna ACL", "line 1: no ACL was found"},
		{"incomplete", asa("permit"), "línea 1: regla incompleta", "line 1: incomplete rule"},
		{"action", asa("allow ip any any"), `línea 1: se esperaba permit o deny, no "allow"`, `line 1: expected permit or deny, not "allow"`},
		{"proto", asa("permit foo any any"), `línea 1: protocolo "foo" desconocido`, `line 1: unknown protocol "foo"`},
		{"flag", asa("permit ip any any fragments"), `línea 1: no se entiende "fragments" (tipos ICMP, time-range y objetos no están soportados todavía)`, `line 1: "fragments" is not understood (ICMP types, time-range and objects are not supported yet)`},
		{"no_address", asa("permit ip"), "línea 1: origen: falta la dirección", "line 1: source: the address is missing"},
		{"mask", asa("permit ip 10.0.0.0 0.0.0.255 any"), "línea 1: origen: máscara 0.0.0.255 no es contigua", "line 1: source: mask 0.0.0.255 is not contiguous"},
		{"eq", asa("permit tcp any any eq"), "línea 1: destino: eq sin argumentos", "line 1: destination: eq without arguments"},
		{"badport", asa("permit tcp any any eq 99999"), `línea 1: destino: puerto "99999" inválido`, `line 1: destination: invalid port "99999"`},
		{"ios_wild", ios("ip access-list extended X\npermit ip 10.0.0.0 0.0.255.0 any\n"), "línea 2: origen: wildcard 0.0.255.0 no es contigua; no se puede expresar como CIDR", "line 2: source: wildcard 0.0.255.0 is not contiguous; it cannot be expressed as CIDR"},
		{"ios_host", ios("ip access-list extended X\npermit ip host any\n"), "", ""},
		{"nx_neq", nx("ip access-list X\npermit tcp any neq 1 2 any\n"), "", ""},
		{"gt", func() error { _, err := ParsePorts("gt", "65535"); return err }(), "gt 65535 no coincide con ningún puerto", "gt 65535 does not match any port"},
		{"lt", func() error { _, err := ParsePorts("lt", "0"); return err }(), "lt 0 no coincide con ningún puerto", "lt 0 does not match any port"},
		{"range", func() error { _, err := ParsePorts("range", "9", "5"); return err }(), "range 9 5 está vacío", "range 9 5 is empty"},
		{"args", func() error { _, err := ParsePorts("range", "9"); return err }(), "range necesita 2 argumento(s)", "range needs 2 arguments"},
		{"op", func() error { _, err := ParsePorts("zzz", "9"); return err }(), `operador de puerto "zzz" desconocido`, `unknown port operator "zzz"`},
		{"v_proto", r(func(x *Rule) { x.Protocol = "zz" }), `protocolo "zz" desconocido`, `unknown protocol "zz"`},
		{"v_srcdst", r(func(x *Rule) { x.Src = netip.Prefix{} }), "origen y destino son obligatorios", "source and destination are required"},
		{"v_ipv4", r(func(x *Rule) { x.Src = mustPrefix("2001:db8::/32") }), "2001:db8::/32: solo IPv4 en esta versión", "2001:db8::/32: IPv4 only in this version"},
		{"v_host", r(func(x *Rule) { x.Src = mustPrefix("10.0.0.1/8") }), "10.0.0.1/8 tiene bits de host; usa 10.0.0.0/8", "10.0.0.1/8 has host bits; use 10.0.0.0/8"},
		{"v_remark", r(func(x *Rule) { x.Remark = "a\nb" }), "el remark no puede tener saltos de línea", "the remark cannot contain line breaks"},
		{"v_ports", r(func(x *Rule) { x.DstPorts = []PortRange{{80, 80}} }), "los puertos solo aplican a tcp/udp, no a ip", "ports only apply to tcp/udp, not to ip"},
		{"v_est", r(func(x *Rule) { x.Established = true }), "established solo aplica a tcp", "established only applies to tcp"},
		{"v_range", r(func(x *Rule) { x.Protocol = "tcp"; x.DstPorts = []PortRange{{90, 80}} }), "rango de puertos 90-80 vacío", "port range 90-80 is empty"},
		{"g_name", gen("ios-xe", ACL{Name: "a b"}), `acl: nombre "a b" inválido`, `acl: invalid name "a b"`},
		{"g_vendor", gen("junos", ACL{Name: "A"}), `acl: fabricante "junos" no soportado (ios-xe, nx-os, asa)`, `acl: vendor "junos" not supported (ios-xe, nx-os, asa)`},
		{"g_rule", gen("ios-xe", ACL{Name: "A", Rules: []Rule{{}}}), `acl: regla 1: protocolo "" desconocido`, `acl: rule 1: unknown protocol ""`},
		{"g_asa", gen("asa", ACL{Name: "A", Rules: []Rule{{Action: Permit, Protocol: "tcp", Src: okRule.Src, Dst: okRule.Dst, Established: true}}}), "acl: regla 1: ASA no tiene 'established'; usa inspección de estado", "acl: rule 1: ASA has no 'established'; use stateful inspection"},
	} {
		if c.es == "" { // casos que solo comprueban que sale sin español
			if c.err == nil {
				t.Errorf("%s: debía fallar", c.name)
				continue
			}
		} else if c.err == nil || c.err.Error() != c.es {
			t.Errorf("%s: es %v, quería %q", c.name, c.err, c.es)
			continue
		}
		var co i18n.Coded
		if !errors.As(c.err, &co) {
			t.Errorf("%s: sin código", c.name)
			continue
		}
		en := co.Localize(i18n.En)
		if c.en != "" && en != c.en {
			t.Errorf("%s: en %q, quería %q", c.name, en, c.en)
		}
		if m := spanish.FindString(en); m != "" {
			t.Errorf("%s: español (%s) en %q", c.name, m, en)
		}
	}
}

// Los escenarios de la regresión recorren todos los códigos de error de ACL.
func TestEscenariosCubrenTodosLosErrores(t *testing.T) {
	regCases(t)
	used := map[string]bool{}
	var mark func(err error)
	mark = func(err error) {
		var e *i18n.Error
		if errors.As(err, &e) {
			used[e.Code] = true
			if e.Cause != nil {
				mark(e.Cause)
			}
		}
		var le *LineError
		if errors.As(err, &le) {
			mark(le.Err)
		}
	}
	for _, err := range regErrs {
		mark(err)
	}
	for _, k := range i18n.Codes() {
		if strings.HasPrefix(k, "acl.err.") && !used[k] && !strings.HasPrefix(k, "acl.err.rule_") && k != "acl.err.import" && k != "acl.err.ports_incomplete" && k != "acl.err.line" {
			t.Errorf("ningún escenario de la regresión produce %s", k)
		}
	}
}
