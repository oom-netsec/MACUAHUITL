package mask_test

import (
	"strings"
	"testing"
)

// superconjunto: nuevo es viejo con una región reemplazada por marcadores (o quitada): todo lo que nuevo deja visible
// ya lo dejaba visible viejo y en el mismo sitio. Es el helper con el que se comprueba que una prueba exacta puede
// cambiar su valor esperado.
func superconjunto(nuevo, viejo string) bool {
	if k := strings.Count(nuevo, " ; "); k > 0 && k == strings.Count(viejo, " ; ") { // una región por segmento
		ns, vs := strings.Split(nuevo, " ; "), strings.Split(viejo, " ; ")
		for i := range ns {
			if !superconjunto1(ns[i], vs[i]) {
				return false
			}
		}
		return true
	}
	return superconjunto1(nuevo, viejo)
}

func superconjunto1(nuevo, viejo string) bool {
	n, v := markerOK.ReplaceAllString(nuevo, "\x00"), markerOK.ReplaceAllString(viejo, "\x00")
	c := 0
	for c < len(n) && c < len(v) && n[c] == v[c] {
		c++
	}
	s := 0
	for s < len(n)-c && s < len(v)-c && n[len(n)-1-s] == v[len(v)-1-s] {
		s++
	}
	return strings.Trim(n[c:len(n)-s], "\x00 ") == ""
}

func TestSuperconjuntoHelper(t *testing.T) {
	for _, c := range []struct {
		n, v string
		ok   bool
	}{
		{"a <MASKED:secret>", "a <MASKED:user-secret> priv 15", true},
		{"a <MASKED:secret> z", "a x y z", true},
		{"a b z", "a x y z", false},
		{"a x <MASKED:secret>", "a x y z", true},
		{"a x y z", "a <MASKED:s> z", false},
	} {
		if got := superconjunto(c.n, c.v); got != c.ok {
			t.Errorf("superconjunto(%q, %q) = %v", c.n, c.v, got)
		}
	}
}

// Las pruebas exactas anteriores que cambiaron de valor: la salida nueva tapa un superconjunto de la de la v0.6.5
// (comprobado aquí con el helper, no a mano) y vale lo que dice la tabla.
func TestExactasActualizadasSonSuperconjunto(t *testing.T) {
	for _, c := range []struct{ plat, in, want string }{
		{"asa", "%ASA-5-111008: User 'enable_15' executed the 'username bob password S3cretPw privilege 15' command.\n",
			"%ASA-5-111008: User 'enable_15' executed the 'username bob password <MASKED:secret>' command.\n"},
		{"ios-xe", "  2  1  admin@vty0  |snmp-server community Cl4ve RO\n", "  2  1  admin@vty0  |snmp-server community <MASKED:secret>\n"},
		{"ios-xe", "%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:snmp-server community Cl4ve RO\n",
			"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:snmp-server community <MASKED:secret>\n"},
	} {
		n, v := nuevo.apply(c.plat, c.in), viejo.apply(c.plat, c.in)
		if n != c.want || !superconjunto(n, v) {
			t.Errorf("%q\n  nueva:  %q\n  v0.6.5: %q\n  tabla:  %q", c.in, n, v, c.want)
		}
	}
}
