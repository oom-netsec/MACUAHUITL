package mask_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// Un valor que empieza con « ; » («username a password ; Zq1234»): el segmento termina en la palabra de secreto sin
// valor y el siguiente no tiene palabra de secreto. En IOS el password es una línea: lo que sigue es el secreto.
func TestValorQueEmpiezaConPuntoYComaNoFuga(t *testing.T) {
	valores := []string{"; Zq1234", ";  Zq1234 ; Yw5678", "; Zq1234 Yw5678"}
	plantillas := []string{"username a password %s", "username a secret %s", "enable secret %s", "tacacs-server key %s",
		"radius-server key %s", "crypto isakmp key %s address 10.1.1.1"}
	malos := 0
	for _, plat := range []string{"ios-xe", ""} {
		for _, tp := range plantillas {
			for _, v := range valores {
				cmd := fmt.Sprintf(tp, v)
				for _, via := range vias {
					if sueltas[via.nombre] {
						continue
					}
					out := via.f(nuevo, plat, cmd)
					for g, n := range visibles4(out, v[1:]) {
						if n > 0 {
							if malos++; malos <= 10 {
								t.Errorf("[%s] (%q) %q: %q visible\n  salida: %q", via.nombre, plat, cmd, g, out)
							}
							break
						}
					}
				}
			}
		}
	}
	if malos > 0 {
		t.Errorf("%d fugas en total", malos)
	}
}

// Revisión: un segmento previo que termina en palabra de secreto adelanta el tramo; la frase del secreto real (que va en
// un segmento posterior) se sigue recordando tras el prompt como antes.
func TestFraseTrasSegmentoConPalabraSinValorSeRecuerda(t *testing.T) {
	for _, cmd := range []string{"enable secret ; username b password abcd efgh", "snmp-server community ; tacacs-server key abcd efgh"} {
		out := grabar(nuevo, func(r sesionRec) { sesionPosterior(r, cmd, "abcd efgh", nil, false) })
		if strings.Contains(marcado.ReplaceAllString(out, "\x00"), "linea abcd efgh fin") {
			t.Errorf("%q: la frase se ve tras el prompt\n%s", cmd, out)
		}
	}
}

// Revisión: prosa citada con «password ;» o «key ;» seguida de una palabra de prosa no se tapa.
func TestProsaCitadaConPuntoYComaTrasPalabraDeSecreto(t *testing.T) {
	for l, prosa := range map[string]string{`ERROR: "password ; is wrong"`: "is wrong", `WARNING: "enter key ; not accepted"`: "not accepted"} {
		if got, _ := mask.Apply("ios-xe", l); !strings.Contains(got, prosa) {
			t.Errorf("%q: la prosa %q quedó tapada: %q", l, prosa, got)
		}
	}
}
