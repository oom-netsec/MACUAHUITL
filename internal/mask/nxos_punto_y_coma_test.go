package mask_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// En NX-OS e ISE un « ; » separa comandos en el CLI: «username u password abc ; def» lo parte el propio equipo y lo que
// sigue es justo el resto del secreto. Con una palabra de secreto en un segmento, el tramo va del valor al fin de la
// línea, « ; » incluidos. Ningún 4-grama de ninguna parte del valor puede verse por ninguna vía de comando.
func TestNXOSEISEPuntoYComaDentroDelSecretoNoFuga(t *testing.T) {
	valores := []string{"Zq1234 ; Yw5678", "Aa11x ; Bb22y ; Cc33z", "Zq1234;Yw5678", "Zq1234 ;Yw5678 ; Mm9988"}
	plantillas := []string{
		"username u password %s", "snmp-server community %s", "tacacs-server key %s", "radius-server key %s",
		"feature tacacs+ ; tacacs-server key %s", "show clock ; username u password %s ; show ver", "key chain K ; key 1 ; key-string 0 %s",
	}
	malos := 0
	for _, plat := range []string{"nx-os", "ise"} {
		for _, tp := range plantillas {
			for _, v := range valores {
				cmd := fmt.Sprintf(tp, v)
				for _, via := range vias {
					if sueltas[via.nombre] {
						continue
					}
					out := via.f(nuevo, plat, cmd)
					for g, n := range visibles4(out, v) {
						if n > 0 {
							if malos++; malos <= 10 {
								t.Errorf("[%s] (%s) %q: %q visible\n  salida: %q", via.nombre, plat, cmd, g, out)
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

// Lo anterior al segmento con la palabra de secreto sigue visible y los segmentos sin palabra de secreto no cambian.
func TestNXOSPuntoYComaSegmentosSinSecretoIntactos(t *testing.T) {
	for _, plat := range []string{"nx-os", "ise"} {
		if got := mask.Cmd(plat, "show clock ; show ver ; conf t"); got != "show clock ; show ver ; conf t" {
			t.Errorf("(%s) sin secreto cambió: %q", plat, got)
		}
		got := mask.Cmd(plat, "show clock ; username u password abc ; def ; show ver")
		if want := "show clock ; username u password <MASKED:secret>"; got != want {
			t.Errorf("(%s) Cmd = %q; quiero %q", plat, got, want)
		}
		for _, via := range vias {
			if sueltas[via.nombre] || !strings.Contains(via.nombre, "Typed") {
				continue
			}
			if out := via.f(nuevo, plat, "show clock ; show ver ; conf t"); out != "show clock ; show ver ; conf t" {
				t.Errorf("[%s] (%s) sin secreto cambió: %q", via.nombre, plat, out)
			}
			if out := via.f(nuevo, plat, "show clock ; username u password abc ; def"); !strings.HasPrefix(out, "show clock ; username u password ") || strings.Contains(out, "def") {
				t.Errorf("[%s] (%s) = %q", via.nombre, plat, out)
			}
		}
	}
}
