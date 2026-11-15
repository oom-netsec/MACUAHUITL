package compliance

import (
	"strings"
	"testing"
)

// M4: las líneas que el informe cita pasan por el enmascarado completo (con su bloque), no solo por cuatro formas.
func TestInformeNoCitaSecretosDeOtrasFormas(t *testing.T) {
	cfg := "tacacs-server host 1.1.1.1 key 7 TACLEAK1\n" +
		"snmp-server host 1.1.1.1 version 2c SNMPLEAK1\n" +
		"crypto isakmp key ISALEAK1 address 1.1.1.1\n" +
		"radius server R\n key 7 RADLEAK1\n" +
		"radius-server key 7 RADLEAK2\n"
	tpl := "- tacacs-server host .*\n- snmp-server host .* version 2c .*\n- crypto isakmp key .*\n- radius-server key .*\nradius server .*\n - key .*\n"
	r, err := Check(cfg, tpl)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{r.Text(), strings.ToLower(r.Text())} {
		for _, leak := range []string{"TACLEAK1", "SNMPLEAK1", "ISALEAK1", "RADLEAK1", "RADLEAK2"} {
			if strings.Contains(strings.ToUpper(text), leak) {
				t.Errorf("el informe cita %s:\n%s", leak, r.Text())
			}
		}
	}
	if !strings.Contains(r.Text(), "<oculto>") {
		t.Errorf("sin marca de oculto:\n%s", r.Text())
	}
}

// M4: una configuración de ASA («ASA Version») cita el host SNMP «host IFNAME IP» con su IP y sin la comunidad.
func TestInformeDeASAConservaLaIPDelHostSNMP(t *testing.T) {
	cfg := "ASA Version 9.16(1)\nhostname fw\nsnmp-server host inside 10.0.0.1\nsnmp-server host inside 10.0.0.2 community ZQCOM1\nenable password ZQEN1\n"
	r, err := Check(cfg, "- snmp-server host .*\n- enable password .*\n")
	if err != nil {
		t.Fatal(err)
	}
	txt := r.Text()
	if !strings.Contains(txt, "10.0.0.1") || strings.Contains(txt, "ZQCOM1") || strings.Contains(txt, "ZQEN1") {
		t.Errorf("%s", txt)
	}
}
