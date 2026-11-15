package mask

import (
	"strings"
	"testing"
)

// Hueco real visto en el ASAv de CML (2026-11-14): show tech-support repite líneas de configuración entre comillas en
// sus avisos («*** Output from config line 9, "enable password …"»), y sus errores y advertencias hacen lo mismo. Lo
// citado pasa por las mismas reglas que la línea suelta, en cualquier plataforma.
func TestLineaDeConfiguracionCitada(t *testing.T) {
	for _, tc := range []struct{ platform, in, leak string }{
		{"asa", `*** Output from config line 9, "enable password Cl4veSecr3ta"`, "Cl4veSecr3ta"},
		{"asa", `*** Output from config line 12, "username admin password Sup3rS3cret privilege 15"`, "Sup3rS3cret"},
		{"asa", `*** Output from config line 40, "failover key Fa1l0verK3y"`, "Fa1l0verK3y"},
		{"asa", `ERROR: % Unable to apply "enable password Cl4veSecr3ta level 15"`, "Cl4veSecr3ta"},
		{"asa", `WARNING: "username bob password Hunt3r2Hunt3r" was replaced`, "Hunt3r2Hunt3r"},
		{"ios-xe", `%Error in config line 7, "snmp-server community S3cretComm RO"`, "S3cretComm"},
		{"nx-os", `Syntax error while parsing "username admin password 0 Nx0sPass123 role network-admin"`, "Nx0sPass123"},
		{"ftd", `*** Output from config line 3, "enable password FtdEnabl3"`, "FtdEnabl3"},
	} {
		out, counts := Apply(tc.platform, tc.in+"\n")
		if strings.Contains(out, tc.leak) || !strings.Contains(out, "<MASKED:") || len(counts) == 0 {
			t.Errorf("%s %q → %q", tc.platform, tc.in, out)
		}
	}
	// Lo demás entre comillas no cambia.
	for _, in := range []string{`*** Output from config line 3, "hostname ASA1"`, `description "enlace a sitio B"`, `banner motd "Acceso restringido"`} {
		if out, _ := Apply("asa", in+"\n"); out != in+"\n" {
			t.Errorf("cambió una línea sin secreto: %q → %q", in, out)
		}
	}
}

// Una línea citada con sangría hereda el bloque de la última línea citada sin sangría (el pre-shared-key dentro de
// su tunnel-group), como en la configuración de verdad.
func TestLineaCitadaHeredaElBloque(t *testing.T) {
	in := `*** Output from config line 5, "tunnel-group 10.0.0.1 ipsec-attributes"` + "\n" +
		`*** Output from config line 6, " ikev1 pre-shared-key Psk123456"` + "\n"
	out, _ := Apply("asa", in)
	if strings.Contains(out, "Psk123456") || !strings.Contains(out, "tunnel-group 10.0.0.1 ipsec-attributes") {
		t.Fatalf("%q", out)
	}
}

// La herencia del bloque importa cuando la regla depende de él: «token» solo es secreto dentro de «license smart».
func TestLineaCitadaUsaElBloqueDeLaCitaAnterior(t *testing.T) {
	in := `*** Output from config line 2, "license smart"` + "\n" + `*** Output from config line 3, " token Tok3nSecr3to"` + "\n"
	if out, _ := Apply("asa", in); strings.Contains(out, "Tok3nSecr3to") {
		t.Fatalf("%q", out)
	}
	// sin el bloque citado antes, «token» suelto no es secreto: la línea queda igual
	solo := `*** Output from config line 3, " token publico"` + "\n"
	if out, _ := Apply("asa", solo); out != solo {
		t.Fatalf("%q", out)
	}
}

// maskCited también corre sobre lo citado: un «key X» citado fuera de cualquier bloque conocido no sale en claro.
func TestLineaCitadaPasaPorMaskCited(t *testing.T) {
	in := `WARNING: "  key Cl4veSu3lta" ignored` + "\n"
	if out, _ := Apply("asa", in); strings.Contains(out, "Cl4veSu3lta") {
		t.Fatalf("%q", out)
	}
}

// Casos de la revisión de seguridad: comillas mal formadas, el terminal y formatos que repiten configuración sin comillas.
func TestCitasMalFormadasYFormatosSinComillas(t *testing.T) {
	for _, tc := range []struct{ platform, in, leak string }{
		{"asa", `5" cable, "enable password Cl4veImpar"`, "Cl4veImpar"},                   // comilla impar antes de la cita
		{"asa", `ERROR: % Unable to apply "enable password Cl4veAbierta`, "Cl4veAbierta"}, // cita sin cerrar
		{"asa", `ERROR: "username bob password "Mi Cl4ve" privilege 15"`, "Cl4ve"},        // comillas dentro de la cita
		{"nx-os", `ERROR: "username bob password 0 \"Esc4pada X\" role network-admin"`, "Esc4pada"},
		{"ios-xe", `CMD: 'snmp-server community HistComm RO' 10:00:01 UTC Fri Nov 14 2026`, "HistComm"}, // show history all
		{"ios-xe", `+snmp-server community DiffComm RO`, "DiffComm"},                                    // show archive config differences
		{"nx-os", `Fri Nov 14 10:00:00 2026:type=update:id=vsh.1:user=admin:cmd=configure terminal ; snmp-server community AcctComm group network-operator (SUCCESS)`, "AcctComm"},
		{"ios-xe", `R1(config)#enable password Ec0Prompt`, "Ec0Prompt"}, // eco con prompt
	} {
		out, _ := Apply(tc.platform, tc.in+"\n")
		if strings.Contains(out, tc.leak) {
			t.Errorf("%s %q → %q", tc.platform, tc.in, out)
		}
	}
}

// El terminal también pasa lo citado por las reglas: un applet de EEM tecleado con la clave entre comillas.
func TestTerminalCitado(t *testing.T) {
	var s Stream
	s.Platform = "ios-xe"
	if out := s.Typed(` action 1.0 cli command "enable password T3cleada"`); strings.Contains(out, "T3cleada") {
		t.Errorf("Typed: %q", out)
	}
	if out := s.Prompted(`action 2.0 cli command "username x password 0 Pr0mpted"`, ""); strings.Contains(out, "Pr0mpted") {
		t.Errorf("Prompted: %q", out)
	}
}

// No se enmascara de más: descripciones y remarks son texto libre, el inventario y la prosa entre comillas no cambian.
func TestCitasQueNoSeTocan(t *testing.T) {
	for _, in := range []string{
		` description "password reset portal"`,
		` 10 remark "rotate the key monthly"`,
		`NAME: "Secret Module", DESCR: "Secret Module key 100W"`,
		`System image file is "bootflash:packages.conf"`,
		`INFO: "Press any key to continue"`,
	} {
		if out, _ := Apply("ios-xe", in+"\n"); out != in+"\n" {
			t.Errorf("cambió: %q → %q", in, out)
		}
	}
}

// Una línea enorme (JSON de MB) usa el modo por pares, lineal: lo citado igual se enmascara.
func TestLineaEnormeCitada(t *testing.T) {
	in := strings.Repeat(`"a" `, 100) + `"enable password En0rme"` + strings.Repeat(" x", 5000) + "\n"
	if out, _ := Apply("asa", in); strings.Contains(out, "En0rme") {
		t.Fatal("la línea enorme dejó la clave")
	}
}
