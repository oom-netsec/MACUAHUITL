package mask_test

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// Un valor que empieza con comillas sigue con lo pegado tras la de cierre («"abc"Zq…»), por las reglas y por la forma
// genérica; y en lo citado, un valor que llega a una comilla sigue tras ella hasta el espacio («password a"bZq…»).
func TestComillaDentroDelValor(t *testing.T) {
	for _, tc := range []struct{ plat, in string }{
		{"ios-xe", `username bob password 0 "abc"Zq10001`},
		{"ios-xe", `username bob password "a b"Zq10002`},
		{"ios-xe", `ip ospf authentication-key "abc"Zq10003`},
		{"nx-os", `username bob password "a b"Zq10004 role network-admin`},
		{"ios-xe", `snmp-server community ""Zq10005 RO`},
		{"ios-xe", `foo password 0 "abc"Zq10006`},
		{"ios-xe", `zz secret 5 "x"Zq10007 x`},
		{"ios-xe", `ERROR: "username bob password a"bZq10008 x"`},
		{"ios-xe", `ERROR: "username bob password a"b"cZq10009"`},
		{"ios-xe", `ERROR: "snmp-server community \\"secret Zq10010 RO"`},
		{"ios-xe", `*** Output from config line 9, "enable password a"bZq10011"`},
		{"ios-xe", `a\b user x \\"x\\"pass a\\"bZq10012 password Zq10013 psk`},
		// Lo pegado puede traer otra comilla: la paridad que ve lo citado no cambia.
		{"ios-xe", `ntp authentication-key 1 md5 "a"b" 7 x password Zq10015`},
		{"ios-xe", `key 7 "ab"" password Zq10016`},
		{"ios-xe", `   key 1 -- text "ab"Zq10017"`},                         // show key chain
		{"ios-xe", `username u password 0 "x"Zq10018 Zq10019 privilege 15`}, // tipo 0: lo que sigue también
		{"ios-xe", `foo password 0 "x"Zq10020 Zq10021`},
		// Lo que suma el tipo 0 también cuenta para la paridad de lo que sigue.
		{"ios-xe", `tacacs-server key 0 "x"y z"w timeout 5 "bar" hello key Zq10022`},
		{"ios-xe", `username u password 0 "x"y z"w privilege 15 "bar" foo key Zq10023`},
	} {
		out, _ := mask.Apply(tc.plat, tc.in+"\n")
		if marca.MatchString(out) {
			t.Errorf("%s %q → %q", tc.plat, tc.in, out)
		}
		if again, _ := mask.Apply(tc.plat, out); again != out {
			t.Errorf("no idempotente %q:\n1: %q\n2: %q", tc.in, out, again)
		}
	}
	// El eco de la terminal partido por un syslog tampoco deja ver la cola del valor.
	c := `a\b user x \\"x\\"pass a\\"bZq76330 password Zq86330 psk`
	if out := sesion(nuevo, guion("R1(config)#", []string{c}, false, false, true), 3); strings.Contains(out, "Zq76330") || strings.Contains(out, "Zq86330") {
		t.Errorf("eco partido: %q", out)
	}
	// Lo que no es secreto sigue igual: la comilla que cierra la cita queda y lo de después también.
	// Con NBSP, el tramo de la copia normalizada no se come la palabra de al lado.
	if out, _ := mask.Apply("ios-xe", "snmp-server community\u00a0public RO\n"); !strings.HasPrefix(out, "snmp-server community") {
		t.Errorf("NBSP: %q", out)
	}
	// La puntuación tras la comilla de cierre no es parte del valor.
	for in, want := range map[string]string{
		`ERROR: "snmp-server community public", line 3`:            `ERROR: "snmp-server community <MASKED:snmp-community>", line 3`,
		`WARNING: "username bob password Cl4ve".`:                  `WARNING: "username bob password <MASKED:user-secret>".`,
		`% Invalid input detected: "enable password Cl4ve"; retry`: `% Invalid input detected: "enable password <MASKED:enable-secret>"; retry`,
		`*** Output from config line 9, "enable password Cl4ve".`:  `*** Output from config line 9, "enable password <MASKED:enable-secret>".`,
	} {
		if out, _ := mask.Apply("ios-xe", in+"\n"); out != want+"\n" {
			t.Errorf("%q → %q, quería %q", in, out, want)
		}
	}
	for _, in := range []string{`ERROR: "enable password Cl4ve" was rejected`, `description "a b"c`, `banner motd "x"y`} {
		out, _ := mask.Apply("ios-xe", in+"\n")
		if strings.Contains(in, "Cl4ve") {
			if out != `ERROR: "enable password <MASKED:enable-secret>" was rejected`+"\n" {
				t.Errorf("%q → %q", in, out)
			}
		} else if out != in+"\n" {
			t.Errorf("tapó de más: %q → %q", in, out)
		}
	}
}
