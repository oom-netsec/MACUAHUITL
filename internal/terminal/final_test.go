package terminal

import (
	"strings"
	"testing"
)

// C1: avisos de Cisco que piden una llave (key config-key password-encrypt, NX-OS key config-key ascii, IKE).
func TestAvisosDeLlaveNoSeGrabanLoTecleado(t *testing.T) {
	for _, prompt := range []string{
		"New key: ", "Old key:", "Confirm key: ", "Retype key: ", "Enter key:", "Re-enter key: ",
		"New Master Key: ", "Retype Master Key: ", "Old Master Key:", "Enter pre-shared key: ", "Enter the pre-shared key:",
		"Confirm new key: ",
	} {
		r, b := newRec()
		r.Output([]byte("R1(config)#key config-key password-encrypt\r\n" + prompt))
		r.Input([]byte("MASTERK1\r"))
		r.Output([]byte("\r\nR1(config)#"))
		r.Input([]byte("show clock\r"))
		r.Close()
		out := b.String()
		if strings.Contains(out, "MASTERK1") || !strings.Contains(out, ">>> [hidden]") || !strings.Contains(out, ">>> show clock") {
			t.Errorf("%q:\n%s", prompt, out)
		}
	}
	// Los avisos que no piden llave no ocultan lo tecleado.
	r, b := newRec()
	r.Output([]byte("R1#Press any key to continue: "))
	r.Input([]byte("show clock\r"))
	r.Close()
	if !strings.Contains(b.String(), ">>> show clock") {
		t.Errorf("ocultó lo tecleado:\n%s", b.String())
	}
}

// C2: el eco tras el prompt de un submodo sale enmascarado (con el prompt real de cada modo).
func TestEcoTrasElPromptDeSubmodos(t *testing.T) {
	for _, tc := range []struct{ prompt, cmd, leak string }{
		{"R1(config-radius-server)#", "key RADK1", "RADK1"},
		{"R1(config-dot1x-creden)#", "password DOTP1", "DOTP1"},
		{"R1(config-isakmp-group)#", "key ISAK1", "ISAK1"},
		{"R1(config-profile)#", "token UMBTOK1", "UMBTOK1"},
		{"ciscoasa(config-username)#", "password ASAUP1", "ASAUP1"},
		{"R1(config-server-tacacs)#", "key TACK1", "TACK1"},
	} {
		r, b := newRec()
		r.Output([]byte(tc.prompt + tc.cmd + "\r\n" + tc.prompt))
		r.Close()
		if out := b.String(); strings.Contains(out, tc.leak) {
			t.Errorf("solo salida %q:\n%s", tc.prompt, out)
		}
		// Sesión completa: se teclea y el equipo hace eco.
		r, b = newRec()
		r.Output([]byte(tc.prompt))
		r.Input([]byte(tc.cmd + "\r"))
		r.Output([]byte(tc.cmd + "\r\n" + tc.prompt))
		r.Close()
		if out := b.String(); strings.Contains(out, tc.leak) {
			t.Errorf("sesión %q:\n%s", tc.prompt, out)
		}
	}
}

// C2: radius server R, y luego «key X» en el submodo; el eco no deja la llave.
func TestRadiusServerYSuLlaveEnElSubmodo(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("R1(config)#"))
	r.Input([]byte("radius server R\r"))
	r.Output([]byte("radius server R\r\nR1(config-radius-server)#"))
	r.Input([]byte("key RADK1\r"))
	r.Output([]byte("key RADK1\r\nR1(config-radius-server)#"))
	r.Close()
	if out := b.String(); strings.Contains(out, "RADK1") {
		t.Errorf("%s", out)
	}
}

// C2 (c): una línea larga se desplaza («$») y el eco empieza en medio: el valor ya tapado al teclear se tapa en el eco.
func TestEcoDesplazadoDeLineaLarga(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("R1(config)#"))
	r.Input([]byte("snmp-server user admin GRP v3 auth sha AUTHK1 priv aes 128 PRIVK1\r"))
	r.Output([]byte("R1(config)#$min GRP v3 auth sha AUTHK1 priv aes 128 PRIVK1\r\nR1(config)#"))
	r.Close()
	if out := b.String(); strings.Contains(out, "AUTHK1") || strings.Contains(out, "PRIVK1") {
		t.Errorf("%s", out)
	}
}

func tecleado(line string) string {
	r, b := newRec()
	r.Output([]byte("R1(config)#"))
	r.Input([]byte(line + "\r"))
	r.Close()
	return b.String()
}

// M5: formas que IOS acepta y las reglas por palabra completa no ven.
func TestTecleadoEnFormasAbreviadas(t *testing.T) {
	for _, tc := range []struct{ in, leak string }{
		{"usern bob sec SECABR1", "SECABR1"},
		{"usern bob sec 0 SECABR2", "SECABR2"},
		{"usern bob pas PASABR3", "PASABR3"},
		{"enable sec SECABR4", "SECABR4"},
		{"snmp-server comm COMABR5 RO", "COMABR5"},
		{"enable secret  DBLSP1", "DBLSP1"},
		{"enable  secret 0  DBLSP2", "DBLSP2"},
		{"show ver\x15enable secret CTRLU1", "CTRLU1"},
		{"hostname x ; snmp-server community NXSEMI1 group network-operator", "NXSEMI1"},
		{"hostname x ; usern bob sec NXSEMI2 ; exit", "NXSEMI2"},
		{"snmp-server user bob grp v3 aut sha AUTABR1 pri aes 128 PRIABR1", "AUTABR1"},
		{"snmp-server user bob grp v3 aut sha AUTABR1 pri aes 128 PRIABR1", "PRIABR1"},
		{"tacacs-server ke TOKABR1", "TOKABR1"},
		{"crypto isakmp ke ISAABR1 address 1.1.1.1", "ISAABR1"},
	} {
		if out := tecleado(tc.in); strings.Contains(out, tc.leak) || !strings.Contains(out, "<MASKED:") {
			t.Errorf("%q:\n%s", tc.in, out)
		}
	}
	// Ctrl-U descarta lo anterior y la línea ejecutada es la nueva.
	if out := tecleado("show ver\x15show clock"); !strings.Contains(out, ">>> show clock\n") {
		t.Errorf("Ctrl-U no borró la línea:\n%s", out)
	}
	// Lo demás no cambia.
	for _, in := range []string{"crypto key generate rsa", "show running-config", "ip route 0.0.0.0 0.0.0.0 1.1.1.1", "aaa authentication login default local", "interface Gi0/1"} {
		if out := tecleado(in); !strings.Contains(out, ">>> "+in+"\n") {
			t.Errorf("cambió %q:\n%s", in, out)
		}
	}
}

// M5: el eco con doble espacio o abreviado también sale tapado.
func TestEcoEnFormasAbreviadas(t *testing.T) {
	for _, in := range []string{"usern bob sec SECECO1", "enable secret  SECECO1", "snmp-server comm SECECO1 RO"} {
		r, b := newRec()
		r.Output([]byte("R1(config)#" + in + "\r\nR1(config)#"))
		r.Close()
		if out := b.String(); strings.Contains(out, "SECECO1") {
			t.Errorf("%q:\n%s", in, out)
		}
	}
}
