package mask

import (
	"strings"
	"testing"
)

// Command: el comando tecleado puede venir abreviado; cada caso es un valor que no debe sobrevivir.
func TestCommandAbreviaturas(t *testing.T) {
	for _, tc := range []struct{ in, leak string }{
		{"cry isa key ZQ1xx add 1.1.1.1", "ZQ1xx"},
		{"tacacs-s key ZQ2xx", "ZQ2xx"},
		{"rad key ZQ3xx", "ZQ3xx"},
		{"ena secret ZQ4xx", "ZQ4xx"},
		{"enab password ZQ5xx", "ZQ5xx"},
		{"enab password level 5 ZQ5yy", "ZQ5yy"},
		{"snmp-s community ZQ6xx RO", "ZQ6xx"},
		{"user bob secret ZQ7xx", "ZQ7xx"},
		{"username bob pri 15 secret 0 ZQ8xx", "ZQ8xx"},
		{"ntp authe 1 md5 ZQ9xx", "ZQ9xx"},
		{"ntp authentication-key 10 md5 ZQ9yy", "ZQ9yy"},
		{"nei 1.1.1.1 password ZQ15xx", "ZQ15xx"},
		{"ip os authentication-key ZQ12xx", "ZQ12xx"},
		{"ip ospf mess 1 md5 ZQ14xx", "ZQ14xx"},
		{"ip ospf mess 1 md5 7 ZQ14yy", "ZQ14yy"},
		{"stan 1 authentication text ZQ10xx", "ZQ10xx"},
		{"stan 1 auth md5 key-s ZQ4xx", "ZQ4xx"},
		{"stan 1 auth text ZQ6xx", "ZQ6xx"},
		{"snmp user u g v3 auth sha ZQ25xx priv aes 128 ZQ26xx", "ZQ25xx"},
		{"snmp user u g v3 auth sha ZQ25xx priv aes 128 ZQ26xx", "ZQ26xx"},
		{"snmp-s user u g v3 au sha ZQ1xx pr aes 128 ZQ2xx", "ZQ2xx"},
		{"auth text ZQ17xx", "ZQ17xx"},
		{"auth md5 key-string ZQ18xx", "ZQ18xx"},
		{"pre-sh ZQ18yy", "ZQ18yy"},
		{"license smart reg idt ZQ24xx", "ZQ24xx"},
		{"username bob secret  ZQ16xx", "ZQ16xx"},
		{"username bob secret\tZQ16yy", "ZQ16yy"},
		{"SNMP-S COMM ZQ30xx RO", "ZQ30xx"},
		{"pre-shared-key address 1.1.1.1 key ZQ31xx", "ZQ31xx"},
	} {
		out, vals := Command(tc.in)
		if strings.Contains(out, tc.leak) || !strings.Contains(out, "<MASKED:") {
			t.Errorf("%q → %q (valores %v)", tc.in, out, vals)
		}
		found := false
		for _, v := range vals {
			found = found || v == tc.leak
		}
		if !found {
			t.Errorf("%q: valores %v sin %q", tc.in, vals, tc.leak)
		}
	}
}

// Command: lo que no es un secreto no se toca, y la lista nunca trae palabras clave ni estructurales.
func TestCommandNoTocaLoQueNoEsSecreto(t *testing.T) {
	for _, in := range []string{
		"show run | sec snmp", "do show run | sec crypto", "sh run | sec user", "show crypto key mypubkey rsa",
		"description enlace key principal", "key chain KC1", "ip ospf authentication message-digest",
		"aaa authentication login default local", "interface Gi0/1", "username bob privilege 15", "ip route 10.0.0.0 255.0.0.0 1.1.1.1",
	} {
		if out, vals := Command(in); out != in || len(vals) != 0 {
			t.Errorf("%q → %q %v", in, out, vals)
		}
	}
	// Tras la barra no se toca nada; antes sí.
	out, _ := Command("snmp-s comm ZQ40xx RO | sec snmp")
	if strings.Contains(out, "ZQ40xx") || !strings.HasSuffix(out, "| sec snmp") {
		t.Errorf("%q", out)
	}
	// Los valores cortos o ya tapados no se anotan; el número de tipo y el algoritmo tampoco.
	_, vals := Command("enable secret 5 abc")
	if len(vals) != 0 {
		t.Errorf("valor corto anotado: %v", vals)
	}
	out, vals = Command("enable secret 5 <MASKED:enable-secret>")
	if len(vals) != 0 || strings.Contains(out, "<MASKED:secret>") {
		t.Errorf("doble máscara: %q %v", out, vals)
	}
}

// Cmd con varias líneas: cada una se procesa.
func TestCmdMultilinea(t *testing.T) {
	out := Cmd("ios-xe", "key ZQ50xx\nsnmp-s comm ZQ51xx RO\npassword ZQ52xx")
	for _, l := range []string{"ZQ50xx", "ZQ51xx", "ZQ52xx"} {
		if strings.Contains(out, l) {
			t.Errorf("fuga de %s: %q", l, out)
		}
	}
}

func TestCommandAbreviaturasConGuion(t *testing.T) {
	for _, in := range []string{"ip ospf auth-key ZQ80xx", "ip ospf authentication-k ZQ80xx", "ip ospf message-d 1 md5 ZQ80xx", "key-str ZQ80xx"} {
		if out, _ := Command(in); strings.Contains(out, "ZQ80xx") {
			t.Errorf("%q → %q", in, out)
		}
	}
	for _, in := range []string{"ip ospf authentication message-digest", "ip ospf message-digest", "key-chain KC1", "ntp server 1.1.1.1 key-id 3"} {
		if out, _ := Command(in); out != in {
			t.Errorf("%q → %q", in, out)
		}
	}
}

// Tras un «|» no se toca nada, ni siquiera con otra palabra de secreto.
func TestCommandNoTocaTrasLaBarra(t *testing.T) {
	in := "ena secret ZQ90xx | sec password"
	if out, _ := Command(in); strings.Contains(out, "ZQ90xx") || !strings.HasSuffix(out, "| sec password") {
		t.Errorf("%q", out)
	}
}
