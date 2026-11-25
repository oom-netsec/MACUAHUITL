package terminal

import (
	"strings"
	"testing"
)

func noLeaks(t *testing.T, label, out string, leaks ...string) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(out, l) {
			t.Errorf("%s: fuga de %q:\n%s", label, l, out)
		}
	}
	if strings.Contains(out, "<MASKED:<MASKED") {
		t.Errorf("%s: máscara anidada:\n%s", label, out)
	}
}

// CRÍTICA: lo tecleado en exec (R1#) con un filtro «| sec …» no debe tapar la salida del equipo antes de las reglas.
func TestFiltroSecEnExecNoRompeLasReglas(t *testing.T) {
	for _, tc := range []struct {
		cmd, show string
		leaks     []string
	}{
		{"show run | sec snmp", "snmp-server community PUBCOMM1 RO\r\nsnmp-server user u g v3 auth sha AUTHZQ4 priv aes 128 PRIVZQ5\r\n", []string{"PUBCOMM1", "AUTHZQ4", "PRIVZQ5"}},
		{"show run | sec tacacs", "tacacs-server key TACZQ6\r\n", []string{"TACZQ6"}},
		{"show run | sec crypto", "crypto isakmp key PSKZQ1 address 0.0.0.0\r\n", []string{"PSKZQ1"}},
		{"show run | sec line", "line vty 0 4\r\n password LINEZQ3\r\n", []string{"LINEZQ3"}},
		{"show run | sec neighbor", " neighbor 1.1.1.1 password BGPZQ5\r\n", []string{"BGPZQ5"}},
		{"show run | sec user", "username bob secret 0 USRZQ7\r\n", []string{"USRZQ7"}},
	} {
		r, b := newRec()
		r.Output([]byte("R1#"))
		r.Input([]byte(tc.cmd + "\r"))
		r.Output([]byte(tc.cmd + "\r\n" + tc.show + "R1#"))
		r.Close()
		noLeaks(t, tc.cmd, b.String(), tc.leaks...)
		if !strings.Contains(b.String(), "| sec") {
			t.Errorf("%s: el comando tecleado no se grabó entero:\n%s", tc.cmd, b.String())
		}
	}
}

// CRÍTICA: tras teclear secretos en config, un «do show run» sigue saliendo enmascarado y sin máscaras anidadas.
func TestDoShowRunTrasTeclearSecretos(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("R1(config)#"))
	for _, c := range []string{"username bob pri 15 secret 0 BOBZQ8"} {
		r.Input([]byte(c + "\r"))
		r.Output([]byte(c + "\r\nR1(config)#"))
	}
	r.Input([]byte("do show run\r"))
	r.Output([]byte("do show run\r\nenable secret 9 $9$AAAAAAAAAAAAAA$bbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n" +
		"username admin privilege 15 secret 9 $9$CCCCCCCCCCCCCC$dddddddddddddddddddddddddddd\r\nR1(config)#"))
	r.Close()
	noLeaks(t, "do show run", b.String(), "BOBZQ8", "AAAAAAAAAAAAAA", "CCCCCCCCCCCCCC")
}

// ALTA: abreviaturas tecleadas en modo config, en lo tecleado y en el eco.
func TestAbreviaturasEnConfig(t *testing.T) {
	for _, tc := range []struct{ prompt, cmd, leak string }{
		{"R1(config)#", "cry isa key ZQ1xx add 1.1.1.1", "ZQ1xx"},
		{"R1(config)#", "tacacs-s key ZQ2xx", "ZQ2xx"},
		{"R1(config)#", "rad key ZQ3xx", "ZQ3xx"},
		{"R1(config)#", "ena secret ZQ4xx", "ZQ4xx"},
		{"R1(config)#", "enab password ZQ5xx", "ZQ5xx"},
		{"R1(config)#", "snmp-s community ZQ6xx RO", "ZQ6xx"},
		{"R1(config)#", "user bob secret ZQ7xx", "ZQ7xx"},
		{"R1(config)#", "ntp authe 1 md5 ZQ9xx", "ZQ9xx"},
		{"R1(config-router)#", "nei 1.1.1.1 password ZQ15xx", "ZQ15xx"},
		{"R1(config-if)#", "ip os authentication-key ZQ12xx", "ZQ12xx"},
		{"R1(config-if)#", "ip ospf mess 1 md5 ZQ14xx", "ZQ14xx"},
		{"R1(config-if)#", "stan 1 authentication text ZQ10xx", "ZQ10xx"},
		{"R1(config)#", "snmp user u g v3 auth sha ZQ25xx priv aes 128 ZQ26xx", "ZQ25xx"},
		{"R1(config)#", "snmp user u g v3 auth sha ZQ25xx priv aes 128 ZQ26xx", "ZQ26xx"},
		{"SW1(config-if-hsrp)#", "auth text ZQ17xx", "ZQ17xx"},
		{"SW1(config-if-hsrp)#", "auth md5 key-string ZQ18xx", "ZQ18xx"},
		{"R1(config)#", "username bob secret  ZQ16xx", "ZQ16xx"},
	} {
		r, b := newRec()
		r.Output([]byte(tc.prompt))
		r.Input([]byte(tc.cmd + "\r"))
		r.Output([]byte(tc.cmd + "\r\n" + tc.prompt))
		r.Close()
		noLeaks(t, tc.cmd, b.String(), tc.leak)
		// Solo el eco (sin haber teclado): la línea del equipo también sale tapada.
		r, b = newRec()
		r.Output([]byte(tc.prompt + tc.cmd + "\r\n" + tc.prompt))
		r.Close()
		noLeaks(t, "eco "+tc.cmd, b.String(), tc.leak)
	}
}

// El valor tapado en lo tecleado se tapa también donde reaparezca (red por contenido), y solo los valores se anotan:
// ni las palabras clave ni el filtro tapan la salida del equipo.
func TestRedPorContenidoSoloValores(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("R1(config)#"))
	r.Input([]byte("ena secret ZQ4xx\r"))
	r.Output([]byte("ena secret ZQ4xx\r\notro ZQ4xx\r\nR1(config)#"))
	r.Close()
	noLeaks(t, "contenido", b.String(), "ZQ4xx")
	if r.secrets != nil && indexOf(r.secrets, "secret") >= 0 || indexOf(r.secrets, "ena") >= 0 {
		t.Errorf("se anotó una palabra clave: %v", r.secrets)
	}
}

// M2: avisos de secreto que antes no se reconocían.
func TestAvisosDeSecretoGenerales(t *testing.T) {
	for _, prompt := range []string{
		"Enter TACACS+ key:", "Enter Radius key:", "Key:", "Enter PSK:", "Enter community string:", "Enter token:", "PIN:",
		"Enter PEM pass phrase:", "Enter the encryption key:", "Encryption key:", "Enter API key:", "Enter Secret: ",
	} {
		r, b := newRec()
		r.Output([]byte("R1#\r\n" + prompt))
		r.Input([]byte("HIDDENZQ1\r"))
		r.Output([]byte("\r\nR1#"))
		r.Close()
		if out := b.String(); strings.Contains(out, "HIDDENZQ1") || !strings.Contains(out, ">>> [hidden]") {
			t.Errorf("%q:\n%s", prompt, out)
		}
	}
	for _, prompt := range []string{"Press any key to continue: ", "Destination filename [x]? ", "Enter selection: "} {
		r, b := newRec()
		r.Output([]byte("R1#\r\n" + prompt))
		r.Input([]byte("show clock\r"))
		// Desde 2026-11-25 lo tecleado se graba (>>>) solo cuando el equipo devuelve su eco; sin eco sale [hidden]. Aquí el
		// equipo hace eco, como uno real.
		r.Output([]byte("show clock\r\n"))
		r.Close()
		if !strings.Contains(b.String(), ">>> show clock") {
			t.Errorf("%q ocultó lo tecleado:\n%s", prompt, b.String())
		}
	}
}

// Tabla de abreviaturas reales de IOS: el prefijo mínimo y uno intermedio de cada palabra clave, tecleados en modo
// config y en el eco tras el prompt.
func TestTablaDeAbreviaturasDeIOS(t *testing.T) {
	const cfg, keyc, line = "R1(config)#", "R1(config-keychain-key)#", "R1(config-line)#"
	for _, tc := range []struct{ prompt, cmd string }{
		{cfg, "ena sec ZQT01xx"}, {cfg, "enab secre ZQT02xx"},
		{cfg, "usern U sec ZQT03xx"}, {cfg, "userna U secr ZQT04xx"},
		{cfg, "snmp-s comm ZQT05xx RO"}, {cfg, "snmp-ser commun ZQT06xx RO"},
		{cfg, "cry isa key ZQT07xx add 1.1.1.1"}, {cfg, "cryp isak key ZQT08xx add 1.1.1.1"},
		{cfg, "tac key ZQT09xx"}, {cfg, "tacacs-s key ZQT10xx"},
		{cfg, "rad key ZQT11xx"}, {cfg, "radius-s key ZQT12xx"},
		{keyc, "key-str ZQT13xx"}, {keyc, "key-stri ZQT14xx"},
		{line, "pass ZQT15xx"}, {line, "passw ZQT16xx"},
		{"R1(config-if)#", "ip ospf auth-key ZQT17xx"}, {"R1(config-if)#", "ip ospf authentication-k ZQT18xx"},
		{"R1(config-if)#", "ip ospf mess 1 md5 ZQT19xx"}, {"R1(config-if)#", "ip ospf message-d 1 md5 ZQT20xx"},
	} {
		leak := tc.cmd[strings.Index(tc.cmd, "ZQ"):]
		leak = leak[:strings.IndexAny(leak+" ", " ")]
		r, b := newRec()
		r.Output([]byte(tc.prompt))
		r.Input([]byte(tc.cmd + "\r"))
		r.Output([]byte(tc.cmd + "\r\n" + tc.prompt))
		r.Close()
		noLeaks(t, "tecleado "+tc.cmd, b.String(), leak)
		r, b = newRec()
		r.Output([]byte(tc.prompt + tc.cmd + "\r\n" + tc.prompt))
		r.Close()
		noLeaks(t, "eco "+tc.cmd, b.String(), leak)
	}
}

// Negativos: en exec y en la salida no se toca nada; en config, una descripción tampoco.
func TestNegativosDeAbreviaturas(t *testing.T) {
	for _, cmd := range []string{"show run | sec snmp", "show key chain", "sh crypto isakmp key"} {
		r, b := newRec()
		r.Output([]byte("R1#"))
		r.Input([]byte(cmd + "\r"))
		r.Output([]byte(cmd + "\r\nR1#"))
		r.Close()
		if out := b.String(); strings.Count(out, cmd) != 2 || strings.Contains(out, "<MASKED") {
			t.Errorf("%q se tocó:\n%s", cmd, out)
		}
	}
	// Una descripción en config no se toca (Command la deja: es texto libre).
	r, b := newRec()
	r.Output([]byte("R1(config-if)#"))
	r.Input([]byte("description password policy\r"))
	r.Output([]byte("description password policy\r\nR1(config-if)#"))
	r.Close()
	if out := b.String(); strings.Count(out, "description password policy") != 2 {
		t.Errorf("descripción tapada:\n%s", out)
	}
}

// mask.Command nunca recibe la salida de un show: en la salida solo corren las reglas ancladas.
func TestLaSalidaNoPasaPorCommand(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("R1#show run\r\n"))
	r.Output([]byte("interface Gi0/1\r\n description password policy\r\n description key chain de la red\r\n" +
		"snmp-server community OUTZQ1xx RO\r\nR1#"))
	r.Close()
	out := b.String()
	if strings.Contains(out, "OUTZQ1xx") || !strings.Contains(out, "<MASKED:snmp-community>") {
		t.Errorf("la regla anclada no corrió:\n%s", out)
	}
	if !strings.Contains(out, " description password policy") || !strings.Contains(out, " description key chain de la red") {
		t.Errorf("Command tocó la salida:\n%s", out)
	}
	// Una línea de salida con palabras de secreto abreviadas, sin prompt, queda como llegó.
	r, b = newRec()
	r.Output([]byte("R1#show x\r\nthe sec value is here and pass word\r\nR1#"))
	r.Close()
	if !strings.Contains(b.String(), "the sec value is here and pass word") {
		t.Errorf("%s", b.String())
	}
}

// Un valor tecleado que coincide con una palabra del comando de la salida («enable», «secret») no desarma las reglas
// ancladas ni se mete dentro de un <MASKED:…>.
func TestValorTecleadoIgualAPalabraDeLaSalida(t *testing.T) {
	for _, val := range []string{"enable", "secret", "username"} {
		r, b := newRec()
		r.Output([]byte("R1(config)#"))
		r.Input([]byte("username bob secret 0 " + val + "\r"))
		r.Output([]byte("username bob secret 0 " + val + "\r\nR1(config)#"))
		r.Input([]byte("do show run\r"))
		r.Output([]byte("do show run\r\nenable secret 9 $9$HASHENABLE0123$abcdefghijklmnopqrstuv\r\n" +
			"username admin privilege 15 secret 9 $9$HASHADMIN0123$abcdefghijklmnopqrstuv\r\nR1(config)#"))
		r.Close()
		noLeaks(t, val, b.String(), "HASHENABLE0123", "HASHADMIN0123")
	}
}

// Solo valores de 4 o más caracteres entran a la red por contenido.
func TestRedPorContenidoIgnoraValoresCortos(t *testing.T) {
	r, _ := newRec()
	r.Output([]byte("R1(config)#"))
	r.Input([]byte("ena secret ab\r"))
	if len(r.secrets) != 0 {
		t.Errorf("se anotó un valor corto: %v", r.secrets)
	}
}
