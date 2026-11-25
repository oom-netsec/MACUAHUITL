package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// paso de una sesión: salida del equipo (out) o lo tecleado.
type paso struct {
	out bool
	s   string
}

func eq(s string) paso  { return paso{true, s} }
func tec(s string) paso { return paso{false, s} }

func sesionTA(pasos []paso) string {
	var b bytes.Buffer
	r := NewRecorder(&b, func() time.Time { return time.Unix(0, 0).UTC() })
	for _, p := range pasos {
		if p.out {
			r.Output([]byte(p.s))
		} else {
			r.Input([]byte(p.s))
		}
	}
	r.Close()
	return b.String()
}

func porByte(s string) []paso {
	var out []paso
	for _, c := range []byte(s) {
		out = append(out, eq(string(c)))
	}
	return out
}

// Contraseña tecleada antes de que llegue su prompt (type-ahead), en todas las formas vistas en la auditoría y en las
// revisiones: no se graba.
func TestTypeAheadNoGrabaLaContrasena(t *testing.T) {
	casos := []struct {
		nombre, secreto string
		pasos           []paso
	}{
		{"primera tecla antes", "S3cretEnable9", []paso{eq("\r\nSW1>"), tec("enable\r"), tec("S"), eq("enable\r\nPassword: "), tec("3cretEnable9\r"), eq("\r\nSW1#")}},
		{"eco rezagado", "S3cretEnable9", []paso{eq("\r\nSW1>"), tec("enabl"), eq("enab"), tec("e\r"), eq("le"), tec("S3cretEnable9\r"), eq("\r\nPassword: "), eq("\r\nSW1#")}},
		{"aaa lento", "S3cretAAA9", []paso{eq("\r\n\r\nUser Access Verification\r\n\r\nUsername: "), tec("admin\r"), eq("admin\r\n"), tec("S3cretAAA9\r"), eq("Password: "), eq("\r\nSW1>")}},
		{"dos retenidas", "S3cretEn9", []paso{eq("\r\nSW1>"), tec("terminal length 0\r"), tec("enable\r"), tec("S3cretEn9\r"), eq("terminal length 0\r\nSW1>enable\r\nPassword: "), eq("\r\nSW1#")}},
		{"dos retenidas en trozos", "S3cretEn9", []paso{eq("\r\nSW1>"), tec("show clock\r"), tec("enable\r"), tec("S3cretEn9\r"), eq("show clock\r\n*10:00:00 UTC\r\nSW1>"), eq("enable\r\nPassword: "), eq("\r\nSW1#")}},
		{"enter vacío y pegado", "S3cretLog9", []paso{eq("\r\nUsername: "), tec("\radmin\rS3cretLog9\r"), eq("\r\nUsername: admin\r\nPassword: "), eq("\r\nSW1>")}},
		{"syslog entre prompt y tecla", "S3cretSys9", []paso{eq("\r\nSW1>"), tec("enable\r"), eq("enable\r\nPassword: "), eq("\r\n*Nov 25 10:00:01.123: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/11, changed state to up\r\n"), tec("S3cretSys9\r"), eq("\r\nSW1#")}},
		{"varias líneas en un trozo", "S3cretEnable9", []paso{eq("\r\nSW1>"), tec("enable\rS3cretEnable9\rshow run | i secret\r"), eq("enable\r\nPass"), eq("word: \r\nSW1#show run | i secret\r\nenable secret 9 $9$abc\r\nSW1#")}},
	}
	// Revisión 1 de la rama: eco editado (retroceso, Tab, flecha), contraseña igual al usuario, contraseña que empieza
	// como el eco partido del comando anterior y prompt partido con el Enter en medio.
	casos = append(casos, []struct {
		nombre, secreto string
		pasos           []paso
	}{
		{"retroceso en lo adelantado", "S3cretTypo9", []paso{eq("\r\nR1>"), tec("show clock\r"), eq("show clock\r\n"), tec("enablx\x7fe\r"), eq("*10:00:00 UTC\r\nR1>"), eq("enablx\b \be\r\nPassword: "), tec("S3cretTypo9\r"), eq("\r\nR1#")}},
		{"retroceso en un trozo", "S3cretTypo9", []paso{eq("\r\nR1>"), tec("show clock\r"), eq("show clock\r\n"), tec("enablx\x7fe\r"), eq("*10:00:00 UTC\r\nR1>enablx\b \be\r\nPassword: "), tec("S3cretTypo9\r"), eq("\r\nR1#")}},
		{"tab", "S3cretTab9", []paso{eq("\r\nR1>"), tec("show clock\r"), eq("show clock\r\n"), tec("en\t\r"), eq("*10:00:00 UTC\r\nR1>"), eq("enable\r\nPassword: "), tec("S3cretTab9\r"), eq("\r\nR1#")}},
		{"flecha arriba", "S3cretArr9", []paso{eq("\r\nR1#"), tec("show clock\r"), eq("show clock\r\n"), tec("\x1b[A\r"), eq("*10:00:00 UTC\r\nR1#"), eq("show clock\r\n*10:00:01 UTC\r\nR1#"), tec("disable\r"), eq("disable\r\nR1>"), tec("enable\r"), eq("enable\r\nPassword: "), tec("S3cretArr9\r"), eq("\r\nR1#")}},
		{"eco editado envenena", "S3cretLater9", []paso{eq("\r\nR1>"), tec("show clock\r"), eq("show clock\r\n"), tec("show verx\x7fsion\r"), eq("*10:00:00 UTC\r\nR1>"), eq("show verx\b \bsion\r\nCisco IOS\r\nR1>"),
			tec("show users\r"), eq("show users\r\n  Line  User\r\nR1>"), tec("enable\r"), eq("enable\r\nPassword: "), tec("S3cretLater9\r"), eq("\r\nR1#"), tec("show clock\r"), eq("show clock\r\n*10:00 UTC\r\nR1#")}},
		{"su en linux", ">>> admin", []paso{eq("\r\nbob@srv:~$ "), tec("su admin\r"), tec("admin\r"), eq("su admin\r\nPassword: "), eq("\r\nadmin@srv:~$ ")}},
		{"empieza como el eco partido", "S3cretPre9", []paso{eq("\r\nR1>"), tec("enable\r"), tec("eS3cretPre9\r"), eq("e\r\n*Mar  1 00:00:01.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"), eq("nable\r\nPassword: "), eq("\r\nR1#")}},
		{"prompt partido con el Enter en medio", "S3cretSplit9", []paso{eq("\r\nR1>"), tec("enable\r"), tec("S3cretSplit9"), eq("enable\r\nPass"), tec("\r"), eq("word: "), eq("\r\nR1#")}},
		{"prompt partido 2", "S3cretSplit9", []paso{eq("\r\nR1>"), tec("enable\r"), eq("enable\r\nPass"), tec("S3cretSplit9\r"), tec("show clock\r"), eq("word: "), eq("\r\nR1#"), eq("show clock\r\n*10:00 UTC\r\nR1#")}},
	}...)
	for _, c := range casos {
		if s := sesionTA(c.pasos); strings.Contains(s, c.secreto) {
			t.Errorf("%s: FUGA\n%s", c.nombre, s)
		}
	}
	// Contraseña igual al usuario (cisco/cisco): el usuario se graba una vez y la contraseña no.
	for _, pasos := range [][]paso{
		{eq("\r\nUsername: "), tec("cisco\r"), tec("cisco\r"), eq("cisco\r\nPassword: "), eq("\r\nR1>")},
		{eq("\r\nUser Access Verification\r\n\r\nUsername: "), tec("c"), eq("c"), tec("i"), eq("i"), tec("s"), eq("s"), tec("c"), eq("c"), tec("o"), eq("o"), tec("\r"), tec("cisco\r"), eq("\r\nPassword: "), eq("\r\nR1>")},
	} {
		if s := sesionTA(pasos); strings.Count(s, ">>> cisco") != 1 || !strings.Contains(s, ">>> [hidden]") {
			t.Errorf("usuario igual a la contraseña:\n%s", s)
		}
	}
	// Byte a byte (consola serie a 9600): la contraseña adelantada tampoco.
	pasos := []paso{eq("\r\nSW1>"), tec("enable\r"), tec("S3cretByte9\r")}
	pasos = append(pasos, porByte("enable\r\nPassword: \r\nSW1#")...)
	if s := sesionTA(pasos); strings.Contains(s, "S3cretByte9") {
		t.Errorf("byte a byte: FUGA\n%s", s)
	}
}

// Lo que ya funcionaba y no debe romperse al arreglar lo anterior (regresiones vistas en revisión).
func TestTypeAheadNoRompeLoQueFuncionaba(t *testing.T) {
	// El eco rezagado del primer comando no hace que «enable» se tome por la contraseña.
	s := sesionTA([]paso{eq("\r\nR1>"), tec("show clock\r"), eq("k"), tec("enable\r"), eq("\r\n*10:00:00 UTC\r\nR1>en"), eq("able\r\nPassword: "), tec("S3cretRz9\r"), eq("\r\nR1#")})
	if strings.Contains(s, "S3cretRz9") || !strings.Contains(s, ">>> enable") {
		t.Errorf("eco rezagado:\n%s", s)
	}
	// Un comando que termina en «…key…:» con el eco partido por un syslog: el resto del eco sigue tapado.
	pasos := []paso{eq("\r\nSW1#")}
	for _, c := range "copy scp://admin" {
		pasos = append(pasos, tec(string(c)), eq(string(c)))
	}
	pasos = append(pasos, eq("\r\n*Mar  1 00:00:01: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"))
	for _, c := range ":Adm1nPw@10.0.0.5/certs/router-key.pem bootflash:" {
		pasos = append(pasos, tec(string(c)), eq(string(c)))
	}
	pasos = append(pasos, tec("\r"), eq("\r\nDestination filename [router-key.pem]? "))
	if s := sesionTA(pasos); strings.Contains(s, "Adm1nPw") {
		t.Errorf("copy scp partido:\n%s", s)
	}
	// Comandos normales, también los que terminan en «:», se graban (enmascarados si llevan secreto).
	s = sesionTA([]paso{eq("\r\nR1#"), tec("show crypto key mypubkey rsa | i Key name:\r"), eq("show crypto key mypubkey rsa | i Key name:\r\n Key name: R1.lab\r\nR1#"), tec("show version\r"), eq("show version\r\nCisco IOS\r\nR1#")})
	if !strings.Contains(s, ">>> show crypto key mypubkey rsa | i Key name:") || !strings.Contains(s, ">>> show version") {
		t.Errorf("comandos:\n%s", s)
	}
	// «Key Data:» de un show no es un prompt de secreto: lo tecleado después (o adelantado) se graba.
	for _, pasos := range [][]paso{
		{eq("\r\nR1#"), tec("show crypto key mypubkey rsa\r"), tec("show clock\r"), eq("show crypto key mypubkey rsa\r\nKey name: R1.lab\r\n Key Data:\r\n  30820122 300D0609\r\nR1#"), eq("show clock\r\n*10:00 UTC\r\nR1#")},
		{eq("\r\nR1#"), tec("show crypto key mypubkey rsa\r"), eq("show crypto key mypubkey rsa\r\nKey name: R1.lab\r\n Key Data:\r\n"), tec("s"), eq("  30820122 300D0609\r\nR1#"), eq("s"), tec("how clock\r"), eq("how clock\r\n*10:00 UTC\r\nR1#")},
	} {
		if s := sesionTA(pasos); !strings.Contains(s, ">>> show clock") || strings.Contains(s, "[hidden]") {
			t.Errorf("Key Data:\n%s", s)
		}
	}
	// La contraseña en su prompt, tecleada después de que llega, sigue oculta como siempre.
	s = sesionTA([]paso{eq("\r\nasa> "), tec("enable\r"), eq("enable\r\nPassword: "), tec("AsaPw9x\r"), eq("\r\nasa# ")})
	if strings.Contains(s, "AsaPw9x") || !strings.Contains(s, ">>> [hidden]") {
		t.Errorf("asa:\n%s", s)
	}
}

// Opción A (2026-11-25): lo tecleado se graba solo con su eco. Un eco partido por syslog en varios trozos se reconstruye
// y el comando se graba; lo que nunca hizo eco sale [hidden].
func TestEcoPartidoEnTrozosSeReconstruye(t *testing.T) {
	syslog := "\r\n*Mar  1 00:00:01.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"
	s := sesionTA([]paso{eq("\r\nR1#"), tec("show running-config\r"), eq("show ru"), eq(syslog), eq("nnin"), eq(syslog), eq("g-config\r\nhostname R1\r\nR1#")})
	if !strings.Contains(s, ">>> show running-config") {
		t.Errorf("eco en trozos:\n%s", s)
	}
	// el primer trozo termina en el espacio entre dos palabras
	s = sesionTA([]paso{eq("\r\nR1#"), tec("show run | sec snmp\r"), eq("show run "), eq(syslog), eq("| sec snmp\r\nR1#")})
	if !strings.Contains(s, ">>> show run | sec ") {
		t.Errorf("eco partido tras un espacio:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nR1#"), tec("show clock\r"), eq("\r\nR1#")}) // el equipo no devolvió el eco
	if !strings.Contains(s, ">>> [hidden]") || strings.Contains(s, ">>> show clock") {
		t.Errorf("sin eco:\n%s", s)
	}
}

// Revisión 1 de la opción A: una línea de salida que termina como la contraseña adelantada no es su eco, ni dos líneas
// ajenas arman el eco; >>> no muestra lo que la salida no grabó ni una palabra que solo aparece dentro de otra.
func TestEcoNoSeConfundeConLaSalida(t *testing.T) {
	casos := []struct {
		nombre, nunca, siempre string
		pasos                  []paso
	}{
		{"comando que termina en la contraseña", ">>> cisco\n", ">>> show run | i cisco", []paso{eq("\r\nR1>"), tec("enable\r"), tec("cisco\r"), eq("enable\r\nPassword: "), eq("\r\nR1#"), tec("show run | i cisco\r"), eq("show run | i cisco\r\nhostname R1\r\nR1#")}},
		{"su que falla y se reteclea", ">>> admin\n", "", []paso{eq("\r\nbob@srv:~$ "), tec("su admin\r"), tec("admin\r"), eq("su admin\r\nPassword: "), eq("\r\nsu: Authentication failure\r\nbob@srv:~$ "), tec("su admin\r"), eq("su admin\r\nPassword: "), tec("x\r"), eq("\r\nsu: Authentication failure\r\nbob@srv:~$ ")}},
		{"banner que termina en la contraseña", ">>> Welcome", ">>> show clock", []paso{eq("\r\nUsername: "), tec("admin\rWelcome\r"), eq("admin\r\nPassword: "), eq("\r\nAuthorized users only. Welcome\r\nR1>"), tec("show clock\r"), eq("show clock\r\n*10:00\r\nR1>")}},
		{"eco armado con salida ajena (linux)", "admin1", ">>> grep -c admin", []paso{eq("\r\nbob@srv:~$ "), tec("sudo -i\r"), tec("admin1\r"), eq("sudo -i\r\n[sudo] password for bob: "), eq("\r\nroot@srv:~# "), tec("grep -c admin\r"), eq("grep -c admin\r\n1\r\nroot@srv:~# ")}},
		{"eco armado con salida ajena (ios)", "Cisco123", ">>> show users | i Cisco", []paso{eq("\r\nR1>"), tec("enable\r"), tec("Cisco123\r"), eq("enable\r\nPassword: "), eq("\r\nR1#"), tec("show users | i Cisco\r"), eq("show users | i Cisco\r\n123\r\nR1#")}},
		{"línea que la salida descarta", "secretkeymaterial", "", []paso{eq("\r\nR1(config)#"), tec("crypto pki import TP pem terminal password Zz9\r"), eq("crypto pki import TP pem terminal password <x>\r\n% Enter PEM-formatted encrypted private key.\r\n"), tec("-----BEGIN RSA PRIVATE KEY-----\rMIIEpAIBAAKCAQEAsecretkeymaterialAAAA\r-----END RSA PRIVATE KEY-----\r\r"), eq("-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEAsecretkeymaterialAAAA\r\n-----END RSA PRIVATE KEY-----\r\n\r\n% PEM files import succeeded.\r\nR1(config)#")}},
		{"secreto dentro del nombre del equipo", ">>> do show run | i cisco", "", []paso{eq("\r\ncisco-sw1(config)#"), tec("username bob secret cisco\r"), eq("username bob secret cisco\r\ncisco-sw1(config)#"), tec("do show run | i cisco\r"), eq("do show run | i cisco\r\ncisco-sw1(config)#")}},
	}
	for _, c := range casos {
		s := sesionTA(c.pasos)
		if strings.Contains(s, c.nunca) || !strings.Contains(s, c.siempre) {
			t.Errorf("%s:\n%s", c.nombre, s)
		}
	}
}

// Cada defensa por separado: el [hidden] de la contraseña adelantada sale en su lugar (antes del fallo), un prompt que
// no es de contraseña («PIN:») no la vuelve eco de un comando posterior, y el comienzo de un eco se olvida si la línea
// siguiente no lo continúa.
func TestEcoDefensasPorSeparado(t *testing.T) {
	s := sesionTA([]paso{eq("\r\nbob@srv:~$ "), tec("su admin\r"), tec("admin\r"), eq("su admin\r\nPassword: "), eq("\r\nsu: Authentication failure\r\nbob@srv:~$ "), tec("admin\r"), eq("admin\r\nadmin: command not found\r\nbob@srv:~$ ")})
	if h, f := strings.Index(s, ">>> [hidden]"), strings.Index(s, "Authentication failure"); h < 0 || h > f {
		t.Errorf("[hidden] fuera de lugar:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nR1>"), tec("token\r"), tec("Cisco123\r"), eq("token\r\nEnter PIN: "), eq("\r\nR1>"), tec("show users | i Cisco123\r"), eq("show users | i Cisco123\r\nR1>")})
	if strings.Contains(s, ">>> Cisco123\n") || !strings.Contains(s, ">>> show users | i Cisco123") {
		t.Errorf("PIN:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nR1>"), tec("token\r"), tec("Cisco123\r"), eq("token\r\nEnter PIN: "), eq("\r\nUsername: Cisco\r\nLogin invalid\r\n123\r\nR1>")})
	if strings.Contains(s, ">>> Cisco123") {
		t.Errorf("eco armado tras una línea ajena:\n%s", s)
	}
}

func TestVisibleOnlyPorPalabra(t *testing.T) {
	for _, c := range []struct{ typed, out, want string }{
		{"show clock", "R1#show clock", "show clock"},
		{"do show run | i cisco", "cisco-sw1(config)#do show run | i <MASKED:secret>", "do show run | i <MASKED:secret>"},
		{"do show run | i cisco", "R1(config)#do show run | i <MASKED:secret> xcisco", "do show run | i <MASKED:secret>"},
		{"username bob secret Zq7", "R1(config)#username bob secret <MASKED:secret>", "username bob secret <MASKED:secret>"},
		{"x secret", "R1#x <MASKED:secret>", "x <MASKED:secret>"},
	} {
		if got := visibleOnly(c.typed, c.out); got != c.want {
			t.Errorf("visibleOnly(%q, %q) = %q, quiero %q", c.typed, c.out, got, c.want)
		}
	}
}

// Revisión 2: un prompt de secreto que devuelve lo tecleado (diálogo setup de IOS) con la respuesta adelantada no la
// graba en >>> ni en la salida, entera o partida por un syslog; y en un eco partido >>> no muestra lo que un trozo
// anterior tapó.
func TestEcoTrasPromptDeSecretoYTrozosTapados(t *testing.T) {
	setup := []paso{eq("\r\nWould you like to enter basic management setup? [yes/no]: "), tec("yes\r"), tec("S3cretSet1\r")}
	for nombre, pasos := range map[string][]paso{
		"entero":  append(append([]paso{}, setup...), eq("yes\r\n  Enter enable secret: "), eq("S3cretSet1\r\n  Enter enable password: ")),
		"partido": append(append([]paso{}, setup...), eq("yes\r\n  Enter enable secret: S3cr"), eq("\r\n*Mar  1 00:00:01.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"), eq("etSet1\r\n  Enter enable password: ")),
	} {
		if s := sesionTA(pasos); strings.Contains(s, "S3cretSet1") || strings.Contains(s, "S3cr\n") || strings.Contains(s, "etSet1") {
			t.Errorf("setup %s:\n%s", nombre, s)
		}
	}
	s := sesionTA([]paso{eq("\r\nadmin@srv:~$ "), tec("snmp-server community Zq7comm RO\r"), eq("snmp-server community Zq7comm RO\r\nbash: snmp-server: not found\r\nadmin@srv:~$ "),
		tec("grep Zq7comm /etc/snmp/x.conf\r"), eq("grep Zq7comm /e"), eq("\r\n%ALERT-1-X: x\r\n"), eq("tc/snmp/x.conf\r\nadmin@srv:~$ ")})
	if strings.Contains(s, "Zq7comm") {
		t.Errorf("eco partido con un trozo tapado:\n%s", s)
	}
}

// Eco desplazado de IOS en una línea larga («R1(config)#$p RM permit 10 …»): es el eco de lo tecleado; lo cortado no
// se tapa, lo que la salida tapó sí. Un trozo corto tras «$» no basta (podría coincidir con una contraseña).
func TestEcoDesplazado(t *testing.T) {
	s := sesionTA([]paso{eq("\r\nR1(config)#"), tec("route-map RM permit 10 ; set community 65000:100\r"), eq("$p RM permit 10 ; set community 65000:100\r\nR1(config)#")})
	if !strings.Contains(s, ">>> route-map RM permit 10 ; set community <MASKED:secret>\n") {
		t.Errorf("desplazado:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nR1>"), tec("token\r"), tec("Xy9secret\r"), eq("token\r\nEnter PIN: "), eq("\r\nR1#"), eq("\r\nR1#$y9secret\r\nR1#")})
	if strings.Contains(s, "Xy9secret") || strings.Contains(s, ">>> y9secret") {
		t.Errorf("trozo corto:\n%s", s)
	}
}

// Revisión 3: lo cortado del eco desplazado pasa por la red de secretos conocidos; un final sin espacios (un PIN largo
// adelantado) no es eco desplazado; el resto de un secreto partido tras un espacio se tapa; y los trozos de un eco
// partido a media palabra se unen sin espacio para comparar con lo que la salida tapó.
func TestEcoRevision3(t *testing.T) {
	cfg := []paso{eq("\r\nR1(config)#"), tec("snmp-server community Zq7comm RO\r"), eq("snmp-server community Zq7comm RO\r\nR1(config)#"), tec("interface Gi0/11\r"), eq("interface Gi0/11\r\nR1(config-if)#")}
	s := sesionTA(append(cfg, tec("description Zq7comm link to the distribution switch number twelve\r"), eq("$ link to the distribution switch number twelve\r\nR1(config-if)#")))
	if strings.Contains(s, "Zq7comm") || !strings.Contains(s, ">>> description <MASKED:secret> link to") {
		t.Errorf("secreto conocido en lo cortado:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nR1>"), tec("token\r"), tec("Xy9secretVeryLongPassword2026abc\r"), eq("token\r\nEnter PIN: "), eq("\r\nR1#"), eq("\r\nR1#$secretVeryLongPassword2026abc\r\nR1#")})
	if strings.Contains(s, ">>> Xy9secret") {
		t.Errorf("PIN largo como eco desplazado:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nWould you like to enter basic management setup? [yes/no]: "), tec("yes\r"), tec("my Long phrase99\r"), eq("yes\r\n  Enter enable secret: my "), eq("\r\n*Mar  1 00:00:01.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"), eq("Long phrase99\r\n  Enter enable password: ")})
	if strings.Contains(s, "phrase99") {
		t.Errorf("resto del secreto tras un espacio:\n%s", s)
	}
	s = sesionTA([]paso{eq("\r\nR1(config)#"), tec("stp pri 4096\r"), eq("stp pr"), eq("\r\n*Mar  1 00:00:01.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"), eq("i 4096\r\nR1(config)#")})
	if strings.Contains(s, ">>> stp <MASKED") {
		t.Errorf("trozos a media palabra:\n%s", s)
	}
}
