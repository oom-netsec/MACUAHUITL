package terminal

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newRec() (*Recorder, *bytes.Buffer) {
	var b bytes.Buffer
	t := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	return NewRecorder(&b, func() time.Time { return t }), &b
}

func TestGrabaSalidaYTecleadoPorLineas(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("SW1#"))
	r.Input([]byte("show clock\r"))
	r.Output([]byte("show clock\r\n10:00:00 UTC\r\nSW1#"))
	r.Close()
	out := b.String()
	for _, want := range []string{"2026-11-06T10:00:00.000Z SW1#", ">>> show clock", "10:00:00 UTC"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Errorf("trae retornos de carro: %q", out)
	}
}

// El punto delicado: lo que se teclea en un prompt de contraseña no llega al archivo.
func TestNoGrabaLoTecleadoEnUnPromptDeContrasena(t *testing.T) {
	for _, prompt := range []string{"Password: ", "Secret: ", "Enter secret: ", "Old password:", "Username: admin\r\nPassword:"} {
		r, b := newRec()
		r.Output([]byte("SW1>enable\r\n" + prompt))
		r.Input([]byte("s3cr3t-X"))
		r.Input([]byte("\r"))
		r.Output([]byte("\r\nSW1#"))
		r.Input([]byte("show clock\r"))
		r.Close()
		out := b.String()
		if strings.Contains(out, "s3cr3t") {
			t.Errorf("%q: la contraseña quedó grabada:\n%s", prompt, out)
		}
		if !strings.Contains(out, ">>> [oculto]") || !strings.Contains(out, ">>> show clock") {
			t.Errorf("%q: faltan la marca o el comando posterior:\n%s", prompt, out)
		}
	}
}

// El prompt puede llegar partido, y la contraseña pegada de golpe o con el retorno en el mismo bloque.
func TestPromptPartidoYContrasenaPegada(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("Pass"))
	r.Output([]byte("word"))
	r.Output([]byte(": "))
	r.Input([]byte("s3cr3t-Y\rshow version\r"))
	r.Close()
	out := b.String()
	if strings.Contains(out, "s3cr3t") || !strings.Contains(out, ">>> show version") {
		t.Errorf("pegada:\n%s", out)
	}
}

func TestSinPromptDeContrasenaSeGrabaLoTecleado(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("SW1#"))
	r.Input([]byte("show run | include password\r")) // la palabra en un comando no es un prompt
	r.Output([]byte("show run | include password\r\nSW1#"))
	r.Input([]byte("clock\x7f\x7f\x7f\x7f\x7fexit\r"))
	r.Close()
	out := b.String()
	if !strings.Contains(out, ">>> show run | include password") || !strings.Contains(out, ">>> exit") || strings.Contains(out, "clock") {
		t.Errorf("%s", out)
	}
}

func TestCtrlCCancelaElModoOculto(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("Password: "))
	r.Input([]byte("abc\x03"))
	r.Output([]byte("\r\nSW1>"))
	r.Input([]byte("show clock\r"))
	r.Close()
	if out := b.String(); strings.Contains(out, "abc") || !strings.Contains(out, ">>> show clock") {
		t.Errorf("%s", out)
	}
}

// Una línea a medias al cerrar se guarda, salvo que fuera una contraseña.
func TestCierreConLineaAMedias(t *testing.T) {
	r, b := newRec()
	r.Input([]byte("show ver"))
	r.Close()
	if !strings.Contains(b.String(), ">>> show ver") {
		t.Errorf("%s", b.String())
	}
	r, b = newRec()
	r.Output([]byte("Password: "))
	r.Input([]byte("s3cr3t"))
	r.Close()
	if strings.Contains(b.String(), "s3cr3t") {
		t.Errorf("%s", b.String())
	}
}

func TestEnmascaraSecretosEnComandosTecleados(t *testing.T) {
	r, b := newRec()
	r.Input([]byte("username bob secret 0 Hunter2xyz\r"))
	r.Close()
	if out := b.String(); strings.Contains(out, "Hunter2xyz") || !strings.Contains(out, "<MASKED:") {
		t.Errorf("%s", out)
	}
}

// El eco del equipo trae lo tecleado y también debe salir enmascarado, aunque llegue partido.
func TestEnmascaraElEcoYLaSalidaDelEquipo(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("SW1(config)#username bob privilege 15 sec"))
	r.Output([]byte("ret 0 Hunter2X\r\nSW1(config)#"))
	r.Output([]byte("line vty 0 4\r\n password 7 0822455D0A16\r\n"))
	r.Output([]byte("-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEA\r\n-----END RSA PRIVATE KEY-----\r\nSW1#"))
	r.Close()
	out := b.String()
	for _, leak := range []string{"Hunter2X", "0822455D0A16", "MIIEow"} {
		if strings.Contains(out, leak) {
			t.Errorf("quedó en claro %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "SW1(config)#username bob privilege 15 secret 0 <MASKED:user-secret>") || !strings.Contains(out, "SW1(config)#") {
		t.Errorf("se perdió el prompt o el enmascarado:\n%s", out)
	}
}

// Una línea de salida sin fin de línea no crece sin límite.
func TestLineaDeSalidaSinSaltoTieneTope(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("x"))
	big := strings.Repeat("A", lineMax)
	r.Output([]byte(big))
	r.Output([]byte(big))
	r.Output([]byte("\r\nSW1#"))
	r.Close()
	if b.Len() > 3*lineMax/2 || !strings.Contains(b.String(), "línea recortada") {
		t.Errorf("len=%d", b.Len())
	}
}

// La contraseña tecleada antes de que llegue el prompt (pegada, o con el enlace lento) tampoco se graba.
func TestContrasenaTecleadaAntesDelPrompt(t *testing.T) {
	casos := map[string][][]byte{
		"pegado":       {[]byte("enable\rEnSecret9\r")},
		"enlace lento": {[]byte("enable\r"), []byte("EnSecret9\r")},
	}
	for nombre, teclas := range casos {
		r, b := newRec()
		r.Output([]byte("SW1>"))
		for _, k := range teclas {
			r.Input(k)
		}
		r.Output([]byte("enable\r\n")) // el eco llega primero, el prompt después
		r.Output([]byte("Password: "))
		r.Output([]byte("\r\nSW1#"))
		r.Input([]byte("show clock\r"))
		r.Close()
		out := b.String()
		if strings.Contains(out, "EnSecret9") || !strings.Contains(out, ">>> [oculto]") || !strings.Contains(out, ">>> enable") || !strings.Contains(out, ">>> show clock") {
			t.Errorf("%s:\n%s", nombre, out)
		}
	}
}

// Lo retenido que nunca resulta contraseña (llega un prompt normal) se graba, y al cerrar también.
func TestLoRetenidoSeGrabaSiNoEraContrasena(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("SW1#"))
	r.Input([]byte("show clock\rshow version\r"))
	r.Output([]byte("show clock\r\n10:00\r\nSW1#"))
	r.Input([]byte("a\rb\r"))
	r.Close()
	out := b.String()
	for _, want := range []string{">>> show clock", ">>> show version", ">>> a", ">>> b"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q:\n%s", want, out)
		}
	}
}

// Al llegar al tope la grabación avisa y deja de escribir, sin fallar.
func TestTopeDeGrabacion(t *testing.T) {
	r, b := newRec()
	r.max = 200
	for i := 0; i < 50; i++ {
		r.Output([]byte("linea de salida numero uno\r\n"))
	}
	r.Input([]byte("show clock\r"))
	r.Close()
	out := b.String()
	if len(out) > 200+len("### grabación recortada\n")+40 || strings.Count(out, "### grabación recortada") != 1 {
		t.Errorf("len=%d:\n%s", len(out), out)
	}
}

func TestLineaTecleadaTieneTope(t *testing.T) {
	r, b := newRec()
	r.Input([]byte(strings.Repeat("a", 3*lineMax) + "\r"))
	r.Close()
	if b.Len() > lineMax+100 {
		t.Errorf("len=%d", b.Len())
	}
}

// El eco de ASA bajo aaa-server host y license smart: el prompt da el bloque.
func TestEnmascaraEcoDeBloquesDeASA(t *testing.T) {
	for _, prompt := range []string{"ciscoasa(config-aaa-server-host)#key TypedKey", "ciscoasa(config-smart-lic)#token ABC123", "ciscoasa(config-license)#token ABC123"} {
		r, b := newRec()
		r.Output([]byte(prompt + "\r\nciscoasa(config)#"))
		r.Close()
		out := b.String()
		if strings.Contains(out, "TypedKey") || strings.Contains(out, "ABC123") || !strings.Contains(out, "<MASKED:") {
			t.Errorf("%q:\n%s", prompt, out)
		}
	}
}

// Lo tecleado bajo aaa-server host (prompt de ASA) también sale enmascarado.
func TestEnmascaraTecleadoEnBloqueDeASA(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)#"))
	r.Input([]byte("key TypedKey\r"))
	r.Output([]byte("key TypedKey\r\nciscoasa(config-aaa-server-host)#"))
	r.Close()
	if out := b.String(); strings.Contains(out, "TypedKey") {
		t.Errorf("%s", out)
	}
}

// El bloque del prompt vale también para líneas pegadas, con log intercalado o a medias al cerrar.
func TestEnmascaraTecleadoSinPromptPropio(t *testing.T) {
	casos := []struct {
		prompt string
		in     []string
		out    string
		leak   []string
	}{
		{"ciscoasa(config-aaa-server-host)# ", []string{"key K1\rkey K2\r"}, "key K2\r\nciscoasa(config-aaa-server-host)# ", []string{"K1", "K2"}},
		{"ciscoasa(config-smart-lic)# ", []string{"token TOK1\rtoken TOK999\r"}, "", []string{"TOK1", "TOK999"}},
		{"ciscoasa(config-aaa-server-host)# ", []string{"key Se", "cret\r"}, "%ASA-5-111008: User 'x' executed", []string{"Secret"}},
		{"ciscoasa(config-aaa-server-host)# ", []string{"key Pend"}, "", []string{"Pend"}},
	}
	for i, c := range casos {
		r, b := newRec()
		r.Output([]byte(c.prompt))
		for j, in := range c.in {
			r.Input([]byte(in))
			if j == 0 && c.out != "" && len(c.in) > 1 {
				r.Output([]byte(c.out + "\r\n"))
			}
		}
		r.Close()
		out := b.String()
		for _, l := range c.leak {
			if strings.Contains(out, l) {
				t.Errorf("caso %d: quedó en claro %q:\n%s", i, l, out)
			}
		}
	}
}

// exit saca del bloque: lo tecleado después ya no lleva el bloque anterior.
func TestSalirDelBloqueQuitaElBloqueDelTeclado(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("exit\r"))
	r.Output([]byte("exit\r\nciscoasa(config)# "))
	r.Input([]byte("hostname FW1\r"))
	r.Close()
	if out := b.String(); !strings.Contains(out, ">>> hostname FW1") {
		t.Errorf("%s", out)
	}
}

// Al pegar la línea que abre el bloque junto con su clave desde (config)#, el bloque viaja entre líneas tecleadas.
func TestEnmascaraTecleadoPegadoQueAbreElBloque(t *testing.T) {
	casos := []struct{ prompt, in, leak string }{
		{"ciscoasa(config)# ", "aaa-server RAD (inside) host 10.1.1.5\rkey PasteK\r", "PasteK"},
		{"ciscoasa(config)# ", "aaa-server RAD (inside) host 10.1.1.5\r key PasteK2\r", "PasteK2"},
		{"SW1(config)# ", "tacacs server ISE\r key TacPaste\r", "TacPaste"},
		{"SW1(config)# ", "tacacs server ISE\rkey TacPaste2\r", "TacPaste2"},
	}
	for _, c := range casos {
		r, b := newRec()
		r.Output([]byte(c.prompt))
		r.Input([]byte(c.in))
		r.Close()
		if out := b.String(); strings.Contains(out, c.leak) {
			t.Errorf("%q:\n%s", c.in, out)
		}
	}
}

// Un prompt nuevo que cambia de bloque reinicia el bloque de lo tecleado.
func TestPromptNuevoReiniciaElBloqueDeLoTecleado(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config)# "))
	r.Input([]byte("aaa-server RAD (inside) host 10.1.1.5\r"))
	r.Output([]byte("aaa-server RAD (inside) host 10.1.1.5\r\nciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("exit\r"))
	r.Output([]byte("exit\r\nciscoasa(config)# "))
	r.Input([]byte("hostname FW1\r"))
	r.Close()
	if out := b.String(); !strings.Contains(out, ">>> hostname FW1") {
		t.Errorf("%s", out)
	}
}

// El resto de un eco partido por un log asíncrono también se enmascara.
func TestEnmascaraRestoDelEcoTrasUnLog(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("key Secret\r")) // pegado con Enter: el eco llega partido por el log
	r.Output([]byte("key Se"))
	r.Output([]byte("\r\n%ASA-5-111008: User 'x' executed a command\r\n"))
	r.Output([]byte("cret\r\nciscoasa(config-aaa-server-host)# "))
	r.Close()
	if out := b.String(); strings.Contains(out, " cret\n") || strings.Contains(out, "Secret") {
		t.Errorf("%s", out)
	}
}

// exit pegado cierra el bloque: lo que sigue ya no se enmascara por el bloque anterior.
func TestExitPegadoCierraElBloqueTecleado(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config)# "))
	r.Input([]byte("aaa-server RAD (inside) host 10.1.1.5\rkey K1\rexit\rkey Foo2\r"))
	r.Close()
	out := b.String()
	if strings.Contains(out, "K1") || !strings.Contains(out, ">>> key Foo2") {
		t.Errorf("%s", out)
	}
}

// El resto del eco puede traer espacios (clave tipo 0 de varias palabras) y venir tras varios logs.
func TestEnmascaraRestoDelEcoConEspaciosYVariosLogs(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("key 0 My Secret phrase\r"))
	r.Output([]byte("key 0 My Se"))
	r.Output([]byte("\r\n%ASA-5-111008: uno\r\n"))
	r.Output([]byte("%ASA-5-111009: dos\r\n"))
	r.Output([]byte("cret phrase\r\nciscoasa(config-aaa-server-host)# "))
	r.Close()
	out := b.String()
	if strings.Contains(out, "cret phrase") || !strings.Contains(out, "%ASA-5-111009: dos") {
		t.Errorf("%s", out)
	}
}

// Desde un eco enmascarado hasta el siguiente prompt, toda línea de salida que no sea syslog ni aviso del equipo se tapa.
func TestEcoEnmascaradoTapaLaSalidaHastaElPrompt(t *testing.T) {
	asaLog := "Nov 14 2026 10:00:00: %ASA-5-111008: User 'x' executed the 'key' command."
	iosLog := "*Nov 14 10:00:00.123: %SYS-5-CONFIG_I: Configured from console by admin"
	casos := []struct {
		nombre string
		typed  string // lo tecleado (con Enter) antes de que llegue el eco partido
		salida []string
		leak   []string // líneas que no deben salir enteras en claro
		keep   []string
	}{
		{"fuera de bloque", "failover key Secret", []string{"ciscoasa(config)#failover key Se", "\r\n" + asaLog + "\r\n", "cret\r\n", "ciscoasa(config)# "}, []string{"cret"}, []string{asaLog}},
		{"ios con fecha", "enable secret 0 My Secret phrase", []string{"SW1(config)#enable secret 0 My Se", "\r\n" + iosLog + "\r\n", "cret phrase\r\n", "SW1(config)# "}, []string{"cret phrase"}, []string{iosLog}},
		{"partido por dos logs", "failover key Secret", []string{"ciscoasa(config)#failover key Se", "\r\n" + asaLog + "\r\n", "cr\r\n", asaLog + "\r\n", "et\r\n", "ciscoasa(config)# "}, []string{"cr", "et"}, []string{asaLog}},
		{"warning intacto", "", []string{"ciscoasa(config)#enable password 0 Pw1", "\r\nWARNING: Command has been added to the configuration using a type 0 password.\r\nERROR: x\r\nINFO: y\r\nciscoasa(config)# "}, nil, []string{"WARNING: Command has been added", "ERROR: x", "INFO: y"}},
		{"show después del prompt", "failover key Secret", []string{"ciscoasa(config)#failover key Se", "\r\n" + asaLog + "\r\n", "cret\r\n", "ciscoasa# ", "show version\r\nCisco Adaptive Security Appliance\r\nciscoasa# "}, []string{"cret"}, []string{"Cisco Adaptive Security Appliance"}},
	}
	for _, c := range casos {
		r, b := newRec()
		for i, s := range c.salida {
			if i == 0 {
				r.Input([]byte(c.typed + "\r"))
			}
			r.Output([]byte(s))
		}
		r.Close()
		out := b.String()
		for _, l := range c.leak {
			if strings.Contains(out, "Z "+l+"\n") {
				t.Errorf("%s: en claro %q:\n%s", c.nombre, l, out)
			}
		}
		for _, k := range c.keep {
			if !strings.Contains(out, k) {
				t.Errorf("%s: se perdió %q:\n%s", c.nombre, k, out)
			}
		}
	}
}

// Un eco completo (con Enter) de un comando exec con secreto no tapa su salida.
func TestEcoCompletoNoTapaLaSalida(t *testing.T) {
	casos := []struct{ cmd, salida, keep string }{
		{"copy scp://bob:Pw1@10.1.1.9/c.txt flash:c.txt", "Destination filename [c.txt]?\r\nSending file modes:\r\n!\r\n1234 bytes copied in 0.5 secs\r\n", "1234 bytes copied"},
		{"license smart register idtoken TOK123", "Registration process is in progress.\r\n", "Registration process is in progress."},
		{"show run | include password 7 0822", "enable password 7 0822455D0A16\r\nusername a password 7 0822455D0A16\r\nhostname FW1\r\n", "hostname FW1"},
	}
	for _, c := range casos {
		r, b := newRec()
		r.Output([]byte("ciscoasa# "))
		r.Input([]byte(c.cmd + "\r"))
		r.Output([]byte(c.cmd + "\r\n" + c.salida + "ciscoasa# "))
		r.Close()
		out := b.String()
		if !strings.Contains(out, c.keep) || strings.Contains(out, "Z <MASKED:secret>\n") {
			t.Errorf("%q:\n%s", c.cmd, out)
		}
		if strings.Contains(out, "Pw1") || strings.Contains(out, "TOK123") || strings.Contains(out, "0822455D") {
			t.Errorf("fuga en %q:\n%s", c.cmd, out)
		}
	}
}

// Integridad: en una sesión mezclada no se pierde ni se duplica ninguna línea de salida ni de «>>>».
func TestIntegridadDeLaSesion(t *testing.T) {
	r, b := newRec()
	const n = 300
	var typed []string
	r.Output([]byte("ciscoasa# "))
	for i := 0; i < n; i++ {
		cmd := fmt.Sprintf("show thing %d", i)
		secret := i%7 == 0
		if secret {
			cmd = fmt.Sprintf("failover key Secret%d", i)
		}
		r.Input([]byte(cmd + "\r"))
		if secret {
			r.Output([]byte(cmd + "\r\n"))
		} else {
			typed = append(typed, cmd)
			r.Output([]byte(cmd + "\r\n"))
		}
		if i%5 == 0 {
			r.Output([]byte(fmt.Sprintf("%%ASA-5-111008: log-%d\r\n", i)))
		}
		for j := 0; j < 3; j++ {
			r.Output([]byte(fmt.Sprintf("out-%d-%d some output text\r\n", i, j)))
		}
		if i == 150 {
			for j := 0; j < 3000; j++ {
				r.Output([]byte(fmt.Sprintf("big-%d %s\r\n", j, strings.Repeat("x", 70))))
			}
		}
		r.Output([]byte("ciscoasa# "))
	}
	r.Close()
	out := b.String()
	for i := 0; i < n; i++ {
		for j := 0; j < 3; j++ {
			if c := strings.Count(out, fmt.Sprintf("Z out-%d-%d some output text\n", i, j)); c != 1 {
				t.Fatalf("out-%d-%d aparece %d veces", i, j, c)
			}
		}
		if i%5 == 0 && strings.Count(out, fmt.Sprintf("log-%d\n", i)) != 1 {
			t.Fatalf("log-%d perdido o duplicado", i)
		}
	}
	for j := 0; j < 3000; j++ {
		if strings.Count(out, fmt.Sprintf("Z big-%d ", j)) != 1 {
			t.Fatalf("big-%d perdido o duplicado", j)
		}
	}
	for _, c := range typed {
		if strings.Count(out, ">>> "+c+"\n") != 1 {
			t.Fatalf("%q perdido o duplicado en >>>", c)
		}
	}
	if got, want := strings.Count(out, ">>> "), n; got != want {
		t.Fatalf("líneas >>>: %d, quería %d", got, want)
	}
	if strings.Contains(out, "Secret") {
		t.Fatalf("fuga de clave:\n%.500s", out)
	}
}

// Rendimiento: unos 5 MB de un show, en trozos de 4 KB, no se vuelven cuadráticos (mejor de dos corridas: la
// máquina puede estar cargada).
func TestRendimientoDeCincoMegas(t *testing.T) {
	if testing.Short() || raceActivo {
		t.Skip("lenta (con -race el detector multiplica el costo de las expresiones regulares)")
	}
	line := strings.Repeat("a", 79) + "\r\n"
	var data []byte
	for len(data) < 5<<20 {
		data = append(data, line...)
	}
	best := time.Hour
	for k := 0; k < 2 && best > 2*time.Second; k++ {
		r, _ := newRec()
		start := time.Now()
		for i := 0; i < len(data); i += 4096 {
			r.Output(data[i:min(i+4096, len(data))])
		}
		r.Close()
		best = min(best, time.Since(start))
	}
	t.Logf("5 MB en %v", best)
	if best > 2*time.Second {
		t.Errorf("tardó %v", best)
	}
}

// Tecleo carácter por carácter: el eco llega partido y se sigue tecleando (aún sin Enter).
func TestEcoPartidoMientrasSeTeclea(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	for _, c := range "key Secret" {
		r.Input([]byte(string(c)))
	}
	r.Output([]byte("key Se"))
	r.Output([]byte("\r\n%ASA-5-111008: uno\r\n"))
	r.Output([]byte("cret\r\n"))
	r.Input([]byte("\r"))
	r.Close()
	if out := b.String(); strings.Contains(out, "Z cret\n") || strings.Contains(out, "Secret") {
		t.Errorf("%s", out)
	}
}

// Pegado con Enter y eco partido por uno y por dos logs; tras completar la línea el eco ya no tapa más.
func TestEcoPartidoDePegadoPorUnoYDosLogs(t *testing.T) {
	for _, logs := range []int{1, 2} {
		r, b := newRec()
		r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
		r.Input([]byte("key Secret\r"))
		r.Output([]byte("key Se"))
		for i := 0; i < logs; i++ {
			r.Output([]byte("\r\n%ASA-5-111008: log\r\n"))
			if i == 0 && logs == 2 {
				r.Output([]byte("cre\r\n")) // trozo intermedio del eco
			}
		}
		r.Output([]byte("t\r\nlinea posterior\r\nciscoasa(config-aaa-server-host)# "))
		r.Close()
		out := b.String()
		if strings.Contains(out, "Z cre\n") || strings.Contains(out, "Z t\n") || strings.Contains(out, "Secret") {
			t.Errorf("logs=%d: fuga:\n%s", logs, out)
		}
		if !strings.Contains(out, "Z linea posterior\n") {
			t.Errorf("logs=%d: tapó de más:\n%s", logs, out)
		}
	}
}
