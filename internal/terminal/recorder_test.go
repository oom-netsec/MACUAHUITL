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
		if !strings.Contains(out, ">>> [hidden]") || !strings.Contains(out, ">>> show clock") {
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
		if strings.Contains(out, "EnSecret9") || !strings.Contains(out, ">>> [hidden]") || !strings.Contains(out, ">>> enable") || !strings.Contains(out, ">>> show clock") {
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
	// Sin prompt que confirme el bloque (cierre), tapar de más «key Foo2» es aceptable; lo que no puede pasar es la fuga de K1.
	if strings.Contains(out, "K1") {
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

// Rendimiento: un show de 1 MB y otro de 5 MB, en trozos de 4 KB, no se vuelven cuadráticos. Lo que se vigila es la
// forma (un costo cuadrático tardaría decenas de segundos), no los milisegundos: topes amplios por si la máquina está cargada.
func TestRendimientoDeCincoMegas(t *testing.T) {
	if testing.Short() || raceActivo {
		t.Skip("lenta (con -race el detector multiplica el costo de las expresiones regulares)")
	}
	line := strings.Repeat("a", 79) + "\r\n"
	run := func(size int) time.Duration {
		var data []byte
		for len(data) < size {
			data = append(data, line...)
		}
		best := time.Hour
		for k := 0; k < 2 && best > 6*time.Second; k++ {
			r, _ := newRec()
			start := time.Now()
			for i := 0; i < len(data); i += 4096 {
				r.Output(data[i:min(i+4096, len(data))])
			}
			r.Close()
			best = min(best, time.Since(start))
		}
		return best
	}
	t1, t5 := run(1<<20), run(5<<20)
	t.Logf("1 MB en %v, 5 MB en %v", t1, t5)
	if t5 > 6*time.Second {
		t.Errorf("5 MB tardó %v", t5)
	}
	if t5 > 12*t1+500*time.Millisecond { // lineal ≈ 5×; cuadrático ≈ 25×
		t.Errorf("el tiempo no crece en forma lineal: 1 MB %v, 5 MB %v", t1, t5)
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

// Pegado de varias líneas: el eco partido de la primera se tapa aunque la última enviada sea otra.
func TestEcoPartidoDeLaPrimeraDeVariasLineasPegadas(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("key Secret\rtimeout 5\r"))
	r.Output([]byte("key Se"))
	r.Output([]byte("\r\n%ASA-5-111008: log\r\n"))
	r.Output([]byte("cret\r\nciscoasa(config-aaa-server-host)# timeout 5\r\nciscoasa(config-aaa-server-host)# "))
	r.Close()
	out := b.String()
	if strings.Contains(out, "Z cret\n") || !strings.Contains(out, "# timeout 5\n") {
		t.Errorf("%s", out)
	}
}

// Retroceso en el eco: «SecX» + «\b \b» + «ret» es «Secret»; se aplica antes de enmascarar, con y sin log en medio.
func TestEcoConRetrocesoSeEnmascaraCompleto(t *testing.T) {
	for _, conLog := range []bool{false, true} {
		for _, bs := range []string{"\b \b", "\x7f", "\b"} {
			r, b := newRec()
			r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
			r.Input([]byte("key Secret\r"))
			if conLog {
				r.Output([]byte("key SecX" + bs))
				r.Output([]byte("\r\n%ASA-5-111008: log\r\n"))
				r.Output([]byte("ret\r\n"))
			} else {
				r.Output([]byte("key SecX" + bs + "ret\r\n"))
			}
			r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
			r.Close()
			out := b.String()
			if strings.Contains(out, "Z ret\n") || strings.Contains(out, "\b") || strings.Contains(out, "\x7f") || !strings.Contains(out, "# key <MASKED:aaa-key>\n") {
				t.Errorf("log=%v bs=%q:\n%s", conLog, bs, out)
			}
		}
	}
}

// La cola de enviadas no se vacía por un Enter vacío ni por un eco que no cuadra (tabulador completado).
func TestColaDeEnviadasSobreviveAEnterVacioYTabulador(t *testing.T) {
	casos := map[string]string{
		"enter vacío": "\rkey Secret\r",
		"tabulador":   "timeout\t5\rkey Secret\r",
		"vacío y tab": "\rtimeout\t5\r\rkey Secret\r",
	}
	for nombre, typed := range casos {
		r, b := newRec()
		r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
		r.Input([]byte(typed))
		if strings.Contains(typed, "timeout") {
			r.Output([]byte("timeout 5\r\nciscoasa(config-aaa-server-host)# "))
		}
		r.Output([]byte("key Se"))
		r.Output([]byte("\r\n%ASA-5-111008: log\r\n"))
		r.Output([]byte("cret\r\nciscoasa(config-aaa-server-host)# "))
		r.Close()
		if out := b.String(); strings.Contains(out, "Z cret\n") {
			t.Errorf("%s:\n%s", nombre, out)
		}
	}
}

// Red por contenido: un valor tapado en lo tecleado se tapa donde aparezca en la salida de la ventana.
func TestRedPorContenidoTapaElValorEnLaSalida(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("key SecretValue1\rshow run\r"))
	r.Output([]byte("key <eco perdido>\r\n"))
	r.Output([]byte("ValueX SecretValue1 y mas\r\n"))  // valor completo
	r.Output([]byte("retValue1 sufijo al inicio\r\n")) // sufijo del valor al inicio (≥2)
	r.Output([]byte("prefijo al final SecretV\r\n"))   // prefijo del valor al final (≥2)
	r.Output([]byte("linea sin relacion\r\n"))
	r.Close()
	out := b.String()
	for _, leak := range []string{"SecretValue1", "retValue1", "SecretV\n"} {
		if strings.Contains(out, leak) {
			t.Errorf("fuga %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "linea sin relacion") {
		t.Errorf("tapó de más:\n%s", out)
	}
}

// La ventana vence con un prompt sin pendientes: después el valor ya no se persigue.
func TestRedPorContenidoVenceConUnPrompt(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config-aaa-server-host)# "))
	r.Input([]byte("key SecretValue1\r"))
	r.Output([]byte("key SecretValue1\r\nciscoasa(config-aaa-server-host)# \r\n"))
	r.Output([]byte("texto SecretValue1 posterior\r\n"))
	r.Close()
	if out := b.String(); !strings.Contains(out, "texto SecretValue1 posterior") {
		t.Errorf("la ventana no venció:\n%s", out)
	}
}

// El borrado de --More-- de IOS no deja sangría falsa que impida abrir el bloque.
func TestBorradoDeMoreNoImpideElBloque(t *testing.T) {
	for _, n := range []int{8, 9, 20} {
		for _, more := range []string{" --More-- ", " --More--", "--More--", "--More-- "} {
			for _, kind := range []string{"cr", "bs"} {
				borrado := "\r" + strings.Repeat(" ", n) + "\r"
				if kind == "bs" {
					borrado = strings.Repeat("\b", n) + strings.Repeat(" ", n) + strings.Repeat("\b", n)
				}
				r, b := newRec()
				r.Output([]byte("SW1#show running-config\r\nhostname SW1\r\n" + more + borrado + "line con 0\r\n password Plain2\r\n"))
				r.Close()
				if out := b.String(); strings.Contains(out, "Plain2") {
					t.Errorf("n=%d %q %s:\n%s", n, more, kind, out)
				}
			}
		}
	}
}

// La red por contenido no tapa palabras que solo contienen el valor o fragmentos suyos.
func TestRedPorContenidoNoTapaDeMas(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("SW1(config)# "))
	r.Input([]byte("enable password Secret\renable password admin\renable password 12\rdo show interfaces\r"))
	r.Output([]byte("enable password Secret\r\nSW1(config)#enable password admin\r\nSW1(config)#enable password 12\r\nSW1(config)#do show interfaces\r\n"))
	for _, l := range []string{
		"GigabitEthernet0/1 is administratively down, line protocol is down",
		"  Hardware is ethernet, address is 0012.3456.789a",
		"     12345 packets input, 12 bytes",
		"interface Vlan12",
		"  Version 12.4",
		"ethernet cret",
		"Secret aparece aqui",
	} {
		r.Output([]byte(l + "\r\n"))
	}
	r.Close()
	out := b.String()
	for _, keep := range []string{"administratively down", "Hardware is ethernet, address is 0012.3456.789a", "12345 packets input, 12 bytes", "interface Vlan12", "Version 12.4", "Z ethernet cret\n"} {
		if !strings.Contains(out, keep) {
			t.Errorf("tapó de más, falta %q:\n%s", keep, out)
		}
	}
	if strings.Contains(out, "Z Secret aparece aqui") {
		t.Errorf("el valor entero no se tapó:\n%s", out)
	}
}

// Lo pegado tras una línea que abre el bloque abreviada se enmascara con el bloque que da el prompt al grabar.
func TestPegadoTrasBloqueAbreviado(t *testing.T) {
	casos := []struct{ prompt, in, echo, leak string }{
		{"SW1(config)# ", "lin vty 0 4\rpassword K4x\r", "lin vty 0 4\r\nSW1(config-line)#password K4x\r\nSW1(config-line)# ", "K4x"},
		{"ciscoasa(config)# ", "aaa-s RAD (inside) host 10.1.1.5\rkey K5x\r", "aaa-s RAD (inside) host 10.1.1.5\r\nciscoasa(config-aaa-server-host)#key K5x\r\nciscoasa(config-aaa-server-host)# ", "K5x"},
	}
	for _, c := range casos {
		r, b := newRec()
		r.Output([]byte(c.prompt))
		r.Input([]byte(c.in))
		r.Output([]byte(c.echo))
		r.Close()
		if out := b.String(); strings.Contains(out, c.leak) {
			t.Errorf("%q:\n%s", c.in, out)
		}
	}
}

// Sin bloque confirmado por un prompt (desbordamiento de lo retenido o cierre), se enmascara con cada bloque.
func TestRetenidoSinBloqueSeEnmascaraConservador(t *testing.T) {
	var many strings.Builder
	many.WriteString("lin vty 0 4\r")
	for i := 0; i < 40; i++ {
		many.WriteString("password K9x\r")
	}
	casos := map[string]string{
		"desborda": many.String(),
		"cierre":   "lin vty 0 4\rpassword K7x\r",
	}
	for nombre, in := range casos {
		r, b := newRec()
		r.Output([]byte("SW1(config)# "))
		r.Input([]byte(in))
		r.Close() // sin que llegue el prompt del bloque
		if out := b.String(); strings.Contains(out, "K9x") || strings.Contains(out, "K7x") {
			t.Errorf("%s:\n%.600s", nombre, out)
		}
	}
}

// AireOS: el login dentro del shell («User:» y «Password:», sin hostname) no graba la clave.
func TestAireOSLoginNoGrabaLaClave(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("\r\n(Cisco Controller)\r\n\r\nUser: "))
	r.Input([]byte("admin\r"))
	r.Output([]byte("admin\r\nPassword:"))
	r.Input([]byte("Secreta1\r"))
	r.Output([]byte("\r\n\r\n(Cisco Controller) >"))
	r.Input([]byte("show sysinfo\r"))
	r.Output([]byte("show sysinfo\r\nProduct Name.... Cisco Controller\r\n\r\n(Cisco Controller) >"))
	r.Close()
	out := b.String()
	if strings.Contains(out, "Secreta1") || !strings.Contains(out, ">>> [hidden]") || !strings.Contains(out, ">>> show sysinfo") {
		t.Errorf("login AireOS mal grabado:\n%s", out)
	}
}

// AireOS: el prompt «(Cisco Controller) >» abre bloque normal y los secretos tecleados o repetidos en el eco salen tapados.
func TestAireOSPromptYRedPorContenido(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("(Cisco Controller) >"))
	r.Input([]byte("config mgmtuser add op1 Secreta1 read-only\r"))
	r.Output([]byte("config mgmtuser add op1 Secreta1 read-only\r\n\r\n(Cisco Controller) >"))
	r.Input([]byte("config radius auth add 1 10.1.1.5 1812 ascii Rad1usK3y\r"))
	r.Output([]byte("config radius auth add 1 10.1.1.5 1812 ascii Rad1usK3y\r\nRad1usK3y\r\n(Cisco Controller) >"))
	// Varias líneas pegadas sin salida entre ellas: se retienen y se graban al llegar el prompt.
	r.Input([]byte("config snmp community create Comun1dad\r"))
	r.Input([]byte("show ap summary\r"))
	r.Output([]byte("(Cisco Controller) >"))
	r.Close()
	out := b.String()
	for _, s := range []string{"Secreta1", "Rad1usK3y", "Comun1dad"} {
		if strings.Contains(out, s) {
			t.Errorf("%q en la grabación:\n%s", s, out)
		}
	}
	for _, s := range []string{"config mgmtuser add op1 <MASKED:user-secret> read-only", "config radius auth add 1 10.1.1.5 1812 ascii <MASKED:radius-key>", "config snmp community create <MASKED:snmp-community>", ">>> show ap summary"} {
		if !strings.Contains(out, s) {
			t.Errorf("falta %q:\n%s", s, out)
		}
	}
}

// Falsos positivos de AireOS: nombres de WLAN y de AP, listados y una descripción con «password» no se tocan.
func TestAireOSFalsosPositivos(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("(Cisco Controller) >"))
	for _, c := range []string{"config wlan ssid 3 Corp-WiFi", "config ap name AP-Sala1 AP-Sala-2", "show ap summary", "show client summary", "config wlan description 3 password de invitados"} {
		r.Input([]byte(c + "\r"))
		r.Output([]byte(c + "\r\n\r\n(Cisco Controller) >"))
	}
	r.Close()
	out := b.String()
	for _, c := range []string{"config wlan ssid 3 Corp-WiFi", "config ap name AP-Sala1 AP-Sala-2", "show ap summary", "show client summary", "config wlan description 3 password de invitados"} {
		if strings.Count(out, c) != 2 {
			t.Errorf("%q debía salir dos veces (tecla y eco):\n%s", c, out)
		}
	}
}

// AireOS: el eco con prompt «(Cisco Controller) >» pasa por las reglas aunque el valor sea corto, y las líneas
// pegadas se graban al volver el prompt (no se quedan retenidas hasta el cierre).
func TestAireOSEcoCortoYPegado(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("(Cisco Controller) >"))
	r.Input([]byte("config mgmtuser add op1 Ab1 read-only\r"))
	r.Output([]byte("config mgmtuser add op1 Ab1 read-only\r\n\r\n(Cisco Controller) >"))
	r.Input([]byte("config snmp community create Cx9\r"))
	r.Input([]byte("show ap summary\r"))
	r.Output([]byte("config snmp community create Cx9\r\nshow ap summary\r\n\r\n(Cisco Controller) >"))
	if !strings.Contains(b.String(), ">>> show ap summary") {
		t.Errorf("las líneas pegadas siguen retenidas al volver el prompt:\n%s", b.String())
	}
	r.Close()
	out := b.String()
	if strings.Contains(out, "Ab1") || strings.Contains(out, "Cx9") {
		t.Errorf("valor corto en la grabación:\n%s", out)
	}
}

// AireOS: dentro de «(Cisco Controller) config>» se teclea sin el prefijo «config»; lo tecleado y el eco salen tapados.
// Al volver a «(Cisco Controller) >» el bloque se cierra.
func TestAireOSConfigSinPrefijoTapaTeclasYEco(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("(Cisco Controller) >"))
	r.Input([]byte("config\r"))
	r.Output([]byte("config\r\n\r\n(Cisco Controller) config>"))
	cmds := []string{"radius auth add 1 10.1.1.5 1812 ascii Rad1usK3y", "mgmtuser add op1 Secreta1 read-only", "snmp community create Comun1dad"}
	for _, c := range cmds {
		r.Input([]byte(c + "\r"))
		r.Output([]byte(c + "\r\n\r\n(Cisco Controller) config>"))
	}
	r.Close()
	out := b.String()
	for _, s := range []string{"Rad1usK3y", "Secreta1", "Comun1dad"} {
		if strings.Contains(out, s) {
			t.Errorf("%q en la grabación:\n%s", s, out)
		}
	}
	if strings.Count(out, "<MASKED:") != 6 {
		t.Errorf("se esperaban 6 tapados (tecla y eco):\n%s", out)
	}
}

// Fuera de config> de AireOS el «radius …» suelto no se toca (IOS-XE).
func TestRadiusSueltoDeOtrasPlataformasNoCambia(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("SW1(config)#"))
	r.Input([]byte("radius auth add 1 10.1.1.5 1812 ascii Visible\r"))
	r.Output([]byte("radius auth add 1 10.1.1.5 1812 ascii Visible\r\nSW1(config)#"))
	r.Close()
	if strings.Count(b.String(), "ascii Visible") != 2 {
		t.Errorf("cambió:\n%s", b.String())
	}
}
