package terminal

import (
	"bytes"
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
