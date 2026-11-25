package terminal

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func audRec() (*Recorder, *bytes.Buffer) {
	var b bytes.Buffer
	return NewRecorder(&b, func() time.Time { return time.Unix(0, 0).UTC() }), &b
}

// B: prompts de secreto reales que secretPrompt no reconoce (más de 30 caracteres o «:» en medio).
func TestSecretoAuditoriaPrompts(t *testing.T) {
	for _, p := range []string{
		"Enter passphrase for key '/home/operador/.ssh/id_ed25519': ",
		"Password for 'https://operador@git.example.com': ",
		"Enter password for sa@db-prod-01.example.internal.corp: ",
		"operador@jump01.dc1.example.internal.corp's password: ",
		"[sudo] password for operador: ",
		"Enter passphrase for /home/operador/.ssh/id_ed25519_produccion: ",
	} {
		r, b := audRec()
		r.Output([]byte("\r\njump01> "))
		r.Input([]byte("ssh core1\r"))
		r.Output([]byte("ssh core1\r\n" + p))
		r.Input([]byte("Fr4seSecreta9\r"))
		r.Output([]byte("\r\ncore1#"))
		r.Close()
		if strings.Contains(b.String(), "Fr4seSecreta9") {
			t.Errorf("FUGA con el prompt %q:\n%s", p, b.String())
		}
	}
}

// C: login automático de Telnet: la contraseña no pasa por Input; si el equipo la devuelve (eco), se graba.
func TestSecretoAuditoriaTelnetEco(t *testing.T) {
	r, b := audRec()
	r.Output([]byte("\r\nUser Access Verification\r\n\r\nUsername: "))
	r.Output([]byte("admin\r\nPassword: ")) // eco del usuario que mandó el núcleo
	r.SecretSent()                          // el login automático avisa antes de mandar la contraseña
	r.Output([]byte("Cl4veBoveda7\r\n"))    // el equipo devuelve la contraseña que mandó el núcleo
	r.Output([]byte("SW1>"))
	r.Close()
	t.Logf("\n%s", b.String())
	if strings.Contains(b.String(), "Cl4veBoveda7") {
		t.Errorf("FUGA: la contraseña de la bóveda quedó en la grabación")
	}
}

// D: un prompt de secreto con eco (diálogo setup de IOS): lo tecleado se oculta, pero el eco del equipo se graba.
func TestSecretoAuditoriaPromptConEco(t *testing.T) {
	for _, p := range []string{"  Enter enable secret: ", "  Enter enable password: ", "  Enter virtual terminal password: ", "    Community string [public]: "} {
		r, b := audRec()
		r.Output([]byte("\r\n" + p))
		for _, c := range "Cl4veSetup77" {
			r.Input([]byte(string(c)))
			r.Output([]byte(string(c))) // IOS devuelve cada tecla en el diálogo setup
		}
		r.Input([]byte("\r"))
		r.Output([]byte("\r\n  Next: "))
		r.Close()
		if strings.Contains(b.String(), "Cl4veSetup77") {
			t.Errorf("FUGA con %q:\n%s", p, b.String())
		}
	}
}

// Sin tapar de más: un comando normal y su salida siguen igual, y una línea «Key: valor» que no responde a nada
// tecleado no se toca.
func TestSecretoAuditoriaSinTaparDeMas(t *testing.T) {
	r, b := audRec()
	r.Output([]byte("\r\nSW1#"))
	r.Input([]byte("show version\r"))
	r.Output([]byte("show version\r\nCisco IOS Software, Version 15.2\r\nConfiguration register is 0xF\r\nSW1#"))
	r.Close()
	for _, want := range []string{">>> show version", "Cisco IOS Software, Version 15.2", "register is 0xF"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("falta %q:\n%s", want, b.String())
		}
	}
}

// Una salida que llega byte a byte (consola serie) y pasa por un «:» tras key/password no se tapa: nadie contestó un prompt.
func TestSecretoAuditoriaSinTaparPorDosPuntos(t *testing.T) {
	r, b := audRec()
	r.Output([]byte("\r\nSW1#"))
	r.Input([]byte("show ip ssh\r"))
	for _, c := range []byte("show ip ssh\r\nMinimum expected Diffie Hellman key size : 2048 bits\r\nKey name: SW1.lab\r\n% Key pair was generated at: 10:00:00 UTC Nov 25 2026\r\nSW1#") {
		r.Output([]byte{c})
	}
	r.Close()
	for _, want := range []string{"key size : 2048 bits", "Key name: SW1.lab", "generated at: 10:00:00 UTC"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("tapó de más, falta %q:\n%s", want, b.String())
		}
	}
}

// SkipTyped (consola): lo tecleado no se graba, ni la contraseña adelantada ni los comandos; el eco sí, tapado.
func TestSecretoAuditoriaSkipTyped(t *testing.T) {
	r, b := audRec()
	r.SkipTyped()
	r.Output([]byte("\r\nUsername: "))
	r.Input([]byte("\radmin\rS3cretLog9\r"))
	r.Output([]byte("\r\nUsername: admin\r\nPassword: "))
	r.Output([]byte("\r\nSW1>"))
	r.Input([]byte("enable\r"))
	r.Output([]byte("enable\r\nPassword: \r\nSW1#"))
	r.Input([]byte("username ops secret 0 Tecl3ado\r"))
	r.Output([]byte("username ops secret 0 Tecl3ado\r\nSW1#"))
	r.Close()
	if s := b.String(); strings.Contains(s, ">>>") || strings.Contains(s, "S3cretLog9") || strings.Contains(s, "Tecl3ado") || !strings.Contains(s, "Username: admin") {
		t.Errorf("SkipTyped:\n%s", s)
	}
}

// Eco rezagado del primer comando entre dos Enter: «enable» no se toma por la contraseña (regresión vista en revisión).
func TestSecretoAuditoriaEcoRezagadoNoConfunde(t *testing.T) {
	r, b := audRec()
	r.Output([]byte("\r\nR1>"))
	r.Input([]byte("show clock\r"))
	r.Output([]byte("k"))
	r.Input([]byte("enable\r"))
	r.Output([]byte("\r\n*10:00:00 UTC\r\nR1>en"))
	r.Output([]byte("able\r\nPassword: "))
	r.Input([]byte("S3cretRz9\r"))
	r.Output([]byte("\r\nR1#"))
	r.Close()
	if s := b.String(); strings.Contains(s, "S3cretRz9") || !strings.Contains(s, ">>> enable") {
		t.Errorf("FUGA o falta enable:\n%s", s)
	}
}

// Un comando que termina en «…key…:» con el eco partido por un syslog (consola sin logging synchronous): el resto del
// eco sigue tapado como en main (revisión: ocultar la línea al Enter cortaba el seguimiento del eco).
func TestSecretoAuditoriaEcoPartidoConDosPuntos(t *testing.T) {
	r, b := audRec()
	r.Output([]byte("\r\nSW1#"))
	for _, c := range "copy scp://admin" {
		r.Input([]byte(string(c)))
		r.Output([]byte(string(c)))
	}
	r.Output([]byte("\r\n*Mar  1 00:00:01: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\r\n"))
	for _, c := range ":Adm1nPw@10.0.0.5/certs/router-key.pem bootflash:" {
		r.Input([]byte(string(c)))
		r.Output([]byte(string(c)))
	}
	r.Input([]byte("\r"))
	r.Output([]byte("\r\nDestination filename [router-key.pem]? "))
	r.Close()
	if strings.Contains(b.String(), "Adm1nPw") {
		t.Errorf("FUGA:\n%s", b.String())
	}
}
