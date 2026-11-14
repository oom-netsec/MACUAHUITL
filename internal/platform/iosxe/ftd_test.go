package iosxe

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

func ftdReply(ver string) func(string) (string, string) {
	return func(line string) (string, string) {
		switch line {
		case "show version":
			return strings.ReplaceAll(ver, "\n", "\r\n"), ""
		case "show pager":
			return "no pager\r\n", ""
		case "terminal length 0", "terminal width 0":
			return "Command not valid: terminal\r\n", ""
		}
		return "", ""
	}
}

// Fixtures de show version de FTDv, Secure Firewall y 1120, armadas con la forma de la documentación, sin validar en laboratorio.
func TestDetectFTD(t *testing.T) {
	for _, f := range []string{"ftd-ftdv", "ftd-secure-firewall", "ftd-1120"} {
		_, r, w := startFake(t, "> ", "> ", ftdReply(asaVersion(t, dir(f))))
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if p, err := d.Detect(context.Background()); err != nil || p != "ftd" {
			t.Fatalf("%s: Detect = %q, %v", f, p, err)
		}
	}
}

// La salida de FTD puede citar la versión de lina: gana ftd. Y un ASA que menciona FTD en texto libre sigue siendo asa.
func TestDetectFTDAntesQueASA(t *testing.T) {
	both := asaVersion(t, dir("ftd-ftdv")) + "\nCisco Adaptive Security Appliance Software Version 9.18(2)\n"
	_, r, w := startFake(t, "> ", "> ", ftdReply(both))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.Detect(context.Background()); p != "ftd" {
		t.Fatalf("Detect = %q", p)
	}
	asaTxt := asaVersion(t, dir("asa-asav")) + "\nModel : migrated to Cisco Firepower Threat Defense soon\n"
	_, r, w = startFake(t, "asa# ", "asa# ", ftdReply(asaTxt))
	d = New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.Detect(context.Background()); p != "asa" {
		t.Fatalf("Detect = %q", p)
	}
}

// Sin nombre de host y sin enable: Open no manda «enable»; los «terminal …» rechazados no rompen la sesión.
func TestFTDOpenSinEnable(t *testing.T) {
	f, r, w := startFake(t, "Copyright 2004-2023, Cisco\r\n\r\n> ", "> ", ftdReply(""))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.written(), "enable") {
		t.Fatalf("se escribió %q", f.written())
	}
	if d.Hostname() != "" {
		t.Fatalf("Hostname = %q", d.Hostname())
	}
	out, err := d.Run(context.Background(), "show pager", 5*time.Second)
	if err != nil || out.Text != "no pager\n" {
		t.Fatalf("out = %q, %v", out.Text, err)
	}
}

// Primer login: cambio de contraseña obligatorio o EULA. Open aborta sin escribir NADA (ni el secreto ni un Enter).
func TestFTDPrimerLoginNoEscribeNada(t *testing.T) {
	for _, first := range []string{
		"You must change your password\r\nEnter new password: ",
		"You must change your password\r\n(current) UNIX password: ",
		"Enter new password: ",
		"Confirm new password: ",
		"Press <ENTER> to display the EULA: \r\nPlease enter 'YES' or press <ENTER> to AGREE to the EULA: ",
		"Please enter 'YES' or press <ENTER> to AGREE to the EULA: ",
	} {
		f, r, w := startFake(t, first, "> ", ftdReply(""))
		d := New().(*driver)
		err := d.Open(context.Background(), r, w, secret.New([]byte("en")))
		if !errors.Is(err, platform.ErrFirstLogin) {
			t.Fatalf("%q: Open = %v", first, err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := f.written(); got != "" {
			t.Fatalf("%q: se escribió %q", first, got)
		}
	}
}

// Líneas de salida que empiezan con «>» (BGP, tablas) y una «>» suelta a mitad de la salida no cortan el comando:
// solo el «> » final lo cierra, aunque el equipo entregue la salida en pedazos.
func TestFTDPromptNoCortaSalida(t *testing.T) {
	devR, drvW := io.Pipe()
	drvR, devW := io.Pipe()
	t.Cleanup(func() { drvW.Close(); devW.Close() })
	go func() {
		io.WriteString(devW, "> ")
		buf := make([]byte, 256)
		for {
			n, err := devR.Read(buf)
			if err != nil {
				return
			}
			if !strings.Contains(string(buf[:n]), "show bgp") {
				io.WriteString(devW, string(buf[:n])+"\r\n> ")
				continue
			}
			io.WriteString(devW, "show bgp\r\n")
			for _, p := range []string{"   Network          Next Hop\r\n", ">", "  ", "10.0.0.0/8      192.0.2.1\r\n", ">\r\n", "> ", " 172.16.0.0/12  192.0.2.2\r\n"} {
				io.WriteString(devW, p)
				time.Sleep(30 * time.Millisecond)
			}
			io.WriteString(devW, "fin\r\n> ")
		}
	}()
	d := New().(*driver)
	if err := d.Open(context.Background(), drvR, drvW, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show bgp", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := "   Network          Next Hop\n>  10.0.0.0/8      192.0.2.1\n>\n>  172.16.0.0/12  192.0.2.2\nfin\n"
	if out.Text != want {
		t.Fatalf("texto %q", out.Text)
	}
}
