package iosxe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

const iseP = "ise/admin# "

// ISE (ADE-OS, CLI Reference 3.1-3.4, sin validar en laboratorio): sin enable; terminal length 0 sí, terminal width no.
func iseReply(ver string) func(string) (string, string) {
	return func(line string) (string, string) {
		switch line {
		case "show version":
			return strings.ReplaceAll(ver, "\n", "\r\n"), ""
		case "terminal width 0", "terminal width 511":
			return "% Invalid input detected at '^' marker.\r\n", ""
		}
		return "", ""
	}
}

func TestDetectISE(t *testing.T) {
	for _, f := range []string{"ise-3.1", "ise-3.4"} {
		_, r, w := startFake(t, iseP, iseP, iseReply(asaVersion(t, dir(f))))
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if p, err := d.Detect(context.Background()); err != nil || p != "ise" {
			t.Fatalf("%s: Detect = %q, %v", f, p, err)
		}
	}
}

// Ni ADE-OS sin ISE (otro producto) ni un IOS que cite el texto en medio de una línea son ISE.
func TestDetectISEExigeLasDosCabeceras(t *testing.T) {
	ade := "Cisco Application Deployment Engine OS Release: 3.1\nADE-OS Build Version: 3.1.0.1\n\nCisco Prime Infrastructure\nVersion : 3.10\n"
	ios := "Cisco IOS Software, C3750 Software, Version 15.0\nnota: Cisco Application Deployment Engine OS Release y Cisco Identity Services Engine\n"
	for name, ver := range map[string]string{"ade-sin-ise": ade, "ios-cita": ios} {
		_, r, w := startFake(t, iseP, iseP, iseReply(ver))
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		p, err := d.Detect(context.Background())
		if p == "ise" || name == "ade-sin-ise" && !errors.Is(err, platform.ErrUnknownPlatform) {
			t.Fatalf("%s: Detect = %q, %v", name, p, err)
		}
	}
}

// Open con prompt host/admin#: sin enable, solo «terminal length 0» (si lo acepta no se manda terminal width).
func TestISEOpenEscribeSoloTerminalLength(t *testing.T) {
	f, r, w := startFake(t, iseP, iseP, iseReply(""))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); err != nil {
		t.Fatal(err)
	}
	if got := f.written(); got != "terminal length 0\n" {
		t.Fatalf("se escribió %q", got)
	}
	if d.Hostname() != "ise/admin" {
		t.Fatalf("hostname %q", d.Hostname())
	}
	out, err := d.Run(context.Background(), "show version", 5*time.Second)
	if err != nil || !strings.HasSuffix(f.written(), "show version\n") || strings.Contains(out.Text, "admin#") {
		t.Fatalf("%+v, %v", out, err)
	}
}

// Si ISE rechazara «terminal length 0» el --More-- se contesta con espacio como en IOS.
func TestISEMoreSeContestaConEspacio(t *testing.T) {
	f, r, w := startFake(t, iseP, iseP, func(line string) (string, string) {
		if line == "show logging system" {
			return "uno\r\n --More-- ", "-"
		}
		return "", ""
	})
	f.onSpace = "\r\n        \r\ndos\r\n"
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show logging system", 5*time.Second)
	if err != nil || !strings.Contains(out.Text, "uno") || !strings.Contains(out.Text, "dos") || strings.Contains(out.Text, "More") {
		t.Fatalf("%q, %v", out.Text, err)
	}
}

// Primer inicio de sesión con cambio de contraseña o una pregunta (y/n): el driver aborta sin escribir nada.
func TestISEPrimerLoginNoEscribeNada(t *testing.T) {
	for _, first := range []string{
		"Password expired. You must change your password now.\r\nEnter new password: ",
		"Your password has expired.\r\nChanging password for admin.\r\nNew password: ",
		"Retype new password: ",
		"(current) password: ",
		"Confirm new password: ",
		"The node is not registered yet. Do you want to continue? (y/n): ",
		"Accept the license agreement? [yes/no] ",
	} {
		f, r, w := startFake(t, first, iseP, iseReply(""))
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

// ISE no cambia a ASA multicontexto: su prompt host/ctx# con length rechazado sigue mandando pager y width.
func TestISENoCambiaASAMulticontexto(t *testing.T) {
	f, r, w := startFake(t, "asa/ctx1# ", "asa/ctx1# ", asaReply(true))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	want := "terminal length 0|terminal pager 0|terminal width 0|terminal width 511"
	if got := strings.Join(lines(f.written()), "|"); got != want {
		t.Fatalf("enviado %q", got)
	}
}

// Un prompt sin «/» (IOS) sigue recibiendo terminal width 0 aunque acepte length 0.
func TestISENoCambiaIOSTerminalWidth(t *testing.T) {
	f, r, w := startFake(t, "SW1# ", "SW1# ", func(string) (string, string) { return "", "" })
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if got := f.written(); got != "terminal length 0\nterminal width 0\n" {
		t.Fatalf("se escribió %q", got)
	}
}
