package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

func TestRunAdhoc(t *testing.T) {
	e := startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "pw-lab\nen-lab\n", "cred", "add", "--label", "lab", "--user", "admin"))
	ap := netip.MustParseAddrPort(e.target)
	dev := fmt.Sprintf("%s:%d", ap.Addr(), ap.Port())
	if _, err := mctl(t, "", "run", "-d", dev, "-c", "configure terminal", "--cred", cred); err == nil || !strings.Contains(err.Error(), "solo lectura") {
		t.Fatalf("comando de escritura aceptado: %v", err)
	}
	if _, err := mctl(t, "", "run", "-c", "show clock"); err == nil || !strings.Contains(err.Error(), "uso: mctl run") {
		t.Fatalf("sin equipos ni credencial: %v", err)
	}
	out, err := mctl(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred)
	if err == nil || !strings.Contains(out, "mctl job logintest") {
		t.Fatalf("sin huella = %q %v", out, err)
	}
	job := regexp.MustCompile(`trabajo ([0-9a-f]+)`).FindStringSubmatch(out)[1]
	lt, _ := mctl(t, "", "job", "logintest", job)
	fp := regexp.MustCompile(`SHA256:\S+`).FindString(lt)
	out = must(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred, "--accept", fp)
	if !strings.Contains(out, "== SW-LAB-01") || !strings.Contains(out, "-- show version") {
		t.Fatalf("texto = %q", out)
	}
	if out = must(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred, "--csv"); !strings.HasPrefix(out, "equipo,direccion,comando,estado,salida\n") {
		t.Fatalf("csv = %q", out)
	}
}
