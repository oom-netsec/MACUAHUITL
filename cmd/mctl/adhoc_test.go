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

// --accept EQUIPO=HUELLA ata la huella al equipo; una huella sola con varios destinos es error de uso.
func TestRunAdhocAcceptPorEquipo(t *testing.T) {
	e := startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "pw-lab\nen-lab\n", "cred", "add", "--label", "lab", "--user", "admin"))
	ap := netip.MustParseAddrPort(e.target)
	dev := fmt.Sprintf("%s:%d", ap.Addr(), ap.Port())
	out, _ := mctl(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred)
	job := regexp.MustCompile(`trabajo ([0-9a-f]+)`).FindStringSubmatch(out)[1]
	lt, _ := mctl(t, "", "job", "logintest", job)
	fp := regexp.MustCompile(`SHA256:\S+`).FindString(lt)
	if !strings.Contains(lt, "--accept "+dev+"="+fp) {
		t.Fatalf("la sugerencia debe llevar el equipo: %q", lt)
	}
	if _, err := mctl(t, "", "run", "-d", dev, "-d", "10.9.9.9", "-c", "show version", "--cred", cred, "--accept", fp); err == nil || !strings.Contains(err.Error(), "--accept EQUIPO="+fp) {
		t.Fatalf("huella sola con dos destinos: %v", err)
	}
	if _, err := mctl(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred, "--accept", "="+fp); err == nil || !strings.Contains(err.Error(), "EQUIPO=HUELLA") {
		t.Fatalf("forma inválida: %v", err)
	}
	if _, err := mctl(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred, "--accept", "10.9.9.9="+fp); err == nil {
		t.Fatal("la huella de otro equipo no debe valer")
	}
	if out = must(t, "", "run", "-d", dev, "-c", "show version", "--cred", cred, "--accept", dev+"="+fp); !strings.Contains(out, "== SW-LAB-01") {
		t.Fatalf("texto = %q", out)
	}
}
