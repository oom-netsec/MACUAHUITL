package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp/snmptest"
)

func TestVisibilityCommands(t *testing.T) {
	startCore(t)
	dir, _ := filepath.Abs("../../internal/topo/testdata/trabajo_20261104-100000")
	svg := filepath.Join(t.TempDir(), "topo.svg")
	if out, err := mctl(t, "", "topo", "build", dir, "--svg", svg); err != nil || !strings.Contains(out, "VLAN nativa distinta") {
		t.Fatalf("topo: %q %v", out, err)
	}
	if b, err := os.ReadFile(svg); err != nil || !strings.HasPrefix(string(b), "<svg") {
		t.Fatalf("svg: %v", err)
	}
	if out, err := mctl(t, "", "topo", "build", dir, "--json"); err != nil || !strings.HasPrefix(out, `{"nodes"`) {
		t.Fatalf("topo json: %q %v", out, err)
	}
	if _, err := mctl(t, "", "topo", "build"); err == nil {
		t.Fatal("topo sin argumentos")
	}

	a := snmptest.New(t, "lab-ro", nil)
	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "lab-ro\n\n", "cred", "add", "--label", "snmp", "--user", "snmp"))
	port := fmt.Sprint(a.Port())
	if out := must(t, "", "snmp", "get", "127.0.0.1", "1.3.6.1.2.1.1.5.0", "--cred", cred, "--port", port); !strings.Contains(out, "SW1") {
		t.Fatalf("snmp get = %q", out)
	}
	if out := must(t, "", "snmp", "walk", "127.0.0.1", "1.3.6.1.2.1.31.1.1.1.1", "--bulk", "--cred", cred, "--port", port); !strings.Contains(out, "Gi1/0/2") {
		t.Fatalf("snmp walk = %q", out)
	}
	if out := must(t, "", "snmp", "poll", "127.0.0.1", "--cred", cred, "--port", port, "--profile", "cpu", "--count", "1", "--json"); !strings.Contains(out, `"FiveSec":7`) {
		t.Fatalf("snmp poll = %q", out)
	}
	if out := must(t, "", "snmp", "traps", "listen", "--addr", "127.0.0.1:0", "--for", "1"); !strings.Contains(out, "escuchando traps en 127.0.0.1:") {
		t.Fatalf("traps = %q", out)
	}
	if _, err := mctl(t, "", "snmp", "traps", "listen", "--addr", "127.0.0.1:162"); err == nil || !strings.Contains(err.Error(), "privilegiado") {
		t.Fatalf("traps 162: %v", err)
	}
	if out := must(t, "", "flows", "listen", "--addr", "127.0.0.1:0", "--for", "1"); !strings.Contains(out, "escuchando flujos en 127.0.0.1:") || !strings.Contains(out, "0 flujos") {
		t.Fatalf("flows = %q", out)
	}
	opts := []string{"--for", "1", "--save", "--rate", "50", "--burst", "60", "--rate-global", "500", "--burst-global", "600", "--queue", "128",
		"--rotate-mb", "5", "--rotate-min", "10", "--name", "x_{fecha}", "--max-files", "3", "--format", "crudo"}
	for _, cmd := range [][]string{{"snmp", "traps", "listen"}, {"flows", "listen"}} {
		base := append(cmd, "--addr", "127.0.0.1:0")
		if out, err := mctl(t, "", append(append([]string{}, base...), opts...)...); err != nil || !strings.Contains(out, "escuchando") || !strings.Contains(out, "guardando en") {
			t.Fatalf("%v con opciones: %q %v", cmd, out, err)
		}
		for _, bad := range [][]string{{"--rate", "20000"}, {"--queue", "5"}, {"--rotate-mb", "2000"}, {"--name", "../x"}, {"--format", "xml"}, {"--max-files", "5000"},
			{"--rate", "4294967396"}, {"--for", "4294967297"}, {"--rotate-mb", "-4294967295"}} {
			if _, err := mctl(t, "", append(append(append([]string{}, base...), "--for", "1"), bad...)...); err == nil {
				t.Errorf("%v %v debía rechazarse", cmd, bad)
			}
		}
	}
	for _, bad := range [][]string{{"--top", "4294967306"}, {"--every", "4294967297"}} { // no se truncan a int32
		if _, err := mctl(t, "", append([]string{"flows", "listen", "--addr", "127.0.0.1:0", "--for", "1"}, bad...)...); err == nil || !strings.Contains(err.Error(), "fuera de rango") {
			t.Errorf("%v: err = %v", bad, err)
		}
	}
	if _, err := mctl(t, "", "gnmi", "get", "127.0.0.1", "/system", "--port", "1", "--timeout", "300"); err == nil {
		t.Fatal("gnmi a puerto cerrado")
	}
}
