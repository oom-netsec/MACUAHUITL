package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/radiustest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tacacstest"
	"github.com/oom-netsec/MACUAHUITL/internal/ikedec"
)

func TestSecurityCommands(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	here := filepath.Dir(f)
	startCore(t)
	rf, err := radiustest.StartFake(radiustest.FakeConfig{Secret: "sec", Users: map[string]string{"alice": "pw"}, Reply: radiustest.AuthzReply()})
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	// Secretos por stdin (sin eco en una terminal): primero el secreto compartido, luego la contraseña.
	out := must(t, "sec\npw\n", "radius", "test", rf.Addr(), "--user", "alice", "--method", "mschapv2", "--nas-ip", "10.0.0.5", "--port-type", "ethernet")
	if !strings.Contains(out, "Access-Accept") || !strings.Contains(out, "Tunnel-Private-Group-ID") {
		t.Fatal(out)
	}
	out = must(t, "sec\n", "radius", "test", rf.Addr(), "--status", "--json")
	if !json.Valid([]byte(out)) || !strings.Contains(out, "status-server") {
		t.Fatal(out)
	}
	if _, err := mctl(t, "", "radius", "test", rf.Addr(), "--user", "alice", "--secret", "x"); err == nil {
		t.Fatal("secreto por argumento aceptado")
	}

	tf, err := tacacstest.StartFake(tacacstest.FakeConfig{Secret: "tk", Users: map[string]string{"admin": "pw"}, Permit: map[string][]string{"show": nil}})
	if err != nil {
		t.Fatal(err)
	}
	defer tf.Close()
	out = must(t, "tk\npw\n", "tacacs", "test", tf.Addr(), "--user", "admin", "--cmd", "show running-config", "--acct")
	if !strings.Contains(out, "authentication: PASS") || !strings.Contains(out, "PASS_ADD") || !strings.Contains(out, "accounting-stop: SUCCESS") {
		t.Fatal(out)
	}

	dir := t.TempDir()
	t.Chdir(dir)
	must(t, "capw\ncapw\n", "pki", "ca", "init", "--name", "Lab CA", "--out", "ca")
	must(t, "kpw\nkpw\n", "pki", "csr", "--cn", "ise01.lab", "--dns", "ise01.lab", "--ip", "10.0.0.10", "-o", "ise01")
	for _, f := range []string{"ca/ca.crt.pem", "ca/ca.key.pem", "ise01.csr.pem", "ise01.key.pem"} {
		if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, st, err)
		}
	}
	if _, err := mctl(t, "kpw\nkpw\n", "pki", "csr", "--cn", "ise01.lab", "-o", "ise01"); err == nil {
		t.Fatal("sobrescribió una llave existente")
	}
	out = must(t, "capw\n", "pki", "ca", "sign", "--ca", "ca", "--csr", "ise01.csr.pem", "--profile", "server", "-o", "ise01.crt.pem")
	if !strings.Contains(out, "LABORATORIO") {
		t.Fatal(out)
	}
	must(t, "kpw\nexp\nexp\n", "pki", "export", "--cert", "ise01.crt.pem", "--chain", "ca/ca.crt.pem", "--key", "ise01.key.pem", "--format", "p12", "-o", "ise01.p12")
	if b, _ := os.ReadFile("ise01.p12"); len(b) == 0 {
		t.Fatal("p12 vacío")
	}
	must(t, "kpw\nkpw\n", "pki", "key", "--alg", "p384", "-o", "otra.key.pem")
	if out = must(t, "", "pki", "decode", "-f", "ise01.crt.pem"); !strings.Contains(out, "serverAuth") || !strings.Contains(out, "IP:10.0.0.10") {
		t.Fatal(out)
	}

	debug := filepath.Join(dir, "debug.txt")
	b, _ := os.ReadFile(filepath.Join(here, "..", "..", "internal", "ikedec", "testdata", "ikev1_p1_mismatch.txt"))
	os.WriteFile(debug, b, 0o600)
	out = must(t, "", "ike", "decode", "-f", debug, "--json")
	var rep ikedec.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Phase1 != "falló" {
		t.Fatalf("%v %q", err, out)
	}
}
