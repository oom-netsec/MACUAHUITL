package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/transfer/transfertest"
)

// waitFor espera hasta que la salida de serve cumpla re (devuelve el primer grupo).
func waitFor(t *testing.T, out *syncBuf, re *regexp.Regexp) string {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			return m[1]
		}
	}
	t.Fatalf("no apareció %v en:\n%s", re, out.String())
	return ""
}

func TestTransferServeGetPut(t *testing.T) {
	startCore(t)
	pub, recv, dest := t.TempDir(), t.TempDir(), t.TempDir()
	data := bytes.Repeat([]byte("router\n"), 400)
	os.WriteFile(filepath.Join(pub, "r1.cfg"), data, 0o600)
	var out syncBuf
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"--lang", "es", "transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1:0", "--write", "--allow", "127.0.0.1", "--from", pub, "--dir", recv, "--duration", "6s"}, strings.NewReader(""), &out)
	}()
	addr := waitFor(t, &out, regexp.MustCompile(`sirviendo tftp en (127\.0\.0\.1:\d+)`))
	waitFor(t, &out, regexp.MustCompile(`(copy running-config tftp://127\.0\.0\.1/)`)) // las líneas de carpetas y la pista salen después
	if s := out.String(); !strings.Contains(s, "lee de:   "+pub) || !strings.Contains(s, "recibe en: "+recv) || !strings.Contains(s, "copy running-config tftp://127.0.0.1/") {
		t.Fatalf("serve:\n%s", s)
	}
	// get a una carpeta elegida, con hash esperado.
	sum := regexp.MustCompile(`SHA-256  (\w+)`)
	g := must(t, "", "transfer", "get", "tftp://"+addr+"/r1.cfg", "--dir", dest)
	if !strings.Contains(g, filepath.Join(dest, "r1.cfg")) || sum.FindStringSubmatch(g) == nil {
		t.Fatalf("get: %s", g)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "r1.cfg")); !bytes.Equal(b, data) {
		t.Fatal("contenido distinto")
	}
	// Segunda descarga al mismo lugar: no sobrescribe.
	if _, err := mctl(t, "", "transfer", "get", "tftp://"+addr+"/r1.cfg", "--dir", dest); err == nil {
		t.Fatal("sobrescribió")
	}
	// Hash equivocado: error y nada queda.
	d2 := t.TempDir()
	if _, err := mctl(t, "", "transfer", "get", "tftp://"+addr+"/r1.cfg", "--dir", d2, "--sha256", strings.Repeat("0", 64)); err == nil {
		t.Fatal("hash distinto aceptado")
	}
	if ents, _ := os.ReadDir(d2); len(ents) != 0 {
		t.Fatal("quedó un archivo con hash distinto")
	}
	// put desde una carpeta, y por ruta de archivo.
	must(t, "", "transfer", "put", "tftp://"+addr+"/subida.cfg", "r1.cfg", "--from", pub)
	must(t, "", "transfer", "put", "tftp://"+addr+"/subida2.cfg", filepath.Join(pub, "r1.cfg"))
	for _, n := range []string{"subida.cfg", "subida2.cfg"} {
		if b, _ := os.ReadFile(filepath.Join(recv, n)); !bytes.Equal(b, data) {
			t.Fatalf("%s no llegó", n)
		}
	}
	if !strings.Contains(must(t, "", "transfer", "list"), "tftp") {
		t.Fatal("list")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "escritura") || !strings.Contains(out.String(), "lectura") {
		t.Fatalf("eventos de transferencia:\n%s", out.String())
	}
}

func TestTransferUsageAndHint(t *testing.T) {
	startCore(t)
	for _, args := range [][]string{
		{"transfer", "serve"},
		{"transfer", "serve", "--proto", "tftp"},
		{"transfer", "serve", "--proto", "tftp", "--listen", "127.0.0.1", "--allow", "no-ip"},
		{"transfer", "serve", "--proto", "ftp", "--listen", "127.0.0.1", "--pasv-ports", "9-1"},
		{"transfer", "get"},
		{"transfer", "put", "tftp://127.0.0.1/x"},
		{"transfer", "put", "tftp://127.0.0.1/x", t.TempDir()},
		{"transfer", "hint", "http", "8080"},
	} {
		if _, err := mctl(t, "", args...); err == nil {
			t.Errorf("mctl %v debió fallar", args)
		}
	}
	out := must(t, "", "transfer", "hint", "scp", "2222")
	if !strings.Contains(out, "tcp dport 22 redirect to :2222") || !strings.Contains(out, "setcap") {
		t.Fatal(out)
	}
	if out := must(t, "", "transfer", "list"); !strings.Contains(out, "no hay servidores") {
		t.Fatal(out)
	}
}

func TestTransferLs(t *testing.T) {
	startCore(t)
	base := transfertest.HTTPIndex(t, "<a href=\"../\">up</a>\n<a href=\"r1.cfg\">r1.cfg</a> 2026-11-06 10:15  1K\n<a href=\"sub/\">sub/</a> 2026-11-05 08:30  -\n<a href=\"evil%E2%80%AEgnp.exe\">x</a>\n")
	out := must(t, "", "transfer", "ls", base+"/imagenes/")
	for _, want := range []string{"dir ", "sub/", "file", "r1.cfg", "1024", "2026-11-06 10:15", "2 entradas (http)"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if j := must(t, "", "transfer", "ls", base+"/", "--json"); !regexp.MustCompile(`"name":\s+"r1.cfg"`).MatchString(j) || !regexp.MustCompile(`"method":\s+"http"`).MatchString(j) {
		t.Fatalf("json:\n%s", j)
	}
	_, err := mctl(t, "", "transfer", "ls", "tftp://127.0.0.1:6969/")
	if err == nil || !strings.Contains(err.Error(), "este servidor no permite listar") {
		t.Fatalf("tftp: %v", err)
	}
	if _, err := mctl(t, "", "transfer", "ls"); err == nil {
		t.Fatal("sin URL debe fallar")
	}
}
