package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/pack"
)

func TestFirmaLosPaquetesDelRepoYVerificanComoOficiales(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	hechos, err := firmaTodos("../../../packs", out, "0.3.0", priv, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hechos {
		data, err := os.ReadFile(filepath.Join(out, h))
		if err != nil {
			t.Fatal(err)
		}
		p, err := pack.Verify(data, "0.3.0", []ed25519.PublicKey{pub})
		if err != nil || !p.Official {
			t.Fatalf("%s no verifica como oficial: %v", h, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "oom-ios-xe-1.0.0.mpack")); err != nil {
		t.Fatal("falta oom-ios-xe-1.0.0.mpack")
	}
}

func TestRechazaLlaveQueNoEsLaOficial(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otra, _, _ := ed25519.GenerateKey(rand.Reader)
	out := t.TempDir()
	if _, err := firmaTodos("../../../packs", out, "0.3.0", priv, []ed25519.PublicKey{otra}); err == nil {
		t.Fatal("firmó con una llave que no corresponde a la oficial")
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Fatalf("dejó archivos con una llave equivocada: %v", entries)
	}
}

func TestLlaveMalFormada(t *testing.T) {
	for _, v := range []string{"", "no-es-base64", "QUJD"} {
		if _, err := llave(v); err == nil {
			t.Fatalf("aceptó %q", v)
		}
	}
}
