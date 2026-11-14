package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/pack"
)

func TestFirmaLosPaquetesDelRepoYVerificanComoOficiales(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	hechos, err := firmaTodos("../../../packs", out, "0.4.1", priv, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hechos {
		data, err := os.ReadFile(filepath.Join(out, h))
		if err != nil {
			t.Fatal(err)
		}
		p, err := pack.Verify(data, "0.4.1", []ed25519.PublicKey{pub})
		if err != nil || !p.Official {
			t.Fatalf("%s no verifica como oficial: %v", h, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "oom-ios-xe-"+versionIOSXE(t)+".mpack")); err != nil {
		t.Fatal("falta el .mpack de oom/ios-xe")
	}
}

func TestRechazaLlaveQueNoEsLaOficial(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otra, _, _ := ed25519.GenerateKey(rand.Reader)
	out := t.TempDir()
	if _, err := firmaTodos("../../../packs", out, "0.4.1", priv, []ed25519.PublicKey{otra}); err == nil {
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

// copia arma una carpeta packs/ temporal con la fuente de ios-xe bajo otro nombre de carpeta, sin tocar el id.
func copia(t *testing.T, carpeta string) string {
	t.Helper()
	src := t.TempDir()
	files, err := pack.ReadSource("../../../packs/ios-xe")
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		p := filepath.Join(src, carpeta, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return src
}

func TestRechazaIDQueNoEsLaCarpeta(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src := copia(t, "ios")
	if _, err := firmaTodos(src, t.TempDir(), "0.4.1", priv, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("firmó packs/ios con id oom/ios-xe")
	}
}

func TestNoPisaUnAssetExistente(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	out := t.TempDir()
	if _, err := firmaTodos("../../../packs", out, "0.4.1", priv, []ed25519.PublicKey{pub}); err != nil {
		t.Fatal(err)
	}
	if _, err := firmaTodos("../../../packs", out, "0.4.1", priv, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("pisó el .mpack de oom/ios-xe")
	}
}

// versionIOSXE lee la versión de packs/ios-xe/manifest.yaml para no fijarla en la prueba.
func versionIOSXE(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../../packs/ios-xe/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^version: (\S+)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("el manifiesto no trae versión")
	}
	return string(m[1])
}
