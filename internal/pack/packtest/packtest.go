// Package packtest da a las pruebas un par de llaves propio (nunca la oficial) y el paquete oficial oom/ios-xe del repo
// armado y firmado con él.
package packtest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/pack"
)

var priv = ed25519.NewKeyFromSeed(func() []byte { h := sha256.Sum256([]byte("macuahuitl-pruebas")); return h[:] }())

// Keys son las llaves oficiales de las pruebas: pasan a core.Options.PackKeys.
func Keys() []ed25519.PublicKey { return []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)} }

// Private es la llave privada de las pruebas.
func Private() ed25519.PrivateKey { return priv }

// RepoDir es la raíz del repo.
func RepoDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..")
}

// Signed arma y firma con la llave de pruebas el zip de la carpeta fuente dir.
func Signed(t testing.TB, dir string) []byte {
	t.Helper()
	files, err := pack.ReadSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	pack.Sign(files, priv)
	b, err := pack.Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// IOSXE es packs/ios-xe del repo, firmado con la llave de pruebas.
func IOSXE(t testing.TB) []byte {
	t.Helper()
	return Signed(t, filepath.Join(RepoDir(), "packs", "ios-xe"))
}

// InstallIOSXE deja oom/ios-xe instalado en <data>/packs, como lo habría dejado «mctl pack install»; el núcleo que
// se abra después sobre data debe usar Keys() como core.Options.PackKeys.
func InstallIOSXE(t testing.TB, data string) {
	t.Helper()
	st, _, err := pack.Open(filepath.Join(data, "packs"), "dev", Keys(), pack.Base{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Install(IOSXE(t), false); err != nil {
		t.Fatal(err)
	}
}
