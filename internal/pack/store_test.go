package pack

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openStore(t *testing.T, dir string, pub ed25519.PublicKey, base Base) (*Store, []Rejected) {
	t.Helper()
	s, rej, err := Open(dir, "v0.3.0", []ed25519.PublicKey{pub}, base)
	if err != nil {
		t.Fatal(err)
	}
	return s, rej
}

func signedZip(t *testing.T, priv ed25519.PrivateKey, mod func(map[string][]byte)) []byte {
	t.Helper()
	f := goodFiles()
	if mod != nil {
		mod(f)
	}
	sign(f, priv)
	return mustZip(t, f)
}

func withVersion(v string) func(map[string][]byte) {
	return func(f map[string][]byte) {
		f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "version: 1.0.0", "version: "+v, 1))
	}
}

func TestIdaYVuelta(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	changes := 0
	s.OnChange = func() { changes++ }

	res, err := s.Install(signedZip(t, priv, nil), false)
	if err != nil || res.Replaced != "" || changes != 1 {
		t.Fatal(err, res, changes)
	}
	if p := s.Snapshot().Find("oom/demo"); p == nil || !p.Official || len(p.Playbooks) != 1 {
		t.Fatalf("%+v", p)
	}
	if ids := s.Snapshot().Find("oom/demo").ScriptIDs(); len(ids) != 1 || ids[0] != "lib-oom-stp" {
		t.Fatal(ids)
	}
	if _, err := os.Stat(filepath.Join(dir, "oom", "demo", "SIGNATURE")); err != nil {
		t.Fatal("no se conservó SIGNATURE")
	}
	// Reabrir: se revalida y vuelve igual, con el origen derivado de la firma.
	s2, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 0 || !s2.Snapshot().Find("oom/demo").Official {
		t.Fatal(rej)
	}
	if _, err := s.Remove("oom/demo"); err != nil || changes != 2 || s.Snapshot().Find("oom/demo") != nil {
		t.Fatal(err, changes)
	}
	if _, err := os.Stat(filepath.Join(dir, "oom", "demo")); !os.IsNotExist(err) {
		t.Fatal("la carpeta sigue")
	}
	if _, err := s.Remove("oom/demo"); Reason(err) != "not_found" {
		t.Fatal(err)
	}
}

func TestRemoveNoUneAlaRuta(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	for _, id := range []string{"../oom/demo", "oom/../oom/demo", "oom/demo/", "/oom/demo"} {
		if _, err := s.Remove(id); Reason(err) != "not_found" {
			t.Errorf("%q: %v", id, err)
		}
	}
	if s.Snapshot().Find("oom/demo") == nil {
		t.Fatal("se quitó con un ID falso")
	}
}

func TestReemplazo(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{})
	if _, err := s.Install(signedZip(t, priv, withVersion("1.1.0")), false); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.1.0", "1.0.9"} {
		_, err := s.Install(signedZip(t, priv, withVersion(v)), false)
		if Reason(err) != "version" {
			t.Errorf("%s: %v", v, err)
		}
	}
	res, err := s.Install(signedZip(t, priv, withVersion("1.2.0")), false)
	if err != nil || res.Replaced != "1.1.0" || s.Snapshot().Find("oom/demo").Version != "1.2.0" {
		t.Fatal(err, res)
	}
}

func TestOficialNoLoReemplazaUnoDeTerceros(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{})
	acme := func(v string) map[string][]byte {
		f := thirdParty()
		f["manifest.yaml"] = []byte(strings.Replace(string(f["manifest.yaml"]), "version: 1.0.0", "version: "+v, 1))
		return f
	}
	signedAcme := acme("1.0.0")
	sign(signedAcme, priv)
	if _, err := s.Install(mustZip(t, signedAcme), false); err != nil || !s.Snapshot().Find("acme/demo").Official {
		t.Fatal(err)
	}
	// Uno de terceros no reemplaza a uno oficial, ni siquiera con una versión más nueva.
	_, err := s.Install(mustZip(t, acme("9.0.0")), true)
	if Reason(err) != "official_replace" {
		t.Fatal(err)
	}
	if s.Snapshot().Find("acme/demo").Version != "1.0.0" {
		t.Fatal("se reemplazó")
	}
}

func TestTercerosRequiereConfirmacion(t *testing.T) {
	pub, _ := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{})
	_, err := s.Install(mustZip(t, thirdParty()), false)
	if Reason(err) != "unsigned" || s.Snapshot().Find("acme/demo") != nil {
		t.Fatal(err)
	}
	res, err := s.Install(mustZip(t, thirdParty()), true)
	if err != nil || res.Pack.Official {
		t.Fatal(err)
	}
	// Reabrir: sin SIGNATURE sigue siendo de terceros.
}

func TestChoques(t *testing.T) {
	pub, priv := testKey(t)
	cases := []struct {
		name string
		base Base
	}{
		{"playbook de la base", Base{PlaybookIDs: []string{"ios-xe/oom-stp"}}},
		{"script de la base", Base{ScriptIDs: []string{"lib-oom-stp"}}},
		{"nombre de script de la base", Base{ScriptNames: []string{"l2 · stp"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := openStore(t, t.TempDir(), pub, c.base)
			_, err := s.Install(signedZip(t, priv, nil), false)
			if Reason(err) != "collision" {
				t.Fatal(err)
			}
		})
	}
	t.Run("con otro paquete", func(t *testing.T) {
		s, _ := openStore(t, t.TempDir(), pub, Base{})
		if _, err := s.Install(signedZip(t, priv, nil), false); err != nil {
			t.Fatal(err)
		}
		_, err := s.Install(signedZip(t, priv, func(f map[string][]byte) {
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "oom/demo", "oom/otro", 1))
		}), false)
		if Reason(err) != "collision" {
			t.Fatal(err)
		}
	})
	t.Run("script de scripts.json con el ID derivado de un playbook", func(t *testing.T) {
		s, _ := openStore(t, t.TempDir(), pub, Base{})
		_, err := s.Install(signedZip(t, priv, func(f map[string][]byte) { f["scripts.json"] = []byte(scriptsJSON("lib-oom-stp")) }), false)
		if Reason(err) != "collision" {
			t.Fatal(err)
		}
	})
}

func TestInstalarRechazadoNoDejaNada(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{PlaybookIDs: []string{"ios-xe/oom-stp"}})
	s.Install(signedZip(t, priv, nil), false)
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 || len(s.Snapshot().Packs) != 0 {
		t.Fatalf("quedó %v", ents)
	}
}

func TestRevalidacionAlArrancar(t *testing.T) {
	pub, priv := testKey(t)
	prep := func(t *testing.T) (string, string) {
		dir := t.TempDir()
		s, _ := openStore(t, dir, pub, Base{})
		if _, err := s.Install(signedZip(t, priv, nil), false); err != nil {
			t.Fatal(err)
		}
		return dir, filepath.Join(dir, "oom", "demo")
	}
	for _, c := range []struct {
		name   string
		tamper func(d string)
		reason string
	}{
		{"archivo alterado", func(d string) { os.WriteFile(filepath.Join(d, "README.md"), []byte("otro"), 0o600) }, "index.mismatch"},
		{"archivo de más", func(d string) { os.WriteFile(filepath.Join(d, "extra.txt"), []byte("x"), 0o600) }, "zip.path"},
		{"playbook de más", func(d string) { os.WriteFile(filepath.Join(d, "playbooks", "otro.yaml"), []byte(goodPlaybook), 0o600) }, "index.mismatch"},
		{"enlace", func(d string) {
			os.Remove(filepath.Join(d, "README.md"))
			os.Symlink("/etc/passwd", filepath.Join(d, "README.md"))
		}, "zip.path"},
		{"índice con la firma intacta pero sin SIGNATURE ni índice", func(d string) { os.Remove(filepath.Join(d, "INDEX")) }, "index.mismatch"},
		{"firma de otra llave", func(d string) { os.WriteFile(filepath.Join(d, "SIGNATURE"), []byte("AAAA\n"), 0o600) }, "signature.invalid"},
		{"subcarpeta", func(d string) { os.MkdirAll(filepath.Join(d, "x"), 0o700) }, "zip.path"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, d := prep(t)
			c.tamper(d)
			s, rej := openStore(t, dir, pub, Base{})
			if len(rej) != 1 || rej[0].Reason != c.reason || rej[0].Dir != "oom/demo" {
				t.Fatalf("%+v", rej)
			}
			if len(s.Snapshot().Packs) != 0 {
				t.Fatal("el paquete alterado quedó cargado")
			}
		})
	}
}

func TestTercerosAlteradoSeOmite(t *testing.T) {
	pub, _ := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	if _, err := s.Install(mustZip(t, thirdParty()), true); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "acme", "demo", "README.md"), []byte("otro"), 0o600)
	_, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 1 || rej[0].Reason != "index.mismatch" {
		t.Fatalf("%+v", rej)
	}
}

func TestArranqueLimpiaTmpYSigueConOtros(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	os.MkdirAll(filepath.Join(dir, ".tmp-123", "x"), 0o700)
	os.WriteFile(filepath.Join(dir, "oom", "demo", "README.md"), []byte("x"), 0o600) // este se omite
	s2, rej := openStore(t, dir, pub, Base{})
	if _, err := os.Stat(filepath.Join(dir, ".tmp-123")); !os.IsNotExist(err) {
		t.Fatal(".tmp sigue")
	}
	if len(rej) != 1 || s2 == nil {
		t.Fatal(rej)
	}
}

func TestReadArchive(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "a.mpack")
	os.WriteFile(f, make([]byte, MaxArchive+1), 0o600)
	if _, err := ReadArchive(f); Reason(err) != "zip.too_big" {
		t.Fatal(err)
	}
	if _, err := ReadArchive(d); Reason(err) != "zip.invalid" {
		t.Fatal(err)
	}
	if _, err := ReadArchive(filepath.Join(d, "no")); Reason(err) != "read" {
		t.Fatal(err)
	}
}

func TestCarpetaQueNoCoincideConSuID(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	if err := os.Rename(filepath.Join(dir, "oom", "demo"), filepath.Join(dir, "oom", "otro")); err != nil {
		t.Fatal(err)
	}
	_, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 1 || rej[0].Reason != "zip.path" {
		t.Fatalf("%+v", rej)
	}
}
