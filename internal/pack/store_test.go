package pack

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// C1: un tercero no puede ocupar IDs movidos ni de futuros paquetes oficiales por la vía del prefijo de editor.
func TestEditoresReservadosParaTerceros(t *testing.T) {
	pub, priv := testKey(t)
	base := Base{PlaybookIDs: []string{"ios-xe/tac-baseline"}, ScriptIDs: []string{"lib-tac-baseline", "lib-cfg-ntp"},
		ReservedPlaybooks: []string{"ios-xe/l2-stp"}, ReservedScripts: []string{"lib-l2-stp"}}
	evil := func(editor string) map[string][]byte {
		f := goodFiles()
		f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "oom/demo", editor+"/evil", 1))
		setPB(f, strings.Replace(goodPlaybook, "oom-stp", "l2-stp", 1))
		return f
	}
	for _, withOfficial := range []bool{false, true} {
		s, _ := openStore(t, t.TempDir(), pub, base)
		if withOfficial {
			if _, err := s.Install(signedZip(t, priv, nil), false); err != nil {
				t.Fatal(err)
			}
		}
		for _, ed := range []string{"l2", "tac", "cfg", "oom", "ios", "nx", "wireless", "lib"} {
			f := evil(ed)
			setPB(f, strings.Replace(goodPlaybook, "oom-stp", ed+"-stp", 1))
			if ed == "l2" {
				setPB(f, strings.Replace(goodPlaybook, "oom-stp", "l2-stp", 1)) // el escenario del hallazgo
			}
			_, err := s.Install(mustZip(t, f), true)
			if r := Reason(err); r != "editor.reserved" {
				t.Errorf("editor %q (oficial=%v): %v", ed, withOfficial, err)
			}
		}
		// Un editor con guion no es válido para terceros: «l2-stp» no podría publicar ios-xe/l2-stp-guard.
		for _, ed := range []string{"ios-xe", "nx-os", "l2-foo", "l2-stp", "acme-x", "abcdefghijklmnopq"} {
			f := evil(ed)
			setPB(f, strings.Replace(goodPlaybook, "oom-stp", ed+"-guard", 1))
			if _, err := s.Install(mustZip(t, f), true); Reason(err) != "manifest.invalid" {
				t.Errorf("editor %q (oficial=%v): %v", ed, withOfficial, err)
			}
		}
		// Un editor normal sigue pudiendo instalar.
		ok := thirdParty()
		setPB(ok, strings.ReplaceAll(string(ok["playbooks/acme-stp.yaml"]), "L2 · STP", "Acme · STP"))
		if _, err := s.Install(mustZip(t, ok), true); err != nil {
			t.Fatal(err)
		}
	}
}

// Defensa en profundidad: aunque el editor no estuviera reservado, un ID de la lista reservada choca (se prueba el
// choque directamente, porque calcular los editores ya reserva el propio «acme»).
func TestIDsReservadosChocan(t *testing.T) {
	pub, _ := testKey(t)
	p, err := Verify(mustZip(t, thirdParty()), "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := openStore(t, t.TempDir(), pub, Base{ReservedPlaybooks: []string{"ios-xe/acme-stp"}})
	wantReason(t, s.collides(p, nil), "collision")
	s, _ = openStore(t, t.TempDir(), pub, Base{ReservedScripts: []string{"lib-acme-stp"}})
	wantReason(t, s.collides(p, nil), "collision")
	// Un oficial no está sujeto a las reservas.
	po := *p
	po.Official = true
	if err := s.collides(&po, nil); err != nil {
		t.Fatal(err)
	}
}

// I1: un paquete que no pasó la revalidación al arrancar se puede reinstalar (la carpeta dañada se aparta).
func TestReinstalarUnPaqueteCorrompido(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	z := signedZip(t, priv, nil)
	if _, err := s.Install(z, false); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "oom", "demo", "README.md"), []byte("dañado"), 0o600)
	s2, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 1 || s2.Snapshot().Find("oom/demo") != nil {
		t.Fatalf("%+v", rej)
	}
	if _, err := s2.Install(z, false); err != nil {
		t.Fatalf("reinstalar: %v", err)
	}
	if s2.Snapshot().Find("oom/demo") == nil {
		t.Fatal("no quedó instalado")
	}
	if _, rej := openStore(t, dir, pub, Base{}); len(rej) != 0 {
		t.Fatalf("tras reinstalar: %+v", rej)
	}
}

// bigPack arma un paquete oficial válido con n playbooks y, si pad > 0, relleno de comentario en cada uno.
func bigPack(t *testing.T, priv ed25519.PrivateKey, n, pad int) []byte {
	t.Helper()
	f := map[string][]byte{"manifest.yaml": []byte(goodManifest), "README.md": []byte("x")}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("p%04d", i)
		body := fmt.Sprintf("id: %s\nplatform: ios-xe\nname: \"P · %s\"\nname_en: \"P · %s\"\ncommands:\n  - cmd: show clock\n", id, id, id)
		if pad > 0 {
			body += "#" + strings.Repeat("x", pad) + "\n"
		}
		f["playbooks/"+id+".yaml"] = []byte(body)
	}
	sign(f, priv)
	return mustZip(t, f)
}

// I2: el INDEX del almacén no cuenta para los topes al revalidar; un paquete justo en el límite sigue cargando.
func TestLimitesNoContanElIndexAlRevalidar(t *testing.T) {
	pub, priv := testKey(t)
	for name, z := range map[string][]byte{
		"2000 entradas": bigPack(t, priv, MaxEntries-3, 0),
		"20 MB":         bigPack(t, priv, 20, maxPlaybook-176),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, _ := openStore(t, dir, pub, Base{})
			if _, err := s.Install(z, false); err != nil {
				t.Fatal(err)
			}
			s2, rej := openStore(t, dir, pub, Base{})
			if len(rej) != 0 || s2.Snapshot().Find("oom/demo") == nil {
				t.Fatalf("al arrancar: %+v", rej)
			}
		})
	}
}

// Si el proceso murió entre los dos rename, al arrancar vuelve la versión vieja que quedó en .tmp-*/old.
func TestRecuperaLaVersionViejaTrasUnaCaida(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	crash := filepath.Join(dir, ".tmp-crash")
	os.MkdirAll(crash, 0o700)
	if err := os.Rename(filepath.Join(dir, "oom", "demo"), filepath.Join(crash, "old")); err != nil {
		t.Fatal(err)
	}
	s2, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 0 || s2.Snapshot().Find("oom/demo") == nil {
		t.Fatalf("no se recuperó: %+v", rej)
	}
	if _, err := os.Stat(crash); !os.IsNotExist(err) {
		t.Fatal(".tmp sigue")
	}
}

// Si la nueva ya entró (final existe), lo que quedó en old se descarta.
func TestNoPisaLaVersionNuevaConLaViejaDeUnaCaida(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, withVersion("1.1.0")), false)
	os.MkdirAll(filepath.Join(dir, ".tmp-x", "old"), 0o700)
	s2, _ := openStore(t, dir, pub, Base{})
	if s2.Snapshot().Find("oom/demo").Version != "1.1.0" {
		t.Fatal("se pisó")
	}
}

func TestOnChangeCorreConElLockTomado(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{})
	s.OnChange = func() {
		if s.mu.TryLock() {
			s.mu.Unlock()
			t.Error("OnChange debe correr bajo s.mu para no dejar publicado un catálogo viejo")
		}
	}
	s.Install(signedZip(t, priv, nil), false)
	s.Remove("oom/demo")
}

// Los rechazos por choque, versión u oficial devuelven el paquete, para auditar su id real.
func TestRechazosDevuelvenElPaquete(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{PlaybookIDs: []string{"ios-xe/oom-stp"}})
	res, err := s.Install(signedZip(t, priv, nil), false)
	if Reason(err) != "collision" || res == nil || res.Pack.ID != "oom/demo" {
		t.Fatalf("%v %+v", err, res)
	}
	s, _ = openStore(t, t.TempDir(), pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	res, err = s.Install(signedZip(t, priv, nil), false)
	if Reason(err) != "version" || res == nil || res.Pack.Version != "1.0.0" {
		t.Fatalf("%v %+v", err, res)
	}
}

// pack.err.read no filtra rutas absolutas de la carpeta de datos.
func TestErrorDeLecturaSinRutas(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root escribe donde sea")
	}
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	_, err := s.Install(signedZip(t, priv, nil), false)
	if Reason(err) != "read" || strings.Contains(err.Error(), dir) {
		t.Fatalf("%v", err)
	}
}

func TestReadArchiveNoSeCuelgaConUnFIFO(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x.mpack")
	if err := sys.Mkfifo(f); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadArchive(f); done <- err }()
	select {
	case err := <-done:
		wantReason(t, err, "zip.invalid")
	case <-time.After(3 * time.Second):
		t.Fatal("ReadArchive se colgó con un FIFO")
	}
}

// Al arrancar se vuelven a aplicar los pasos 4 a 7: un oom/* alterado a mano que se quedó sin firma no conserva el editor.
func TestArranqueOomSinFirmaSeOmite(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	if err := os.Remove(filepath.Join(dir, "oom", "demo", "SIGNATURE")); err != nil { // el INDEX no cubre SIGNATURE: solo cambia el origen
		t.Fatal(err)
	}
	_, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 1 || rej[0].Reason != "editor.reserved" || rej[0].ID != "oom/demo" {
		t.Fatalf("%+v", rej)
	}
}

// Los oficiales se aceptan primero: ante un choque en disco, el de terceros es el que se omite aunque su carpeta
// vaya antes en el orden del directorio («acme» < «oom»).
func TestArranqueOficialesPrimero(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	if _, err := s.Install(signedZip(t, priv, nil), false); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	s2, _ := openStore(t, other, pub, Base{})
	if _, err := s2.Install(mustZip(t, thirdParty()), true); err != nil { // mismo nombre de script «L2 · STP»
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(other, "acme"), filepath.Join(dir, "acme")); err != nil {
		t.Fatal(err)
	}
	s3, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 1 || rej[0].ID != "acme/demo" || rej[0].Reason != "collision" || s3.Snapshot().Find("oom/demo") == nil {
		t.Fatalf("%+v", rej)
	}
}

// Un núcleo que ya trae un ID de un paquete instalado, o más viejo que su min_core, omite el paquete al arrancar.
func TestArranqueReaplicaChoquesYMinCore(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	s.Install(signedZip(t, priv, nil), false)
	_, rej := openStore(t, dir, pub, Base{PlaybookIDs: []string{"ios-xe/oom-stp"}})
	if len(rej) != 1 || rej[0].Reason != "collision" {
		t.Fatalf("choque: %+v", rej)
	}
	_, rej, err := Open(dir, "v0.1.0", []ed25519.PublicKey{pub}, Base{})
	if err != nil || len(rej) != 1 || rej[0].Reason != "core.too_old" {
		t.Fatalf("min_core: %+v %v", rej, err)
	}
}

// Un editor que pasa a estar reservado tras instalar el paquete (una versión nueva del núcleo) lo omite al arrancar.
func TestArranqueReaplicaLasReservas(t *testing.T) {
	pub, _ := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	if _, err := s.Install(mustZip(t, thirdParty()), true); err != nil {
		t.Fatal(err)
	}
	reservedSegments["acme"] = true
	defer delete(reservedSegments, "acme")
	_, rej := openStore(t, dir, pub, Base{})
	if len(rej) != 1 || rej[0].Reason != "editor.reserved" {
		t.Fatalf("%+v", rej)
	}
}

// Si el paso previo de InstallWith falla, no se instala nada: ni disco, ni foto, ni OnChange; si sale bien, corre
// con el paquete ya validado y antes de publicarlo.
func TestInstallWithPrepare(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	changes := 0
	s.OnChange = func() { changes++ }
	boom := errors.New("boom")
	if _, err := s.InstallWith(signedZip(t, priv, nil), false, func(*Pack, string) error { return boom }, nil); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 || len(s.Snapshot().Packs) != 0 || changes != 0 {
		t.Fatalf("quedó %v %d", ents, changes)
	}
	visto := true
	if _, err := s.InstallWith(signedZip(t, priv, nil), false, func(p *Pack, _ string) error {
		visto = s.Snapshot().Find(p.ID) != nil // todavía no está publicado
		return nil
	}, nil); err != nil || visto || s.Snapshot().Find("oom/demo") == nil {
		t.Fatalf("%v visto=%v", err, visto)
	}
}

// Si falla el fsync de la carpeta tras el rename, el paquete ya está en disco: se publica y el fallo es un aviso.
func TestFalloDelFsyncFinalPublicaYAvisa(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{})
	old := syncDir
	syncDir = func(d string) error {
		if !strings.Contains(d, ".tmp-") {
			return errors.New("fsync simulado")
		}
		return old(d)
	}
	defer func() { syncDir = old }()
	changes := 0
	s.OnChange = func() { changes++ }
	res, err := s.Install(signedZip(t, priv, nil), false)
	if err != nil || res.SyncWarning == nil || changes != 1 || len(s.Snapshot().Packs) != 1 {
		t.Fatalf("res=%+v err=%v changes=%d", res, err, changes)
	}
}

// prepare corre antes de tocar el disco y commit después del extract, antes de publicar: nada que retenga una
// transacción durante el fsync del extract. Un fallo de commit no deshace la instalación: va en Result.CommitErr.
func TestInstallWithCommitCorreDespuesDelExtract(t *testing.T) {
	pub, priv := testKey(t)
	dir := t.TempDir()
	s, _ := openStore(t, dir, pub, Base{})
	enDisco := func() bool { _, err := os.Stat(filepath.Join(dir, "oom", "demo")); return err == nil }
	var prepDisco, commitDisco, commitPublicado bool
	boom := errors.New("boom")
	res, err := s.InstallWith(signedZip(t, priv, nil), false,
		func(*Pack, string) error { prepDisco = enDisco(); return nil },
		func(p *Pack) error {
			commitDisco, commitPublicado = enDisco(), s.Snapshot().Find(p.ID) != nil
			return boom
		})
	if err != nil || !errors.Is(res.CommitErr, boom) || prepDisco || !commitDisco || commitPublicado || s.Snapshot().Find("oom/demo") == nil {
		t.Fatalf("err=%v res=%+v prep=%v commit=%v/%v", err, res, prepDisco, commitDisco, commitPublicado)
	}
}

// El nombre en inglés de un script derivado también choca: dos paquetes con nombres distintos en español pero
// iguales en inglés dejarían dos scripts indistinguibles con la app en inglés. Lo mismo contra la base.
func TestChocaElNombreEnIngles(t *testing.T) {
	pub, priv := testKey(t)
	s, _ := openStore(t, t.TempDir(), pub, Base{ScriptNamesEN: []string{"Base · Health"}})
	if _, err := s.Install(signedZip(t, priv, nil), false); err != nil { // oom/demo: «L2 · STP» en los dos idiomas
		t.Fatal(err)
	}
	for _, en := range []string{"L2 · STP", "l2 · stp", "Base · Health"} {
		f := thirdParty()
		setPB(f, strings.NewReplacer(`name: "L2 · STP"`, `name: "Acme · Árbol"`, `name_en: "L2 · STP"`, `name_en: "`+en+`"`).Replace(string(f["playbooks/acme-stp.yaml"])))
		if _, err := s.Install(mustZip(t, f), true); Reason(err) != "collision" {
			t.Errorf("name_en %q: %v; quería collision", en, err)
		}
	}
	ok := thirdParty()
	setPB(ok, strings.NewReplacer(`name: "L2 · STP"`, `name: "Acme · Árbol"`, `name_en: "L2 · STP"`, `name_en: "Acme · Tree"`).Replace(string(ok["playbooks/acme-stp.yaml"])))
	if _, err := s.Install(mustZip(t, ok), true); err != nil {
		t.Fatal(err)
	}
}
