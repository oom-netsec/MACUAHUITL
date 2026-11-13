package pack

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
)

const goodManifest = `id: oom/demo
version: 1.0.0
min_core: 0.2.0
name: Demo
name_en: Demo
description: Paquete de prueba
description_en: Test package
platforms: [ios-xe]
author: Pruebas
license: Apache-2.0
`

const goodPlaybook = `id: oom-stp
platform: ios-xe
name: "L2 · STP"
name_en: "L2 · STP"
commands:
  - cmd: show spanning-tree summary
`

func goodFiles() map[string][]byte {
	return map[string][]byte{
		"manifest.yaml":          []byte(goodManifest),
		"README.md":              []byte("# Demo\n"),
		"playbooks/oom-stp.yaml": []byte(goodPlaybook),
	}
}

// setPB deja en f un solo playbook, en el archivo que lleva el nombre de su id (regla del instalador).
func setPB(f map[string][]byte, body string) {
	for n := range f {
		if strings.HasPrefix(n, "playbooks/") {
			delete(f, n)
		}
	}
	id := strings.Trim(strings.SplitN(strings.SplitN(body, "id: ", 2)[1], "\n", 2)[0], "\"")
	f["playbooks/"+id+".yaml"] = []byte(body)
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(files map[string][]byte, priv ed25519.PrivateKey) {
	files["SIGNATURE"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Index(files))) + "\n")
}

func mustZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	b, err := Zip(files)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := Reason(err); got != reason {
		t.Fatalf("motivo %q (err=%v), se esperaba %q", got, err, reason)
	}
}

func TestOficialValido(t *testing.T) {
	pub, priv := testKey(t)
	f := goodFiles()
	sign(f, priv)
	p, err := Verify(mustZip(t, f), "v0.3.0", []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Official || p.Origin() != "official" || len(p.Playbooks) != 1 || p.Playbooks[0].ID != "ios-xe/oom-stp" || p.SHA256 == "" || p.Readme != "# Demo\n" {
		t.Fatalf("%+v", p)
	}
}

func TestOficialSinPrefijoDeEditor(t *testing.T) {
	pub, priv := testKey(t)
	f := goodFiles()
	setPB(f, strings.Replace(goodPlaybook, "oom-stp", "stp", 1))
	sign(f, priv)
	if _, err := Verify(mustZip(t, f), "dev", []ed25519.PublicKey{pub}); err != nil {
		t.Fatal(err)
	}
}

func thirdParty() map[string][]byte {
	f := goodFiles()
	f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "oom/demo", "acme/demo", 1))
	setPB(f, strings.Replace(goodPlaybook, "oom-stp", "acme-stp", 1))
	return f
}

func TestTercerosValido(t *testing.T) {
	p, err := Verify(mustZip(t, thirdParty()), "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Official || p.Origin() != "third-party" || !p.DevCore {
		t.Fatalf("%+v", p)
	}
}

func TestRechazos(t *testing.T) {
	pub, priv := testKey(t)
	keys := []ed25519.PublicKey{pub}
	_, otra := testKey(t)
	signed := func(mod func(map[string][]byte)) map[string][]byte {
		f := goodFiles()
		mod(f)
		sign(f, priv)
		return f
	}
	cases := []struct {
		name   string
		files  map[string][]byte
		core   string
		reason string
	}{
		{"firma de otra llave", func() map[string][]byte { f := goodFiles(); sign(f, otra); return f }(), "dev", "signature.invalid"},
		{"firma que no cubre un archivo", func() map[string][]byte {
			f := goodFiles()
			sign(f, priv)
			f["playbooks/otro.yaml"] = []byte(goodPlaybook)
			return f
		}(), "dev", "signature.invalid"},
		{"firma no base64", func() map[string][]byte { f := goodFiles(); f["SIGNATURE"] = []byte("!!!"); return f }(), "dev", "signature.invalid"},
		{"ruta con ..", signed(func(f map[string][]byte) { f["playbooks/../x.yaml"] = []byte("x") }), "dev", "zip.path"},
		{"ruta absoluta", signed(func(f map[string][]byte) { f["/etc/x"] = []byte("x") }), "dev", "zip.path"},
		{"barra invertida", signed(func(f map[string][]byte) { f["playbooks\\x.yaml"] = []byte("x") }), "dev", "zip.path"},
		{"unicode que imita la barra", signed(func(f map[string][]byte) { f["playbooks∕x.yaml"] = []byte("x") }), "dev", "zip.path"},
		{"subcarpeta", signed(func(f map[string][]byte) { f["playbooks/a/x.yaml"] = []byte("x") }), "dev", "zip.path"},
		{"nombre en mayúsculas", signed(func(f map[string][]byte) { f["playbooks/X.yaml"] = []byte("x") }), "dev", "zip.path"},
		{"archivo ajeno", signed(func(f map[string][]byte) { f["extra.txt"] = []byte("x") }), "dev", "zip.path"},
		{"sin README", func() map[string][]byte { f := goodFiles(); delete(f, "README.md"); return f }(), "dev", "zip.missing"},
		{"README de más de 64 KB", func() map[string][]byte {
			f := goodFiles()
			f["README.md"] = bytes.Repeat([]byte("a"), MaxReadme+1)
			return f
		}(), "dev", "zip.too_big"},
		{"manifiesto con campo desconocido", func() map[string][]byte {
			f := goodFiles()
			f["manifest.yaml"] = []byte(goodManifest + "extra: 1\n")
			return f
		}(), "dev", "manifest.invalid"},
		{"id con editor mal formado", func() map[string][]byte {
			f := goodFiles()
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "oom/demo", "Oom/Demo", 1))
			return f
		}(), "dev", "manifest.invalid"},
		{"version con v", func() map[string][]byte {
			f := goodFiles()
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "version: 1.0.0", "version: v1.0.0", 1))
			return f
		}(), "dev", "manifest.invalid"},
		{"nombre con control", func() map[string][]byte {
			f := goodFiles()
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "name: Demo", "name: \"De\\x01mo\"", 1))
			return f
		}(), "dev", "manifest.invalid"},
		{"núcleo viejo", signed(func(map[string][]byte) {}), "v0.1.9", "core.too_old"},
		{"editor oom sin firma", func() map[string][]byte { f := goodFiles(); return f }(), "dev", "editor.reserved"},
		{"comando de escritura", signed(func(f map[string][]byte) {
			setPB(f, strings.Replace(goodPlaybook, "show spanning-tree summary", "configure terminal", 1))
		}), "dev", "playbook.denied"},
		{"redirect en pipe", signed(func(f map[string][]byte) {
			setPB(f, strings.Replace(goodPlaybook, "show spanning-tree summary", "show run | redirect flash:x", 1))
		}), "dev", "playbook.denied"},
		{"playbook roto", signed(func(f map[string][]byte) { f["playbooks/stp.yaml"] = []byte("id: x\n") }), "dev", "playbook.invalid"},
		{"plataforma sin driver", signed(func(f map[string][]byte) {
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "[ios-xe]", "[ios-xe, nx-os]", 1))
			setPB(f, strings.Replace(goodPlaybook, "ios-xe", "nx-os", 1))
		}), "dev", "playbook.platform"},
		{"plataforma fuera de platforms", signed(func(f map[string][]byte) {
			f["manifest.yaml"] = []byte(strings.Replace(goodManifest, "[ios-xe]", "[ios]", 1))
		}), "dev", "playbook.platform"},
		{"script inválido", signed(func(f map[string][]byte) { f["scripts.json"] = []byte(`{"formato":"x"}`) }), "dev", "script.invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := Zip(c.files)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(data, c.core, keys)
			wantReason(t, err, c.reason)
		})
	}
}

func TestPrefijoDeTerceros(t *testing.T) {
	f := thirdParty()
	setPB(f, strings.Replace(goodPlaybook, "oom-stp", "stp", 1))
	_, err := Verify(mustZip(t, f), "dev", nil)
	wantReason(t, err, "id.prefix")

	f = thirdParty()
	f["scripts.json"] = []byte(scriptsJSON("lib-stp"))
	_, err = Verify(mustZip(t, f), "dev", nil)
	wantReason(t, err, "id.prefix")

	f["scripts.json"] = []byte(scriptsJSON("lib-acme-stp"))
	p, err := Verify(mustZip(t, f), "dev", nil)
	if err != nil || len(p.Scripts) != 1 {
		t.Fatal(err, p)
	}
}

func scriptsJSON(id string) string {
	return `{"formato":"macuahuitl-scripts","version":1,"exportado":"2026-11-12T00:00:00Z","scripts":[{"id":"` + id +
		`","name":"STP","tech":"l2","platform":"ios-xe","description":"","commands":["show spanning-tree"],"tags":[],"origin":"biblioteca","created_at":"2026-11-07T00:00:00Z","updated_at":"2026-11-07T00:00:00Z"}]}`
}

func TestScriptsConConfiguracionSePermiten(t *testing.T) {
	f := thirdParty()
	j := strings.Replace(scriptsJSON("lib-acme-cfg"), "show spanning-tree", "interface Gi1/0/1", 1)
	f["scripts.json"] = []byte(j)
	if _, err := Verify(mustZip(t, f), "dev", nil); err != nil {
		t.Fatal(err)
	}
}

// rawZip arma un zip a mano, sin pasar por Zip, para entradas que Zip no produce.
func rawZip(t *testing.T, entries ...func(*zip.Writer)) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range entries {
		e(w)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func put(name, body string) func(*zip.Writer) {
	return func(w *zip.Writer) {
		f, _ := w.Create(name)
		f.Write([]byte(body))
	}
}

func TestZipEntradasRaras(t *testing.T) {
	t.Run("directorio", func(t *testing.T) {
		_, err := Verify(rawZip(t, put("playbooks/", ""), put("manifest.yaml", goodManifest)), "dev", nil)
		wantReason(t, err, "zip.path")
	})
	t.Run("enlace", func(t *testing.T) {
		d := rawZip(t, func(w *zip.Writer) {
			h := &zip.FileHeader{Name: "README.md"}
			h.SetMode(0o777 | fs.ModeSymlink)
			f, _ := w.CreateHeader(h)
			f.Write([]byte("/etc/passwd"))
		})
		_, err := Verify(d, "dev", nil)
		wantReason(t, err, "zip.path")
	})
	t.Run("repetido", func(t *testing.T) {
		_, err := Verify(rawZip(t, put("README.md", "a"), put("README.md", "b")), "dev", nil)
		wantReason(t, err, "zip.dup")
	})
	t.Run("repetido que solo cambia en mayúsculas", func(t *testing.T) {
		_, err := Verify(rawZip(t, put("manifest.yaml", goodManifest), put("Manifest.yaml", "b")), "dev", nil)
		wantReason(t, err, "zip.dup")
	})
	t.Run("no es zip", func(t *testing.T) {
		_, err := Verify([]byte("hola"), "dev", nil)
		wantReason(t, err, "zip.invalid")
	})
	t.Run("demasiadas entradas", func(t *testing.T) {
		var es []func(*zip.Writer)
		for i := 0; i < MaxEntries+1; i++ {
			es = append(es, put("playbooks/a.yaml", ""))
		}
		_, err := Verify(rawZip(t, es...), "dev", nil)
		wantReason(t, err, "zip.too_big")
	})
	t.Run("bomba de compresión", func(t *testing.T) {
		// 25 MB de ceros comprimen a unos KB: la cabecera no dice nada del tope, lo que cuenta es lo que se lee.
		big := strings.Repeat("\x00", 25<<20)
		d := rawZip(t, put("manifest.yaml", goodManifest), put("README.md", "x"), put("playbooks/a.yaml", big))
		if len(d) > MaxArchive {
			t.Fatalf("el zip de la prueba pesa %d", len(d))
		}
		_, err := Verify(d, "dev", nil)
		wantReason(t, err, "zip.too_big")
	})
	t.Run("varios archivos que juntos pasan el tope", func(t *testing.T) {
		chunk := strings.Repeat("\x00", 900<<10) // cada uno cabe en su tope de 1 MB; 25 juntos pasan de 20 MB
		var es []func(*zip.Writer)
		for i := 0; i < 25; i++ {
			es = append(es, put("playbooks/p"+string(rune('a'+i))+".yaml", chunk))
		}
		_, err := Verify(rawZip(t, es...), "dev", nil)
		wantReason(t, err, "zip.too_big")
	})
	t.Run("archivo de más de 20 MB", func(t *testing.T) {
		_, err := Verify(make([]byte, MaxArchive+1), "dev", nil)
		wantReason(t, err, "zip.too_big")
	})
}

func TestZipDeterminista(t *testing.T) {
	a, b := mustZip(t, goodFiles()), mustZip(t, goodFiles())
	if !bytes.Equal(a, b) {
		t.Fatal("el zip no es determinista")
	}
}

func TestIndice(t *testing.T) {
	got := string(Index(map[string][]byte{"b": []byte("2"), "a": []byte("1"), "SIGNATURE": []byte("x")}))
	want := "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b  a\nd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35  b\n"
	if got != want {
		t.Fatalf("%q", got)
	}
}

func TestLlaveOficialCarga(t *testing.T) {
	if len(OfficialKeys()) != 1 || len(OfficialKeys()[0]) != ed25519.PublicKeySize {
		t.Fatal("oom.pub")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.0.0", "1.0.0", 0}, {"1.0.1", "1.0.0", 1}, {"1.2.0", "1.10.0", -1}, {"2.0.0", "1.99.99", 1}} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s %s: %d", c.a, c.b, got)
		}
	}
}

// C2: lo que un paquete instalado aporta a la biblioteca de scripts debe ser válido siempre; si no, rompería
// LibraryWith para siempre. Se rechaza al instalar.
func TestPlaybooksQueRomperianLaBiblioteca(t *testing.T) {
	pb := func(id, name string, cmds int) string {
		s := "id: " + id + "\nplatform: ios-xe\nname: " + name + "\nname_en: x\ncommands:\n"
		for i := 0; i < cmds; i++ {
			s += "  - cmd: show clock\n"
		}
		return s
	}
	cases := map[string]struct{ file, body string }{
		"punto":                   {"acme-x.y.yaml", pb("acme-x.y", "A · B", 1)},
		"guion bajo":              {"acme_x.yaml", pb("acme_x", "A · B", 1)},
		"mayúsculas":              {"stp.yaml", pb("Acme-x", "A · B", 1)},
		"espacio":                 {"stp.yaml", pb("\"acme x\"", "A · B", 1)},
		"id distinto del archivo": {"stp.yaml", pb("acme-otro", "A · B", 1)},
		"lib de más de 60":        {"acme-" + strings.Repeat("a", 56) + ".yaml", pb("acme-"+strings.Repeat("a", 56), "A · B", 1)},
		"nombre de más de 64":     {"acme-stp.yaml", pb("acme-stp", strings.Repeat("n", 65), 1)},
		"más de 200 comandos":     {"acme-stp.yaml", pb("acme-stp", "A · B", 201)},
	}
	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			f := thirdParty()
			setPB(f, c.body)
			f["playbooks/"+c.file] = []byte(c.body)
			if "playbooks/"+c.file != "playbooks/"+strings.Trim(strings.SplitN(strings.SplitN(c.body, "id: ", 2)[1], "\n", 2)[0], "\"")+".yaml" {
				delete(f, "playbooks/"+strings.Trim(strings.SplitN(strings.SplitN(c.body, "id: ", 2)[1], "\n", 2)[0], "\"")+".yaml")
			}
			_, err := Verify(mustZip(t, f), "dev", nil)
			wantReason(t, err, "playbook.invalid")
		})
	}
}

func TestScriptsDePaqueteOficialExigenBibliotecaYLib(t *testing.T) {
	pub, priv := testKey(t)
	f := goodFiles()
	f["scripts.json"] = []byte(strings.Replace(scriptsJSON("lib-oom-x"), `"origin":"biblioteca"`, `"origin":"usuario"`, 1))
	sign(f, priv)
	_, err := Verify(mustZip(t, f), "dev", []ed25519.PublicKey{pub})
	wantReason(t, err, "script.invalid")
}

func TestPlainRechazaFormato(t *testing.T) {
	if plain("a\u202eb", 10) || !plain("ab", 10) {
		t.Fatal("plain debe rechazar caracteres de formato (bidi)")
	}
}
