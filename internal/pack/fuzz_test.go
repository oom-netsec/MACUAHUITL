package pack

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fuzzKey es una llave fija de pruebas (nunca la oficial).
func fuzzKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

func fuzzZip(f map[string][]byte) []byte {
	b, _ := Zip(f) // un nombre que Zip no acepta da nil: Verify lo rechaza
	return b
}

// tree lista cada ruta bajo root.
func tree(root string) []string {
	var l []string
	filepath.WalkDir(root, func(p string, _ os.DirEntry, _ error) error { l = append(l, p); return nil })
	slices.Sort(l)
	return l
}

// FuzzVerify: bytes arbitrarios como zip. Sin pánico; un paquete aceptado sin firma nunca es «oficial» ni del
// editor oom; y si se importa, solo se escribe dentro de su carpeta.
func FuzzVerify(f *testing.F) {
	pub, priv := fuzzKey()
	signed := goodFiles()
	sign(signed, priv)
	f.Add(fuzzZip(signed))
	f.Add(fuzzZip(thirdParty()))
	f.Add(fuzzZip(goodFiles()))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Verify(data, "v0.3.0", []ed25519.PublicKey{pub})
		if err != nil {
			return
		}
		if !p.Official && p.Editor() == "oom" {
			t.Fatal("SEGURIDAD: paquete oom sin firma aceptado")
		}
		files, _ := unzip(data)
		if p.Official {
			sig, ok := files[fileSig]
			if !ok || !validSig(pub, files, sig) {
				t.Fatal("SEGURIDAD: paquete oficial sin firma válida")
			}
			return
		}
		outer := t.TempDir() // el padre de root: ahí se ve un escape de varios niveles
		root := filepath.Join(outer, "root")
		dir := filepath.Join(root, "work", "playbooks")
		s, _, err := Open(filepath.Join(root, "store"), "v0.3.0", []ed25519.PublicKey{pub}, Base{})
		if err != nil {
			t.Fatal(err)
		}
		before := tree(outer)
		if r, err := s.StagePlaybooks(p, dir, nil, nil); err == nil {
			_ = r.Publish(dir)
		}
		for _, n := range tree(outer) {
			if !slices.Contains(before, n) && !isUnder(n, dir) {
				t.Fatalf("escribió fuera de su carpeta: %s", n)
			}
		}
	})
}

// isUnder: p es dir, está dentro o es una carpeta que lo contiene (MkdirAll crea los padres).
func isUnder(p, dir string) bool {
	sep := string(filepath.Separator)
	return p == dir || strings.HasPrefix(p, dir+sep) || strings.HasPrefix(dir, p+sep)
}

func validSig(pub ed25519.PublicKey, files map[string][]byte, sig []byte) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	return err == nil && ed25519.Verify(pub, Index(files), raw)
}

// FuzzVerifyMutado: un paquete oficial válido con un cambio en un archivo (sin volver a firmar) o un archivo
// añadido: si el contenido firmado cambió, Verify no puede darlo por oficial.
func FuzzVerifyMutado(f *testing.F) {
	f.Add(uint8(0), uint32(3), byte(1), "", []byte(nil))
	f.Add(uint8(1), uint32(0), byte(0xff), "", []byte(nil))
	f.Add(uint8(0), uint32(0), byte(0), "playbooks/extra.yaml", []byte("id: x\n"))
	f.Add(uint8(2), uint32(10), byte(0x20), "../x", []byte("x"))
	pub, priv := fuzzKey()
	f.Fuzz(func(t *testing.T, which uint8, pos uint32, x byte, extra string, extraData []byte) {
		orig := goodFiles()
		sign(orig, priv)
		want := Index(orig)
		files := map[string][]byte{}
		for n, b := range orig {
			files[n] = slices.Clone(b)
		}
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		slices.Sort(names)
		n := names[int(which)%len(names)]
		if b := files[n]; len(b) > 0 {
			b[int(pos)%len(b)] ^= x
		}
		if extra != "" {
			files[extra] = extraData
		}
		p, err := Verify(fuzzZip(files), "v0.3.0", []ed25519.PublicKey{pub})
		if err != nil {
			return
		}
		if p.Official && !bytes.Equal(Index(files), want) {
			t.Fatal("SEGURIDAD: contenido modificado aceptado como oficial")
		}
	})
}
