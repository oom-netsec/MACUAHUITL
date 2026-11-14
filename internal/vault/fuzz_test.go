package vault

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// FuzzOpenBackup abre un respaldo válido mutado (o bytes arbitrarios): sin pánico, sin escribir nada y, si lo
// abre, solo con credenciales idénticas a las del original (el formato es autenticado).
func FuzzOpenBackup(f *testing.F) {
	root := f.TempDir()
	src, err := Create(filepath.Join(root, "vault.mcv"), pw("maestra"), testParams)
	if err != nil {
		f.Fatal(err)
	}
	want := map[string]string{}
	for _, c := range []Credential{cred("core", "PW-CORE", "EN-CORE"), cred("borde", "PW-BORDE", "")} {
		if _, err := src.Put(c); err != nil {
			f.Fatal(err)
		}
		want[c.Label] = c.Username + "\x00" + string(c.Password.Bytes())
	}
	good := filepath.Join(root, "good.mcvault")
	if _, err := WriteBackup(src, good, pw(frase), false); err != nil {
		f.Fatal(err)
	}
	orig, _ := os.ReadFile(good)
	f.Add(uint32(0), byte(1), uint16(0), []byte(nil))
	f.Add(uint32(40), byte(0xff), uint16(0), []byte(nil))
	f.Add(uint32(0), byte(0), uint16(20), []byte(nil))
	f.Add(uint32(0), byte(0), uint16(0), []byte("no es un respaldo"))
	f.Fuzz(func(t *testing.T, pos uint32, x byte, cut uint16, raw []byte) {
		data := raw
		if len(raw) == 0 { // el motor entrega []byte{} en lugar de nil: este es el camino del respaldo válido mutado
			data = slices.Clone(orig)
			data[int(pos)%len(data)] ^= x
			data = data[:len(data)-min(int(cut), len(data))]
		}
		dir := t.TempDir()
		p := filepath.Join(dir, "r.mcvault")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := OpenBackup(p, pw(frase))
		if es, _ := os.ReadDir(dir); len(es) != 1 {
			t.Fatalf("OpenBackup escribió junto al respaldo: %d entradas", len(es))
		}
		if err != nil {
			return
		}
		defer b.LockAll()
		infos, err := b.ListAll()
		if err != nil {
			return
		}
		for _, i := range infos {
			c, err := b.Get(i.ID)
			if err != nil {
				continue
			}
			if w, ok := want[i.Label]; !ok || w != c.Username+"\x00"+string(c.Password.Bytes()) {
				t.Fatalf("SEGURIDAD: un respaldo alterado abrió con una credencial que no estaba: %q", i.Label)
			}
		}
	})
}
