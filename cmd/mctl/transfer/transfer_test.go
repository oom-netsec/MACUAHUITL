package transfer

import (
	"os"
	"path/filepath"
	"testing"
)

// --files con --from se resuelve dentro de --from, no contra el cwd; lo absoluto o lo que sale de --from se rechaza.
func TestFilesRelativosAFrom(t *testing.T) {
	from, otro := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(from, "img.bin"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(from, "sub"), 0o700)
	os.WriteFile(filepath.Join(from, "sub", "b.bin"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(otro, "fuera.bin"), []byte("x"), 0o600)
	os.Symlink(filepath.Join(otro, "fuera.bin"), filepath.Join(from, "enlace.bin"))
	t.Chdir(otro) // el cwd no debe influir

	got, err := resolveFiles([]string{" img.bin", "sub/b.bin", ""}, from)
	if err != nil || len(got) != 2 || got[0] != filepath.Join(from, "img.bin") || got[1] != filepath.Join(from, "sub", "b.bin") {
		t.Fatalf("got = %v err = %v", got, err)
	}
	// una ruta absoluta convive con --from (fileserve publica ambos), como antes
	if got, err := resolveFiles([]string{filepath.Join(otro, "fuera.bin"), "img.bin"}, from); err != nil || got[0] != filepath.Join(otro, "fuera.bin") || got[1] != filepath.Join(from, "img.bin") {
		t.Fatalf("absoluta con from: %v %v", got, err)
	}
	// sin --files no se abre --from (la validación clara de la carpeta la hace el servidor)
	if got, err := resolveFiles(nil, filepath.Join(otro, "no-existe")); err != nil || len(got) != 0 {
		t.Fatalf("sin files: %v %v", got, err)
	}
	for _, mala := range []string{"../" + filepath.Base(otro) + "/fuera.bin", "..", "enlace.bin"} {
		if _, err := resolveFiles([]string{mala}, from); err == nil {
			t.Errorf("%q debía rechazarse", mala)
		}
	}
	// sin --from sigue siendo relativo al cwd
	if got, err = resolveFiles([]string{"fuera.bin"}, ""); err != nil || got[0] != filepath.Join(otro, "fuera.bin") {
		t.Fatalf("sin from: %v %v", got, err)
	}
}
