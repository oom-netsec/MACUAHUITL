package sys

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMkfifoNoSoportadoEnWindows(t *testing.T) {
	if err := Mkfifo(filepath.Join(t.TempDir(), "tubo")); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Mkfifo: %v", err)
	}
}

// Sin verificación por SID todavía (43a3): Owner falla cerrado.
func TestOwnerFallaCerradoEnWindows(t *testing.T) {
	fi, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := Owner(fi); ok || uid != 0 {
		t.Fatalf("Owner = %d, %v", uid, ok)
	}
}

// HardLinked por FileInfo no ve la cuenta de enlaces en Windows: decide HardLinkedFile.
func TestHardLinkedPorFileInfoEsFiltroEnWindows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a")
	os.WriteFile(p, []byte("x"), 0o600)
	if err := os.Link(p, filepath.Join(dir, "b")); err != nil {
		t.Skip(err)
	}
	fi, _ := os.Stat(p)
	if HardLinked(fi) {
		t.Fatal("HardLinked(fi) debe devolver false en Windows")
	}
}

// En Windows RenameNoReplaceIn arma rutas absolutas: un nombre que salga de la carpeta se rechaza.
func TestRenameNoReplaceInNoSaleDeLaCarpeta(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	os.WriteFile(filepath.Join(dir, "a"), []byte("A"), 0o600)
	for _, dst := range []string{"../x", `..\x`, `C:\x`} {
		if err := RenameNoReplaceIn(root, "a", dst); err == nil {
			t.Fatalf("%q: salió de la carpeta", dst)
		}
	}
}

// UNC y rutas de dispositivo se rechazan antes de abrir nada (SMB saldría a la red y filtraría el hash NTLM).
func TestRutasUNCYDispositivoRechazadas(t *testing.T) {
	for _, p := range []string{`\\host\share\f`, `//host/share/f`, `\\?\C:\Windows\win.ini`, `\\.\pipe\x`, `\\.\COM1`} {
		if _, err := OpenRegular(p); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("OpenRegular(%q): %v", p, err)
		}
		if _, err := OpenNew(p); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("OpenNew(%q): %v", p, err)
		}
	}
}

// Un junction en la ruta hace fallar OpenNew y el destino no se crea.
func TestOpenNewNoSigueJunction(t *testing.T) {
	dir, fuera := t.TempDir(), t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(dir, "j"), fuera).CombinedOutput(); err != nil {
		t.Skip("sin mklink /J:", err, string(out))
	}
	if _, err := OpenNew(filepath.Join(dir, "j")); err == nil {
		t.Fatal("OpenNew abrió sobre un junction")
	}
	if ents, _ := os.ReadDir(fuera); len(ents) != 0 {
		t.Fatalf("se creó algo a través del junction: %v", ents)
	}
}

// «sub\x», con sub un junction, saldría de la carpeta: se rechaza todo nombre con separadores.
func TestRenameNoReplaceInRechazaSubcarpetas(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	os.WriteFile(filepath.Join(dir, "a"), []byte("A"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	if err := RenameNoReplaceIn(root, "a", `sub\x`); err == nil {
		t.Fatal(`aceptó sub\x`)
	}
	if err := RenameNoReplaceIn(root, `sub\x`, "a"); err == nil {
		t.Fatal(`aceptó sub\x como origen`)
	}
}
