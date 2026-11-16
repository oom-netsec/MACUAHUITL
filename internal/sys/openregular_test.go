package sys

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "a")
	os.WriteFile(reg, []byte("x"), 0o600)
	f, err := OpenRegular(reg)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := OpenRegular(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directorio: %v", err)
	}
	if _, err := OpenRegular(filepath.Join(dir, "no")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inexistente: %v", err)
	}
}

func TestOpenInRoot(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := OpenNewIn(root, "nuevo")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("hola"))
	f.Close()
	if _, err := OpenNewIn(root, "nuevo"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("sobrescribió: %v", err)
	}
	if _, err := OpenNewIn(root, "../fuera"); err == nil {
		t.Fatal("salió de la carpeta")
	}
	g, err := OpenRegularIn(root, "nuevo")
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	if _, err := OpenRegularIn(root, "."); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directorio: %v", err)
	}
}

// Un enlace simbólico (aunque apunte a nada) en la ruta hace fallar OpenNew y OpenNewIn, y el destino no se crea.
func TestOpenNewNoSigueEnlaces(t *testing.T) {
	dir := t.TempDir()
	destino := filepath.Join(dir, "destino")
	if err := os.Symlink(destino, filepath.Join(dir, "enlace")); err != nil {
		t.Skip("sin privilegio para crear enlaces simbólicos:", err)
	}
	if _, err := OpenNew(filepath.Join(dir, "enlace")); err == nil {
		t.Fatal("OpenNew siguió el enlace")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := OpenNewIn(root, "enlace"); err == nil {
		t.Fatal("OpenNewIn siguió el enlace")
	}
	if _, err := os.Lstat(destino); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("el destino se creó a través del enlace: %v", err)
	}
}

func TestHardLinkedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a")
	os.WriteFile(p, []byte("x"), 0o600)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if hl, err := HardLinkedFile(f); err != nil || hl {
		t.Fatalf("un solo nombre: %v, %v", hl, err)
	}
	if err := os.Link(p, filepath.Join(dir, "b")); err != nil {
		t.Skip(err)
	}
	if hl, err := HardLinkedFile(f); err != nil || !hl {
		t.Fatalf("dos nombres: %v, %v", hl, err)
	}
	f.Close()
	if _, err := HardLinkedFile(f); err == nil {
		t.Fatal("un archivo cerrado debe dar error (y quien llama rechaza)")
	}
}

func TestRenameNoReplaceIn(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	os.WriteFile(filepath.Join(dir, "a"), []byte("A"), 0o600)
	os.WriteFile(filepath.Join(dir, "b"), []byte("B"), 0o600)
	if err := RenameNoReplaceIn(root, "a", "b"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("sobre un existente: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "b")); string(got) != "B" {
		t.Fatalf("pisó el destino: %q", got)
	}
	if err := RenameNoReplaceIn(root, "a", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "c")); err != nil {
		t.Fatal(err)
	}
}

// El error simulado de «sin renombrado atómico» se reconoce como tal.
func TestNoAtomicRename(t *testing.T) {
	if !NoAtomicRename(ErrNoAtomicRename) || !NoAtomicRename(&os.LinkError{Err: ErrNoAtomicRename}) {
		t.Fatal("ErrNoAtomicRename no se reconoce")
	}
	if NoAtomicRename(fs.ErrExist) {
		t.Fatal("ErrExist no es falta de renombrado atómico")
	}
}

// Fase 30d: ErrNotRegular lleva código; el texto en español es el de siempre y con en sale en inglés.
func TestErrNotRegularEsYEn(t *testing.T) {
	if ErrNotRegular.Error() != "la ruta no es un archivo regular" {
		t.Errorf("es: %q", ErrNotRegular.Error())
	}
	if en := i18n.In("en", fmt.Errorf("abrir: %w", ErrNotRegular)); en != "abrir: the path is not a regular file" {
		t.Errorf("en: %q", en)
	}
}
