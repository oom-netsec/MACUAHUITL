package sys

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// RedirectStderr manda stderr y stdout al registro path (ADR 0012 g): el núcleo es un binario -H windowsgui, sin consola.
// Cambia también el handle estándar, para que un pánico del runtime de Go caiga en el archivo. Crea la carpeta privada
// si falta y rota el registro con OpenLog.
func RedirectStderr(path string) error {
	if err := MkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := OpenLog(path, LogMax)
	if err != nil {
		return err
	}
	h := windows.Handle(f.Fd())
	if err := windows.SetStdHandle(windows.STD_ERROR_HANDLE, h); err != nil {
		f.Close()
		return err
	}
	windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, h)
	os.Stderr, os.Stdout = f, f
	return nil
}
