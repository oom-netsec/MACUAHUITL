package sys

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

var redirected bool

// LogFailure agrega msg al registro path cuando el núcleo falló antes de RedirectStderr (sin consola no habría dónde
// leerlo). Mejor esfuerzo y sin rotar; si ya se redirigió, stderr es el registro y no hace nada.
func LogFailure(path, msg string) {
	if redirected {
		return
	}
	if MkdirPrivate(filepath.Dir(path)) == nil {
		appendLog(path, msg)
	}
}

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
	redirected = true
	return nil
}

// cpUTF8 es CP_UTF8.
const cpUTF8 = 65001

// ConsoleUTF8 pone la página de códigos de salida de la consola en UTF-8 (CP_UTF8): con la cp437 de siempre los acentos
// salen rotos. Solo si stdout es una consola (GetConsoleMode); con -H windowsgui o con la salida redirigida no hay consola
// que cambiar y no hace nada. Mejor esfuerzo: un fallo se ignora.
func ConsoleUTF8() {
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) != nil {
		return
	}
	windows.SetConsoleOutputCP(cpUTF8)
}
