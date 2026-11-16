package sys_test

import (
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/internal/sys/systest"
)

// En Windows el registro nace con la DACL protegida (OpenNewPrivate), no con la ACL heredada de la carpeta.
func TestOpenLogNacePrivadoEnWindows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "macuahuitld.log")
	f, err := sys.OpenLog(p, sys.LogMax)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	systest.Private(t, p, 0o600)
}

// Sin consola (el runner de CI redirige stdout) ConsoleUTF8 no falla ni cambia nada.
func TestConsoleUTF8SinConsola(t *testing.T) {
	sys.ConsoleUTF8()
	sys.ConsoleUTF8() // idempotente
}
