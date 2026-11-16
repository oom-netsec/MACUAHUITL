package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// macuahuitld.startup: sí con cualquier fallo, salvo que ya corra un núcleo del mismo usuario; con el canal de otro usuario sí.
func TestStartupWanted(t *testing.T) {
	otro := i18n.Wrap("ipc.err.pipe_other_user", ipc.ErrAlreadyRunning, nil)
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"ya corre uno propio", ipc.ErrAlreadyRunning, false},
		{"ya corre uno propio, con detalle", fmt.Errorf("%w (detalle)", ipc.ErrAlreadyRunning), false},
		{"canal de otro usuario", otro, true},
		{"canal de otro usuario envuelto", fmt.Errorf("x: %w", otro), true},
		{"harden", consoleErr{i18n.New("harden.err.lockquota", i18n.A("cause", "x"))}, true},
		{"error común", errors.New("x"), true},
		{"sin error", nil, false},
	} {
		if got := startupWanted(c.err); got != c.want {
			t.Errorf("%s: %v, quería %v", c.name, got, c.want)
		}
	}
}

// El error de run conserva el código del catálogo aunque se escriba en el idioma de la consola.
func TestConsoleErrConservaElCodigo(t *testing.T) {
	var ie *i18n.Error
	if !errors.As(consoleErr{i18n.New("harden.err.root", nil)}, &ie) || ie.Code != "harden.err.root" {
		t.Fatal("consoleErr perdió el código")
	}
}

// Con un núcleo sano del mismo usuario corriendo no se escribe la causa (sería una causa vieja y falsa); sin núcleo, sí.
func TestWriteStartupSegunElNucleo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	file := func(d string) string { return filepath.Join(d, sys.StartupName) }
	for _, c := range []struct {
		name  string
		probe func() (bool, error)
		want  bool
	}{
		{"corre un núcleo", func() (bool, error) { return true, nil }, false},
		{"no corre", func() (bool, error) { return false, nil }, true},
		{"la sonda falla", func() (bool, error) { return false, errors.New("x") }, true},
	} {
		d := t.TempDir()
		writeStartup(d, errors.New("boom"), c.probe)
		if _, err := os.Stat(file(d)); (err == nil) != c.want {
			t.Errorf("%s: escrito=%v, quería %v", c.name, err == nil, c.want)
		}
	}
	d := t.TempDir() // ErrAlreadyRunning propio: no se escribe aunque la sonda diga que no hay núcleo
	writeStartup(d, ipc.ErrAlreadyRunning, func() (bool, error) { return false, nil })
	if _, err := os.Stat(file(d)); err == nil {
		t.Error("escribió con ErrAlreadyRunning")
	}
}
