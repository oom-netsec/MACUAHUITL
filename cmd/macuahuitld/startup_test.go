package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
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
