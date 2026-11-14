package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Un error que trae texto de un paquete o de un equipo no puede escribir secuencias de terminal en stderr.
func TestErrorDeMctlSinSecuenciasDeTerminal(t *testing.T) {
	var b bytes.Buffer
	printErr(&b, errors.New("pack: field \x1b]52;c;cHduZWQ=\x07 not found \x1b[2J\x9b"))
	if s := b.String(); strings.ContainsAny(s, "\x1b\x07\u009b") || !strings.HasPrefix(s, "mctl: pack: field") {
		t.Fatalf("%q", s)
	}
}
