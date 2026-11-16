package main

import (
	"strings"
	"testing"
)

// En Windows, mctl en una terminal elevada no puede hablar con el núcleo (corre en Medium): sale con un mensaje claro
// antes de marcar el pipe. La ayuda y -h siguen funcionando.
func TestMctlElevadoNoMarcaElCanal(t *testing.T) {
	defer func(f func() bool) { elevatedBlocked = f }(elevatedBlocked)
	elevatedBlocked = func() bool { return true }
	t.Setenv("XDG_RUNTIME_DIR", "") // sin esto, un Dial real fallaría con otro mensaje: el mensaje elevado prueba que no hubo Dial

	_, err := mctlRaw(t, "", "core", "stop")
	if err == nil || !strings.Contains(err.Error(), "elevated terminal") {
		t.Fatalf("err = %v", err)
	}
	_, err = mctlRaw(t, "", "--lang", "es", "core", "stop")
	if err == nil || !strings.Contains(err.Error(), "terminal elevada") {
		t.Fatalf("es: err = %v", err)
	}
	if out, err := mctlRaw(t, "", "--help"); err != nil || out == "" {
		t.Fatalf("ayuda: %v", err)
	}
	if _, err := mctlRaw(t, "", "--version"); err != nil {
		t.Fatalf("versión: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if _, err := mctlRaw(t, "", "core", "stop", "-h"); err != nil && strings.Contains(err.Error(), "elevated") {
		t.Fatalf("-h no debe pedir el núcleo: %v", err)
	}

	elevatedBlocked = func() bool { return false }
	if _, err := mctlRaw(t, "", "core", "stop"); err != nil && strings.Contains(err.Error(), "elevated") {
		t.Fatalf("sin elevar no debe salir el mensaje: %v", err)
	}
}
