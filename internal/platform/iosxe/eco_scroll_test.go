package iosxe

import (
	"strings"
	"testing"
)

// Un comando largo con scroll horizontal se ve como «$» + su final: es su eco, no un desfase. Un resto corto de otra
// salida que coincide con el final del comando no cuenta como eco.
func TestEchoFirstAceptaScrollPeroNoRestosCortos(t *testing.T) {
	cmd := "show running-config | include " + strings.Repeat("abcdefghij", 18) + "fin-unico"
	scroll := "$" + cmd[len(cmd)-150:] + "\nsalida\n"
	if !echoFirst(scroll, cmd) {
		t.Fatal("el eco con scroll «$» debe contar como eco")
	}
	if echoFirst("unico\nsalida\n", cmd) {
		t.Fatal("un resto corto que coincide con el final no es eco")
	}
	if echoFirst("resto de otra salida\n", cmd) {
		t.Fatal("una línea ajena no es eco")
	}
}
