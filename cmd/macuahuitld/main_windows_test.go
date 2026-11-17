package main

import (
	"os"
	"testing"
)

// El runner de CI de Windows corre elevado, y run se niega a arrancar elevado (ADR 0012): las pruebas de run fijan «no elevado».
func TestMain(m *testing.M) {
	privileged = func() bool { return false }
	os.Exit(m.Run())
}
