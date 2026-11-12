package vault

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealRoundTripAndTamper(t *testing.T) {
	blob, err := Seal(pw("clave"), []byte("llave privada"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("llave privada")) {
		t.Fatal("texto en claro en el sobre")
	}
	got, err := Unseal(pw("clave"), blob)
	if err != nil || string(got) != "llave privada" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Unseal(pw("otra"), blob); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("contraseña incorrecta: %v", err)
	}
	for i := range blob {
		b := append([]byte(nil), blob...)
		b[i] ^= 0x01
		if _, err := Unseal(pw("clave"), b); err == nil {
			t.Fatalf("byte %d alterado aceptado", i)
		}
	}
	if _, err := Unseal(pw("clave"), blob[:20]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncado: %v", err)
	}
	hostile := append([]byte(nil), blob...)
	copy(hostile[4:8], []byte{0xff, 0xff, 0xff, 0xff}) // pide 4 TiB de memoria
	if _, err := Unseal(pw("clave"), hostile); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("parámetros hostiles: %v", err)
	}
	if _, err := Seal(nil, []byte("x"), testParams); !errors.Is(err, ErrEmptyPassword) {
		t.Fatal("contraseña vacía aceptada")
	}
}

// Revisión: un sobre pegado no puede pedir más memoria/hilos de Argon2id que el tope de MCK1.
func TestUnsealCapsArgon2ForPastedEnvelopes(t *testing.T) {
	old := SealMaxMemoryKiB
	SealMaxMemoryKiB = 16384
	t.Cleanup(func() { SealMaxMemoryKiB = old })
	for name, p := range map[string]Params{
		"memoria": {MemoryKiB: 32768, Iterations: 1, Threads: 1},
		"hilos":   {MemoryKiB: 8192, Iterations: 1, Threads: 16},
	} {
		blob, err := Seal(pw("clave"), []byte("x"), p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Unseal(pw("clave"), blob); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
