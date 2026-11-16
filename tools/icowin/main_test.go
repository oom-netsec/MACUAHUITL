package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"testing"
)

func pngOf(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, n, n))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Formato ICO con PNG dentro (Windows Vista+): cabecera de 6 bytes, una entrada de 16 por imagen y los PNG tal cual.
// En la entrada, 256 se escribe como 0.
func TestICO(t *testing.T) {
	a, b := pngOf(t, 16), pngOf(t, 256)
	ico, err := build([][]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	if le.Uint16(ico[0:]) != 0 || le.Uint16(ico[2:]) != 1 || le.Uint16(ico[4:]) != 2 {
		t.Fatalf("cabecera: % x", ico[:6])
	}
	off := uint32(6 + 16*2)
	for i, p := range [][]byte{a, b} {
		e := ico[6+16*i:]
		w := []byte{16, 0}[i]
		if e[0] != w || e[1] != w || le.Uint16(e[4:]) != 1 || le.Uint16(e[6:]) != 32 {
			t.Fatalf("entrada %d: % x", i, e[:16])
		}
		if le.Uint32(e[8:]) != uint32(len(p)) || le.Uint32(e[12:]) != off {
			t.Fatalf("entrada %d: tamaño %d o desplazamiento %d", i, le.Uint32(e[8:]), le.Uint32(e[12:]))
		}
		if !bytes.Equal(ico[off:off+uint32(len(p))], p) {
			t.Fatalf("entrada %d: el PNG no va tal cual", i)
		}
		off += uint32(len(p))
	}
	if int(off) != len(ico) {
		t.Fatalf("sobran bytes: %d de %d", off, len(ico))
	}
}

func TestICORechazaLoQueNoSirve(t *testing.T) {
	for name, in := range map[string][][]byte{
		"vacío":     nil,
		"no es PNG": {[]byte("hola")},
		"no cuadrado": {func() []byte {
			var b bytes.Buffer
			_ = png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 16, 32)))
			return b.Bytes()
		}()},
		"más de 256": {pngOf(t, 512)},
	} {
		if _, err := build(in); err == nil {
			t.Errorf("%s: quiero error", name)
		}
	}
}
