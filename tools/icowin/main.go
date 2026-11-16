// Command icowin arma el ícono .ico del instalador de Windows con los PNG del ícono (deploy/packaging/icons), sin
// herramientas externas. Uso: go run ./tools/icowin salida.ico 16.png 24.png … 256.png
//
// Formato ICO con las imágenes en PNG (Windows Vista y posteriores): cabecera ICONDIR, una ICONDIRENTRY por imagen y
// los PNG tal cual, en el orden recibido.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"os"
)

func build(pngs [][]byte) ([]byte, error) {
	if len(pngs) == 0 {
		return nil, errors.New("icowin: sin imágenes")
	}
	var head, body bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&head, le, [3]uint16{0, 1, uint16(len(pngs))}) // reservado, tipo 1 = ícono, cantidad
	off := 6 + 16*len(pngs)
	for i, p := range pngs {
		cfg, err := png.DecodeConfig(bytes.NewReader(p))
		if err != nil {
			return nil, fmt.Errorf("icowin: imagen %d: %w", i+1, err)
		}
		if cfg.Width != cfg.Height || cfg.Width < 1 || cfg.Width > 256 {
			return nil, fmt.Errorf("icowin: imagen %d: %dx%d (debe ser cuadrada, de 1 a 256)", i+1, cfg.Width, cfg.Height)
		}
		side := byte(cfg.Width % 256) // 256 se escribe como 0
		head.Write([]byte{side, side, 0, 0})
		_ = binary.Write(&head, le, [2]uint16{1, 32}) // planos, bits por píxel
		_ = binary.Write(&head, le, [2]uint32{uint32(len(p)), uint32(off)})
		body.Write(p)
		off += len(p)
	}
	return append(head.Bytes(), body.Bytes()...), nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "uso: icowin salida.ico imagen.png…")
		os.Exit(2)
	}
	var pngs [][]byte
	for _, f := range os.Args[2:] {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pngs = append(pngs, b)
	}
	ico, err := build(pngs)
	if err == nil {
		err = os.WriteFile(os.Args[1], ico, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
