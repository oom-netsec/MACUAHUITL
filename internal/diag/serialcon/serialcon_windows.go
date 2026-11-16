package serialcon

import (
	"errors"
	"fmt"
	"os"
)

// La consola serie de Windows (puertos COM) llega en una fase propia: aquí solo lo que hace falta para compilar. Las
// tablas llevan las mismas claves que en Unix para que validate acepte lo mismo.
var bauds = map[int]uint32{1200: 0, 2400: 0, 4800: 0, 9600: 0, 19200: 0, 38400: 0, 57600: 0, 115200: 0, 230400: 0, 460800: 0, 921600: 0}

var csize = map[int]uint32{5: 0, 6: 0, 7: 0, 8: 0}

func open(Config) (*Port, error) { return nil, fmt.Errorf("serialcon: %w", errors.ErrUnsupported) }

// Break no se puede sin un puerto abierto, y open nunca lo da en Windows.
func (p *Port) Break() error { return fmt.Errorf("serialcon: BREAK: %w", errors.ErrUnsupported) }

// List no encuentra adaptadores: la enumeración de COM llega con la fase de la consola serie.
func List() []string { return nil }

func Pty() (*os.File, string, error) {
	return nil, "", fmt.Errorf("serialcon: %w", errors.ErrUnsupported)
}
