package sys

import (
	"fmt"
	"io/fs"
	"os"
)

// StartDetached lanza el núcleo exe (ruta absoluta, junto a macuahuitl.exe) separado de quien lo llama y vuelve sin
// esperar a que arranque (ADR 0012 g). Solo Windows: en Linux lo arranca systemd --user y devuelve errors.ErrUnsupported
// sin lanzar nada. Rechaza rutas UNC y de dispositivo y lo que no sea un archivo regular (así la búsqueda de extensiones
// de Windows no lanza un .bat vecino). El error es el de Start (por ejemplo, el exe no existe): el llamador lo registra.
func StartDetached(exe string) error {
	if err := requireAbs(exe); err != nil {
		return err
	}
	if err := checkPath(exe); err != nil {
		return err
	}
	if fi, err := os.Lstat(exe); err != nil {
		return err
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w (no es un archivo regular)", exe, fs.ErrInvalid)
	}
	return startDetached(exe)
}
