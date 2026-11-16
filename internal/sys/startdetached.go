package sys

// StartDetached lanza el núcleo exe (ruta absoluta, junto a macuahuitl.exe) separado de quien lo llama y vuelve sin
// esperar a que arranque (ADR 0012 g). Solo Windows: en Linux lo arranca systemd --user y devuelve errors.ErrUnsupported
// sin lanzar nada. El error es el de Start (por ejemplo, el exe no existe): el llamador lo registra.
func StartDetached(exe string) error {
	if err := requireAbs(exe); err != nil {
		return err
	}
	return startDetached(exe)
}
