package sys

import "os"

// MarkOfTheWeb marca path como bajado de la red (flujo alterno Zone.Identifier, ZoneId=3, zona Internet) para
// que SmartScreen y Office lo traten con cautela. path es SIEMPRE la ruta interna del archivo ya recibido, nunca
// un nombre del par (los nombres con ':' se rechazan antes). Falla sin pérdida: en FAT/exFAT no hay flujos y el
// llamador solo avisa; el archivo ya está bien guardado.
func MarkOfTheWeb(path string) error {
	f, err := os.OpenFile(path+":Zone.Identifier", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString("[ZoneTransfer]\r\nZoneId=3\r\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
