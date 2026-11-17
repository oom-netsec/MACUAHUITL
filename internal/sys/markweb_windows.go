package sys

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

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

// MarkOfTheWebIfSame marca path solo si sigue siendo el archivo want (os.SameFile): si la carpeta cambió por una
// junction, otro archivo recibiría la marca. Devuelve nil si no coincide o si el volumen no admite flujos
// (FAT/exFAT); cualquier otro fallo se devuelve para que quien llama lo deje en el log.
func MarkOfTheWebIfSame(path string, want os.FileInfo) error {
	li, err := os.Lstat(path)
	if err != nil || !os.SameFile(li, want) {
		return nil
	}
	err = MarkOfTheWeb(path)
	if errors.Is(err, windows.ERROR_INVALID_NAME) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	return err
}
