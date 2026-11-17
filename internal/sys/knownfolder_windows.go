package sys

import "golang.org/x/sys/windows"

// DocumentsDir es la carpeta Documentos del usuario según el shell (FOLDERID_Documents): sigue la carpeta localizada
// («Documentos») y la movida a otra unidad o a OneDrive. Vacía si no se pudo leer.
func DocumentsDir() string {
	p, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return ""
	}
	return p
}
