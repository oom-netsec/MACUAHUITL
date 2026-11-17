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

// IsRemoteDrive dice si la unidad de path (X:) es una unidad de red mapeada (DRIVE_REMOTE): su ACL no es la de este equipo.
func IsRemoteDrive(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	p, err := windows.UTF16PtrFromString(path[:2] + `\`)
	return err == nil && windows.GetDriveType(p) == windows.DRIVE_REMOTE
}
