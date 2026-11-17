package devices

import "strings"

// CleanFolder valida el nombre de una carpeta de hosts (las mismas reglas que Host.Folder, pero obligatorio).
func CleanFolder(name string) (string, error) {
	if !folderRe.MatchString(name) || name != strings.TrimSpace(name) {
		return "", fe("folder", "hostfield.folder")
	}
	return name, nil
}
