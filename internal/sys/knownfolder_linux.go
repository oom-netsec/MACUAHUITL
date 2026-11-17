package sys

// DocumentsDir: solo existe en Windows (FOLDERID_Documents); en Linux es vacía.
func DocumentsDir() string { return "" }

// IsRemoteDrive: las unidades mapeadas son de Windows; en Linux siempre false.
func IsRemoteDrive(string) bool { return false }
