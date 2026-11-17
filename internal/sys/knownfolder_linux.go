package sys

// DocumentsDir: solo existe en Windows (FOLDERID_Documents); en Linux es vacía.
func DocumentsDir() string { return "" }
