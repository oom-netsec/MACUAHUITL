package sys

import "os"

// SyncDir hace fsync de una carpeta para que un rename o un archivo nuevo sobrevivan a una caída.
func SyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
