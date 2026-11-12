package patrol

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// zipFiles crea <dir>/<name>.zip con los archivos dados (rutas relativas a dir).
// Solo archivos regulares: un symlink no se sigue. Con deleteLoose borra los
// archivos empaquetados salvo manifest.json y las carpetas que queden vacías.
func zipFiles(dir, name string, files []string, deleteLoose bool) (string, error) {
	out := filepath.Join(dir, name+".zip")
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("patrol: zip: %w", err)
	}
	zw := zip.NewWriter(f)
	add := func(rel string) error {
		p := filepath.Join(dir, rel)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s no es un archivo regular", rel)
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		h, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		h.Name, h.Method = filepath.ToSlash(rel), zip.Deflate
		dst, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = io.Copy(dst, src)
		return err
	}
	for _, rel := range files {
		if err := add(rel); err != nil {
			zw.Close()
			f.Close()
			os.Remove(out)
			return "", fmt.Errorf("patrol: zip: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return "", fmt.Errorf("patrol: zip: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", fmt.Errorf("patrol: zip: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("patrol: zip: %w", err)
	}
	if deleteLoose {
		for _, rel := range files {
			if rel != "manifest.json" {
				os.Remove(filepath.Join(dir, rel))
				os.Remove(filepath.Dir(filepath.Join(dir, rel))) // solo si quedó vacía
			}
		}
	}
	return out, nil
}

// FinalZip es la ruta del zip que escribe Finish según la política; vacía con ZipNone.
func FinalZip(w *Writer, s Spec) string {
	switch s.Zip {
	case ZipAtEnd:
		return filepath.Join(w.dir, filepath.Base(w.dir)+".zip")
	case ZipPerRound:
		return filepath.Join(w.dir, filepath.Base(w.dir)+"_final.zip")
	}
	return ""
}
