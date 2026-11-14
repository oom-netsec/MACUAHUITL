package patrol

import (
	"archive/zip"
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"io"
	"os"
	"path/filepath"
)

// zipFiles crea <dir>/<name>.zip con los archivos dados (rutas relativas a dir).
// Solo archivos regulares: un symlink no se sigue. Con deleteLoose borra los
// archivos empaquetados salvo manifest.json y las carpetas que queden vacías.
func zipFiles(w *Writer, name string, files []string, deleteLoose bool) (string, error) {
	dir := w.dir
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
			return i18n.New("patrol.err.zip_not_regular", i18n.A("file", rel))
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
		// Write hace MkdirAll y abre el archivo bajo w.mu: sin él, la carpeta de un equipo podría borrarse entre ambos pasos.
		w.mu.Lock()
		defer w.mu.Unlock()
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
