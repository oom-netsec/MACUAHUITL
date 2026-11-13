package pack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Topes del ADR 0010. Se miden con los bytes que de verdad se leen, no con las cabeceras del zip.
const (
	MaxArchive   = 20 << 20
	MaxEntries   = 2000
	MaxReadme    = 64 << 10
	maxManifest  = 64 << 10
	maxScripts   = 5 << 20
	maxPlaybook  = 1 << 20
	fileManifest = "manifest.yaml"
	fileReadme   = "README.md"
	fileScripts  = "scripts.json"
	fileSig      = "SIGNATURE"
	filePlay     = "playbooks/"
)

var playName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// allowedPath dice si name es una de las rutas del formato (lista cerrada: cubre «..», «\», rutas absolutas,
// Unicode que imita «/» y subcarpetas).
func allowedPath(name string) bool {
	switch name {
	case fileManifest, fileReadme, fileScripts, fileSig:
		return true
	}
	if rest, ok := strings.CutPrefix(name, filePlay); ok {
		if base, ok := strings.CutSuffix(rest, ".yaml"); ok {
			return playName.MatchString(base)
		}
	}
	return false
}

func maxOf(name string) int64 {
	switch {
	case name == fileReadme:
		return MaxReadme
	case name == fileManifest, name == fileSig:
		return maxManifest
	case name == fileScripts:
		return maxScripts
	}
	return maxPlaybook
}

// Index es el índice que firma el paquete: una línea «sha256  ruta» por archivo menos SIGNATURE, ordenadas por
// ruta en orden de bytes y terminadas en \n.
func Index(files map[string][]byte) []byte {
	var names []string
	for n := range files {
		if n != fileSig {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		h := sha256.Sum256(files[n])
		b.WriteString(hex.EncodeToString(h[:]) + "  " + n + "\n")
	}
	return b.Bytes()
}

// unzip lee el zip ya en memoria a un mapa ruta→bytes, con todas las reglas de la sección Zip del ADR.
func unzip(data []byte) (map[string][]byte, error) {
	if len(data) > MaxArchive {
		return nil, i18n.New("pack.err.zip.too_big", i18n.A("what", "archive"))
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, i18n.New("pack.err.zip.invalid", nil)
	}
	if len(zr.File) > MaxEntries {
		return nil, i18n.New("pack.err.zip.too_big", i18n.A("what", "entries"))
	}
	files := map[string][]byte{}
	seen := map[string]bool{}
	left := int64(MaxArchive)
	for _, f := range zr.File {
		k := strings.ToLower(f.Name)
		if seen[k] {
			return nil, i18n.New("pack.err.zip.dup", i18n.A("name", f.Name))
		}
		seen[k] = true
		if !allowedPath(f.Name) || f.Mode()&(fs.ModeSymlink|fs.ModeDir|fs.ModeIrregular) != 0 || f.FileInfo().IsDir() {
			return nil, i18n.New("pack.err.zip.path", i18n.A("name", f.Name))
		}
		rc, err := f.Open()
		if err != nil {
			return nil, i18n.New("pack.err.zip.invalid", nil)
		}
		lim := min(left, maxOf(f.Name))
		b, err := io.ReadAll(io.LimitReader(rc, lim+1))
		rc.Close()
		if err != nil {
			return nil, i18n.New("pack.err.zip.invalid", nil)
		}
		if int64(len(b)) > lim {
			what := "archive"
			if lim == maxOf(f.Name) {
				what = f.Name
			}
			return nil, i18n.New("pack.err.zip.too_big", i18n.A("what", what))
		}
		left -= int64(len(b))
		files[f.Name] = b
	}
	return files, nil
}

// Zip arma el zip determinista de files: orden por ruta, fecha fija, sin directorios ni extras.
func Zip(files map[string][]byte) ([]byte, error) {
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		h := &zip.FileHeader{Name: n, Method: zip.Deflate, Modified: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readDir lee una carpeta con la estructura del zip (una fuente packs/<nombre>/ o un paquete instalado) a un
// mapa ruta→bytes. Sin enlaces, sin rutas fuera del formato y con los mismos topes. extra son archivos propios
// del almacén que se aceptan en la raíz (p. ej. INDEX).
func readDir(dir string, extra ...string) (map[string][]byte, error) {
	files := map[string][]byte{}
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "playbooks" {
				return nil
			}
			return i18n.New("pack.err.zip.path", i18n.A("name", rel))
		}
		known := false
		for _, e := range extra {
			known = known || rel == e
		}
		if !d.Type().IsRegular() || (!known && !allowedPath(rel)) {
			return i18n.New("pack.err.zip.path", i18n.A("name", rel))
		}
		if len(files) >= MaxEntries {
			return i18n.New("pack.err.zip.too_big", i18n.A("what", "entries"))
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		lim := min(MaxArchive-total, maxOf(rel))
		b, err := io.ReadAll(io.LimitReader(f, lim+1))
		if err != nil {
			return err
		}
		if int64(len(b)) > lim {
			return i18n.New("pack.err.zip.too_big", i18n.A("what", rel))
		}
		total += int64(len(b))
		files[rel] = b
		return nil
	})
	var ie *i18n.Error
	if err != nil && !errors.As(err, &ie) {
		return nil, i18n.Wrap("pack.err.read", err, nil)
	}
	return files, err
}

// Build arma el zip determinista de una carpeta fuente packs/<nombre>/ (sin SIGNATURE) y la valida con las
// reglas del instalador, salvo la firma, como si fuera de terceros. keys vacío: la firma no se exige.
func Build(dir string) ([]byte, error) {
	files, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	return Zip(files)
}
