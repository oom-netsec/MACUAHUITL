package fileserve

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

var errNotPublished = errors.New("archivo no publicado")

const maxListed = 1000

// source es lo que un servidor entrega en lectura: archivos sueltos elegidos de uno en uno
// y, si se pide, los archivos regulares del primer nivel de una carpeta. Siempre por nombre
// base: no hay subcarpetas, ni "..", ni enlaces simbólicos.
type source struct {
	files map[string]string      // nombre base → ruta absoluta
	infos map[string]os.FileInfo // lo que eran al publicarlos: si luego son otro archivo, no se sirven
	dir   string                 // ruta real ya validada; vacía = sin carpeta
	root  *os.Root               // la carpeta abierta una vez: toda la lectura va por aquí
	rcv   *receiver              // si recibe en la misma carpeta, lo que aún se escribe no se entrega
}

// close suelta la carpeta abierta; los archivos ya abiertos siguen siendo válidos.
func (s *source) close() {
	if s.root != nil {
		s.root.Close()
	}
}

func (s *source) enabled() bool { return len(s.files) > 0 || s.dir != "" }

// plainName deja pasar solo un nombre base (con un "/" inicial opcional: algunos clientes lo mandan).
func plainName(name string) (string, bool) {
	name = strings.TrimPrefix(name, "/")
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return "", false
	}
	for _, r := range name { // un nombre con salto de línea rompería las órdenes de scp y FTP
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return name, true
}

func (s *source) hidden(name string) bool {
	return s.rcv != nil && s.rcv.dir == s.dir && s.rcv.writing(name)
}

// exists es la comprobación barata previa a abrir (el servidor TFTP responde error 1 sin abrir nada).
func (s *source) exists(name string) bool {
	name, ok := plainName(name)
	if !ok {
		return false
	}
	if _, ok := s.files[name]; ok {
		return true
	}
	if s.dir == "" || s.hidden(name) {
		return false
	}
	li, err := s.root.Lstat(name)
	return err == nil && li.Mode().IsRegular() && !sys.HardLinked(li)
}

// open abre un archivo publicado. En la carpeta, lo que se abre debe ser exactamente lo que
// se vio con Lstat (os.SameFile): un enlace puesto entre una cosa y otra no se sigue.
func (s *source) open(name string) (*os.File, os.FileInfo, error) {
	name, ok := plainName(name)
	if !ok {
		return nil, nil, errNotPublished
	}
	path, listed := s.files[name]
	var li os.FileInfo
	if !listed {
		if s.dir == "" || s.hidden(name) {
			return nil, nil, errNotPublished
		}
		var err error
		if li, err = s.root.Lstat(name); err != nil || !li.Mode().IsRegular() || sys.HardLinked(li) {
			return nil, nil, errNotPublished
		}
	} else {
		li = s.infos[name] // nil si no se registró (pruebas): sin esa comprobación
	}
	var f *os.File
	var err error
	if listed {
		f, err = sys.OpenRegular(path)
	} else {
		f, err = sys.OpenRegularIn(s.root, name)
	}
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil || (li != nil && !os.SameFile(li, fi)) || sys.HardLinked(fi) {
		f.Close()
		return nil, nil, errNotPublished
	}
	return f, fi, nil
}

// list devuelve lo publicado, ordenado por nombre, para los protocolos que listan (FTP, SFTP).
func (s *source) list() []os.FileInfo {
	byName := map[string]os.FileInfo{}
	if s.dir != "" {
		if ents, err := fs.ReadDir(s.root.FS(), "."); err == nil {
			for _, e := range ents {
				if _, ok := plainName(e.Name()); !ok || !e.Type().IsRegular() || s.hidden(e.Name()) { // un enlace tiene tipo ModeSymlink: no entra
					continue
				}
				if fi, err := e.Info(); err == nil && !sys.HardLinked(fi) {
					byName[e.Name()] = fi
				}
				if len(byName) >= maxListed {
					break
				}
			}
		}
	}
	for name, p := range s.files {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			byName[name] = renamed{fi, name}
		}
	}
	out := make([]os.FileInfo, 0, len(byName))
	for _, fi := range byName {
		out = append(out, fi)
	}
	slices.SortFunc(out, func(a, b os.FileInfo) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// renamed muestra un archivo suelto con su nombre publicado.
type renamed struct {
	os.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }

// OpenFrom abre name (solo nombre base) de la carpeta elegida dir con las mismas reglas que
// la publicación: carpeta válida y no sensible, archivo regular de primer nivel, sin enlaces.
// Es lo que usan los clientes para enviar (put) desde una carpeta.
func OpenFrom(dir, name string, deny ...string) (*os.File, os.FileInfo, error) {
	root, real, err := OpenDir(dir, deny...)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close() // el archivo abierto sigue siendo válido
	f, fi, err := (&source{dir: real, root: root}).open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("fileserve: %q no es un archivo regular de %s", name, real)
	}
	return f, fi, nil
}
