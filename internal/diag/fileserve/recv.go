package fileserve

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// La recepción es la única parte de este paquete que escribe en disco, y es la misma para
// TFTP, FTP, SCP y SFTP: nombre saneado, archivo nuevo, topes. Los protocolos no tocan el
// sistema de archivos por su cuenta.

var (
	errExists  = i18n.New("fileserve.reason.exists", nil)
	errTooBig  = i18n.New("fileserve.reason.too_big", nil)
	errTotal   = i18n.New("fileserve.reason.total", nil)
	errTooMany = i18n.New("fileserve.reason.too_many_files", nil)
)

// SafeName deja solo el nombre base de lo que pide el equipo: lo que haya antes del último
// separador (/ o \) se descarta, así "../../etc/passwd" y "cfg/r1.txt" no salen de la
// carpeta. Rechaza vacío o solo espacios, espacios al inicio o al final, nombres que empiezan
// con "." (dotfiles que el shell, el escritorio o el SSH cargan solos, y "." y ".."), UTF-8
// inválido, NUL, caracteres de control y de formato Unicode (U+202E, ancho cero, BOM) que
// disfrazan el nombre, y nombres de más de 200 bytes.
func SafeName(raw string) (string, error) {
	if i := strings.LastIndexAny(raw, `/\`); i >= 0 {
		raw = raw[i+1:]
	}
	if strings.TrimSpace(raw) == "" {
		return "", i18n.New("fileserve.reason.name_empty", nil)
	}
	if raw != strings.TrimSpace(raw) {
		return "", i18n.New("fileserve.reason.name_spaces", nil)
	}
	if raw[0] == '.' {
		return "", i18n.New("fileserve.reason.name_dot", nil)
	}
	if len(raw) > 200 {
		return "", i18n.New("fileserve.reason.name_long", nil)
	}
	if !utf8.ValidString(raw) {
		return "", i18n.New("fileserve.reason.name_utf8", nil)
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "", i18n.New("fileserve.reason.name_control", nil)
		}
		if unicode.Is(unicode.Cf, r) {
			return "", i18n.New("fileserve.reason.name_format", nil)
		}
	}
	return raw, nil
}

type receiver struct {
	dir               string   // ruta real validada, solo para mostrar y auditar
	root              *os.Root // la carpeta abierta una vez: toda la E/S va por aquí
	maxFile, maxTotal int64
	mu                sync.Mutex
	total             int64
	files, maxFiles   int
	inFlight          map[string]bool // archivos aún en escritura
}

// newReceiver abre dir (ya validada) como Root; prepare usa newReceiverIn con la que abrió OpenDir.
func newReceiver(dir string, maxFile, maxTotal int64) (*receiver, error) {
	if !filepath.IsAbs(dir) {
		return nil, i18n.New("fileserve.err.recv_relative", i18n.A("dir", dir))
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("fileserve: %w", err)
	}
	return newReceiverIn(root, dir, maxFile, maxTotal), nil
}

func newReceiverIn(root *os.Root, dir string, maxFile, maxTotal int64) *receiver {
	if maxFile <= 0 {
		maxFile = DefaultMaxFile
	}
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotal
	}
	return &receiver{dir: dir, root: root, maxFile: maxFile, maxTotal: maxTotal, inFlight: map[string]bool{}, maxFiles: maxRecvFiles}
}

// close suelta la carpeta abierta; los archivos ya abiertos siguen siendo válidos.
func (r *receiver) close() { r.root.Close() }

// exists es solo una pista para rechazar pronto; la decisión real es O_EXCL en create.
func (r *receiver) exists(name string) bool {
	_, err := r.root.Lstat(name)
	return err == nil
}

func (r *receiver) writing(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inFlight[name]
}

func (r *receiver) grow(n int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.total+n > r.maxTotal {
		return errTotal
	}
	r.total += n
	return nil
}

func (r *receiver) shrink(n int64) {
	r.mu.Lock()
	r.total -= n
	r.mu.Unlock()
}

// create abre el archivo nuevo. announced (>0) es el tamaño que anuncia el cliente: si ya
// excede un tope, ni se crea. Nunca sobrescribe ni sigue enlaces simbólicos.
func (r *receiver) create(raw string, announced int64) (*recvFile, error) {
	name, err := SafeName(raw)
	if err != nil {
		return nil, err
	}
	if announced > r.maxFile {
		return nil, errTooBig
	}
	path := filepath.Join(r.dir, name)
	r.mu.Lock() // comprobar, crear y marcar "en escritura" a la vez: nadie pasa el tope ni ve el archivo a medias
	var f *os.File
	switch {
	case announced > 0 && r.total+announced > r.maxTotal:
		err = errTotal
	case r.files >= r.maxFiles:
		err = errTooMany
	default:
		if f, err = sys.OpenNewIn(r.root, name); err == nil {
			r.inFlight[name] = true
			r.files++
		}
	}
	r.mu.Unlock()
	if errors.Is(err, errTotal) || errors.Is(err, errTooMany) {
		return nil, err
	}
	if errors.Is(err, os.ErrExist) {
		return nil, errExists
	}
	if err != nil {
		return nil, err
	}
	return &recvFile{r: r, f: f, path: path, name: name}, nil
}

// recvFile es un archivo en recepción: cuenta lo escrito contra los topes y se confirma
// (commit) o se descarta (abort) una sola vez.
type recvFile struct {
	r            *receiver
	f            *os.File
	path, name   string
	mu           sync.Mutex
	size, cursor int64 // size es hasta dónde se ha escrito (SFTP puede escribir fuera de orden)
	done         bool
}

func (w *recvFile) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done || off < 0 || end < off {
		return 0, i18n.New("fileserve.reason.bad_offset", nil)
	}
	if end > w.size {
		if end > w.r.maxFile {
			return 0, errTooBig
		}
		if err := w.r.grow(end - w.size); err != nil {
			return 0, err
		}
		w.size = end
	}
	return w.f.WriteAt(p, off)
}

func (w *recvFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	off := w.cursor
	w.mu.Unlock()
	n, err := w.WriteAt(p, off)
	w.mu.Lock()
	w.cursor += int64(n)
	w.mu.Unlock()
	return n, err
}

func (w *recvFile) finish() {
	w.r.mu.Lock()
	delete(w.r.inFlight, w.name)
	w.r.mu.Unlock()
}

// commit cierra el archivo y devuelve su SHA-256 y tamaño.
func (w *recvFile) commit() (sum string, size int64, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return "", w.size, i18n.New("fileserve.reason.file_closed", nil)
	}
	w.done = true
	defer w.f.Close()
	defer w.finish() // recién entonces se puede entregar
	h := sha256.New()
	if _, err = w.f.Seek(0, io.SeekStart); err == nil {
		_, err = io.Copy(h, w.f)
	}
	return hex.EncodeToString(h.Sum(nil)), w.size, err
}

// abort descarta un archivo incompleto: no se deja a medias en la carpeta de recepción.
func (w *recvFile) abort() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return
	}
	w.done = true
	w.f.Close()
	w.r.root.Remove(w.name)
	w.finish()
	w.r.shrink(w.size)
	w.r.mu.Lock()
	w.r.files-- // devuelve también el cupo de archivos
	w.r.mu.Unlock()
}
