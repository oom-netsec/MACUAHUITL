package ingest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxOpen    = 64 // archivos abiertos a la vez con {origen}
	maxOrigins = 1024
	maxName    = 64
	maxSuffix  = 10000
)

// Sink es el archivo de salida: dónde, cómo se llama, cuándo rota, cuántos
// guarda y en qué formato. Con 0 no rota por tamaño ni por tiempo.
type Sink struct {
	Dir         string
	Template    string // ver ValidateTemplate
	RotateBytes int64
	RotateEvery time.Duration
	MaxFiles    int
	Format      string            // texto (default), crudo o jsonl
	OnOpen      func(path string) // archivo nuevo creado
	OnRemove    func(path string) // archivo borrado por la retención
}

// ValidateTemplate acepta {fecha}, {hora} y {origen} más [A-Za-z0-9_.-], de 1 a
// 64 caracteres, y exige {fecha} o {hora} para que dos archivos no choquen.
func ValidateTemplate(t string) error {
	if t == "" || len(t) > maxName {
		return fmt.Errorf("la plantilla debe tener entre 1 y %d caracteres", maxName)
	}
	if !strings.Contains(t, "{fecha}") && !strings.Contains(t, "{hora}") {
		return errors.New("la plantilla debe llevar {fecha} o {hora}")
	}
	s := strings.NewReplacer("{fecha}", "0", "{hora}", "0", "{origen}", "0").Replace(t)
	if strings.ContainsAny(s, "{}") {
		return errors.New("la plantilla solo admite los tokens {fecha}, {hora} y {origen}, bien cerrados")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return fmt.Errorf("la plantilla solo admite letras, dígitos, _ . - y los tokens; no %q", r)
		}
	}
	if strings.Contains(s, "..") {
		return errors.New("la plantilla no puede llevar \"..\"")
	}
	return nil
}

// Validate comprueba los rangos: 1 a 1024 MB, 1 min a 7 días y 1 a 1000 archivos.
func (s Sink) Validate() error {
	if s.Dir == "" {
		return errors.New("falta la carpeta de salida")
	}
	if err := ValidateTemplate(s.Template); err != nil {
		return err
	}
	if s.RotateBytes != 0 && (s.RotateBytes < 1<<20 || s.RotateBytes > 1024<<20) {
		return errors.New("el tamaño de rotación debe estar entre 1 y 1024 MB")
	}
	if s.RotateEvery != 0 && (s.RotateEvery < time.Minute || s.RotateEvery > 7*24*time.Hour) {
		return errors.New("la rotación por tiempo debe estar entre 1 minuto y 7 días")
	}
	if s.MaxFiles < 1 || s.MaxFiles > 1000 {
		return errors.New("el máximo de archivos debe estar entre 1 y 1000")
	}
	switch s.Format {
	case "", "texto", "crudo", "jsonl":
		return nil
	}
	return fmt.Errorf("formato %q no soportado (texto, crudo o jsonl)", s.Format)
}

// Record es lo que el archivo pide a cada evento: de qué origen ("ip:puerto" o IP)
// viene y su línea (con salto final) en el formato pedido: texto, crudo o jsonl.
type Record interface {
	Origin() string
	Line(format string) []byte
}

// fileOrigin deja la IP apta para un nombre de archivo (`:` pasa a `-`).
func fileOrigin(ip string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, ip)
}

// originRe es lo que fileOrigin da para una IP: IPv4 con puntos o IPv6 con «-» en vez de «:»
// (con IPv4 incrustada o zona al final).
const originRe = `(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4}(?:-[0-9A-Fa-f]{0,4}){2,7}(?:\.[0-9]{1,3}){0,3}(?:-[0-9A-Za-z]{1,15})?)`

type outFile struct {
	f      *os.File // nil si el límite de abiertos lo cerró
	path   string
	size   int64
	opened time.Time
	use    uint64
}

// Writer escribe los eventos en los archivos del Sink; no es seguro para uso
// concurrente (lo usa una sola gorutina).
type Writer struct {
	s         Sink
	now       func() time.Time
	ext       string
	perOrigin bool
	re        *regexp.Regexp
	files     map[string]*outFile // clave: origen, o "" sin {origen}
	open      int
	tick      uint64
}

// OutputError es un fallo del disco al preparar la salida (no una configuración inválida).
type OutputError struct{ Err error }

func (e *OutputError) Error() string { return e.Err.Error() }
func (e *OutputError) Unwrap() error { return e.Err }

// NewWriter no valida: quien lo llama usa antes Sink.Validate.
func NewWriter(s Sink, now func() time.Time) (*Writer, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, &OutputError{fmt.Errorf("carpeta de salida: %w", err)}
	}
	w := &Writer{s: s, now: now, ext: ".log", perOrigin: strings.Contains(s.Template, "{origen}"), files: map[string]*outFile{}}
	if s.Format == "jsonl" {
		w.ext = ".jsonl"
	}
	// la plantilla escapada como regex; cada token solo encaja con lo que el propio writer produce
	q := strings.NewReplacer(`\{fecha\}`, `[0-9]{8}`, `\{hora\}`, `[0-9]{6}`, `\{origen\}`, originRe).Replace(regexp.QuoteMeta(s.Template))
	w.re = regexp.MustCompile("^" + q + `(?:_[1-9][0-9]{0,3})?` + regexp.QuoteMeta(w.ext) + "$") // el sufijo _N llega a maxSuffix (4 dígitos)
	return w, nil
}

// Write guarda el evento en el archivo de su origen (o el único, sin {origen}).
func (w *Writer) Write(r Record) error {
	key := ""
	if w.perOrigin {
		key = fileOrigin(SourceIP(r.Origin()))
	}
	line := r.Line(w.s.Format)
	now := w.now()
	of := w.files[key]
	if of != nil && w.due(of, len(line), now) {
		w.closeFile(of)
		of = nil
	}
	var err error
	switch {
	case of == nil:
		of, err = w.create(key, now)
	case of.f == nil:
		if err = w.reopen(of); errors.Is(err, fs.ErrNotExist) { // la retención o alguien de fuera lo borró
			of, err = w.create(key, now)
		}
	}
	if err != nil {
		return err
	}
	w.tick++
	of.use = w.tick
	n, err := of.f.Write(line)
	of.size += int64(n)
	return err
}

func (w *Writer) due(of *outFile, add int, now time.Time) bool {
	if w.s.RotateBytes > 0 && of.size > 0 && of.size+int64(add) > w.s.RotateBytes {
		return true
	}
	return w.s.RotateEvery > 0 && now.Sub(of.opened) >= w.s.RotateEvery
}

func (w *Writer) closeFile(of *outFile) {
	if of.f != nil {
		of.f.Close()
		of.f = nil
		w.open--
	}
}

// room cierra el archivo abierto menos usado si ya hay maxOpen.
func (w *Writer) room() {
	for w.open >= maxOpen {
		var lru *outFile
		var lruKey string
		for k, of := range w.files {
			if of.f != nil && (lru == nil || of.use < lru.use) {
				lru, lruKey = of, k
			}
		}
		w.closeFile(lru)
		if len(w.files) > maxOrigins {
			delete(w.files, lruKey) // ese origen volverá con un archivo nuevo
		}
	}
}

func (w *Writer) reopen(of *outFile) error {
	w.room()
	f, err := os.OpenFile(of.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("archivo de salida: %w", err)
	}
	of.f = f
	w.open++
	return nil
}

// create abre un archivo nuevo con el nombre de la plantilla; si existe agrega _N.
func (w *Writer) create(key string, now time.Time) (*outFile, error) {
	w.room()
	base := strings.NewReplacer("{fecha}", now.Format("20060102"), "{hora}", now.Format("150405"), "{origen}", key).Replace(w.s.Template)
	for i := 0; i < maxSuffix; i++ {
		name := base + w.ext
		if i > 0 {
			name = fmt.Sprintf("%s_%d%s", base, i, w.ext)
		}
		path := filepath.Join(w.s.Dir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("archivo de salida: %w", err)
		}
		of := &outFile{f: f, path: path, opened: now}
		w.files[key] = of
		w.open++
		if w.s.OnOpen != nil {
			w.s.OnOpen(path)
		}
		w.retain()
		return of, nil
	}
	return nil, errors.New("demasiados archivos con el mismo nombre")
}

// retain borra los más viejos (por mtime) que encajan con la plantilla hasta
// dejar MaxFiles; nunca toca un archivo abierto ni uno que no encaje.
func (w *Writer) retain() {
	ents, err := os.ReadDir(w.s.Dir)
	if err != nil {
		return
	}
	type old struct {
		path string
		mod  time.Time
	}
	var ours []old
	for _, e := range ents {
		if !e.Type().IsRegular() || !w.re.MatchString(e.Name()) {
			continue
		}
		if info, err := e.Info(); err == nil {
			ours = append(ours, old{filepath.Join(w.s.Dir, e.Name()), info.ModTime()})
		}
	}
	if len(ours) <= w.s.MaxFiles {
		return
	}
	sort.Slice(ours, func(i, j int) bool {
		if !ours[i].mod.Equal(ours[j].mod) {
			return ours[i].mod.Before(ours[j].mod)
		}
		return ours[i].path < ours[j].path
	})
	byPath := map[string]string{} // ruta -> origen, de las entradas conocidas
	for k, of := range w.files {
		byPath[of.path] = k
	}
	for _, o := range ours[:len(ours)-w.s.MaxFiles] {
		k, known := byPath[o.path]
		if known && w.files[k].f != nil {
			continue
		}
		if os.Remove(o.path) != nil {
			continue
		}
		if known {
			delete(w.files, k) // cerrada y borrada: el origen volverá con un archivo nuevo
		}
		if w.s.OnRemove != nil {
			w.s.OnRemove(o.path)
		}
	}
}

// Close cierra los archivos abiertos.
func (w *Writer) Close() {
	for _, of := range w.files {
		w.closeFile(of)
	}
}
