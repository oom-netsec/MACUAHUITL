// Package backup guarda y administra los respaldos de configuración de los equipos:
// un archivo por equipo, tipo (running o startup) y momento, con permisos 0600 y retención.
//
// Layout: <Root>/<equipo>/<AAAAMMDDTHHMMSSZ>-<tipo>.cfg y su ficha .json al lado.
// No hace: red ni recolectar (eso es de Patrol); tampoco restaurar. Es lo único que escribe en Root.
//
// shortcut: la comprobación de enlaces simbólicos (Lstat) deja una ventana entre comprobar y
// usar si otro proceso con la cuenta del ingeniero los cambia a la vez; el núcleo es el único escritor.
package backup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

type Kind string

const (
	Running Kind = "running"
	Startup Kind = "startup"
)

const stampLayout = "20060102T150405Z"

// DefaultKeep es la retención por equipo y tipo cuando la petición no dice otra.
const DefaultKeep = 30

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	fileRe = regexp.MustCompile(`^(\d{8}T\d{6}Z)-(running|startup)\.cfg$`)
	idRe   = regexp.MustCompile(`^(\d{8}T\d{6}Z)-(running|startup)$`)
)

// Entry es un respaldo. ID es "equipo/sello-tipo".
type Entry struct {
	ID     string    `json:"id"`
	Device string    `json:"device"`
	Kind   Kind      `json:"kind"`
	At     time.Time `json:"at"`
	Bytes  int       `json:"bytes"`
	SHA256 string    `json:"sha256"`
	// Masked: el trabajo enmascaró los secretos. Sin ficha se supone que sí (aviso conservador).
	Masked bool   `json:"masked"`
	Job    string `json:"job,omitempty"`
	Round  int    `json:"round,omitempty"`
	// Serial: número de serie del equipo al respaldar (show version); restaurar exige que coincida.
	Serial string `json:"serial,omitempty"`
	// Truncated: el trabajo recortó la salida; no es la configuración completa.
	Truncated bool `json:"truncated,omitempty"`
	// Sig: HMAC-SHA256 de la ficha con la llave de la bóveda; sin ella o inválida el respaldo se puede ver y comparar, no restaurar.
	Sig string `json:"sig,omitempty"`
}

// sigInput serializa los campos que identifican y garantizan el respaldo, cada uno con su longitud para que no haya dos fichas con el mismo texto.
func (e Entry) sigInput() []byte {
	var b []byte
	for _, f := range []string{"macuahuitl-backup-v1", e.ID, e.Device, string(e.Kind), strconv.Itoa(e.Bytes), e.SHA256, strconv.FormatBool(e.Masked),
		e.Serial, strconv.FormatBool(e.Truncated)} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

// Sign da la firma de la ficha con key.
func (e Entry) Sign(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(e.sigInput())
	return hex.EncodeToString(m.Sum(nil))
}

// Verify dice si la ficha trae una firma válida de key. Sin llave o sin firma, no.
func (e Entry) Verify(key []byte) bool {
	got, err := hex.DecodeString(e.Sig)
	if len(key) == 0 || err != nil || len(got) == 0 {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write(e.sigInput())
	return hmac.Equal(got, m.Sum(nil))
}

// Path es el archivo .cfg del respaldo bajo root.
func (e Entry) Path(root string) string {
	return filepath.Join(root, e.Device, e.At.UTC().Format(stampLayout)+"-"+string(e.Kind)+".cfg")
}

func metaPath(cfg string) string { return strings.TrimSuffix(cfg, ".cfg") + ".json" }

// Name valida el nombre de equipo que llega de fuera: sin separadores, sin punto inicial.
func Name(device string) (string, error) {
	if !nameRe.MatchString(device) {
		return "", i18n.New("backup.store.bad_device", i18n.A("device", device))
	}
	return device, nil
}

// Sanitize convierte el nombre de la carpeta de Patrol en uno válido para Name.
func Sanitize(device string) string {
	var b strings.Builder
	for _, r := range device {
		if r < 0x80 && (r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if len(s) > 128 {
		s = s[:128]
	}
	if s == "" || s[0] == '.' || s[0] == '-' {
		s = "_" + s
	}
	return s
}

// Store es la carpeta de respaldos. Key (opcional) es la llave con que Save firma la ficha.
type Store struct {
	Root string
	Key  []byte
}

// dir devuelve la carpeta del equipo ya comprobada: nombre válido y, si existe, una carpeta
// de verdad (no un enlace) dentro de Root. create la crea con 0700 si falta.
func (s Store) dir(device string, create bool) (string, error) {
	if _, err := Name(device); err != nil {
		return "", err
	}
	if create {
		if err := os.MkdirAll(s.Root, 0o700); err != nil {
			return "", fmt.Errorf("backup: %w", err)
		}
	}
	d := filepath.Join(s.Root, device)
	fi, err := os.Lstat(d)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !create {
			return d, nil
		}
		if err := os.Mkdir(d, 0o700); err != nil {
			return "", fmt.Errorf("backup: %w", err)
		}
		return d, nil
	case err != nil:
		return "", fmt.Errorf("backup: %w", err)
	case !fi.IsDir():
		return "", i18n.New("backup.store.not_dir", i18n.A("dir", d))
	}
	return d, nil
}

// Save guarda text. Si ese equipo, tipo y momento ya existen no lo pisa y devuelve created=false.
func (s Store) Save(e Entry, text string) (Entry, bool, error) {
	e.Device = Sanitize(e.Device)
	if e.Kind != Running && e.Kind != Startup {
		return e, false, i18n.New("backup.store.bad_kind", i18n.A("kind", string(e.Kind)))
	}
	e.At = e.At.UTC().Truncate(time.Second)
	e.ID = e.Device + "/" + e.At.Format(stampLayout) + "-" + string(e.Kind)
	sum := sha256.Sum256([]byte(text))
	e.Bytes, e.SHA256 = len(text), hex.EncodeToString(sum[:])
	e.Sig = ""
	if len(s.Key) > 0 {
		e.Sig = e.Sign(s.Key)
	}
	if _, err := s.dir(e.Device, true); err != nil {
		return e, false, err
	}
	cfg := e.Path(s.Root)
	if _, err := os.Lstat(cfg); err == nil {
		if old, _, err := s.Get(e.ID); err == nil {
			return old, false, nil
		}
		return e, false, nil
	}
	meta, _ := json.Marshal(e)
	// La ficha va primero: nunca queda un .cfg sin ella.
	if err := writeNew(metaPath(cfg), meta, true); err != nil {
		return e, false, err
	}
	if err := writeNew(cfg, []byte(text), false); err != nil {
		return e, false, err
	}
	return e, true, nil
}

// writeNew crea el archivo con 0600; O_EXCL no sigue enlaces simbólicos ni pisa nada. Con replace, una
// ficha vieja (de un intento cortado) se borra antes, pero solo si es un archivo regular.
func writeNew(p string, b []byte, replace bool) error {
	if fi, err := os.Lstat(p); err == nil && replace {
		if !fi.Mode().IsRegular() {
			return i18n.New("backup.store.not_regular", i18n.A("path", p))
		}
		os.Remove(p)
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(p)
		return fmt.Errorf("backup: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("backup: %w", err)
	}
	return f.Close()
}

// entries lee las entradas de la carpeta del equipo que son archivos .cfg de verdad.
func (s Store) entries(device string) ([]Entry, error) {
	d, err := s.dir(device, false)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(d)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	var out []Entry
	for _, de := range des {
		m := fileRe.FindStringSubmatch(de.Name())
		if m == nil || !de.Type().IsRegular() { // DirEntry no sigue enlaces: un symlink no es regular
			continue
		}
		at, err := time.Parse(stampLayout, m[1])
		if err != nil {
			continue
		}
		e := Entry{ID: device + "/" + m[1] + "-" + m[2], Device: device, Kind: Kind(m[2]), At: at, Masked: true}
		if fi, err := de.Info(); err == nil {
			e.Bytes = int(fi.Size())
		}
		if b, err := readSmall(metaPath(filepath.Join(d, de.Name()))); err == nil {
			var meta Entry
			if json.Unmarshal(b, &meta) == nil {
				e.Masked, e.Job, e.Round, e.SHA256 = meta.Masked, meta.Job, meta.Round, meta.SHA256
				e.Serial, e.Truncated, e.Sig = meta.Serial, meta.Truncated, meta.Sig
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

func readSmall(p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return nil, i18n.New("backup.store.bad_meta", nil)
	}
	return os.ReadFile(p)
}

// List devuelve los respaldos de un equipo (vacío = todos), los más nuevos primero.
func (s Store) List(device string) ([]Entry, error) {
	if device != "" {
		return s.entries(device)
	}
	des, err := os.ReadDir(s.Root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	var out []Entry
	for _, de := range des {
		if !de.IsDir() || !nameRe.MatchString(de.Name()) {
			continue
		}
		es, err := s.entries(de.Name())
		if err != nil {
			continue
		}
		out = append(out, es...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

// ParseID separa "equipo/sello-tipo" y valida cada parte.
func ParseID(id string) (device string, at time.Time, kind Kind, err error) {
	dev, rest, ok := strings.Cut(id, "/")
	m := idRe.FindStringSubmatch(rest)
	if _, nerr := Name(dev); !ok || nerr != nil || m == nil {
		return "", time.Time{}, "", i18n.New("backup.store.bad_id", i18n.A("id", id))
	}
	at, err = time.Parse(stampLayout, m[1])
	return dev, at, Kind(m[2]), err
}

// Get devuelve un respaldo y su texto.
func (s Store) Get(id string) (Entry, string, error) {
	dev, at, kind, err := ParseID(id)
	if err != nil {
		return Entry{}, "", err
	}
	es, err := s.entries(dev)
	if err != nil {
		return Entry{}, "", err
	}
	for _, e := range es {
		if e.At.Equal(at) && e.Kind == kind {
			f, err := sys.OpenRegular(e.Path(s.Root))
			if err != nil {
				return Entry{}, "", fmt.Errorf("backup: %w", err)
			}
			defer f.Close()
			b, err := io.ReadAll(f)
			return e, string(b), err
		}
	}
	return Entry{}, "", i18n.New("backup.store.not_found", i18n.A("id", id))
}

// Prune deja los keep respaldos más nuevos de cada tipo del equipo y borra el resto (.cfg y ficha).
// Solo toca archivos regulares con nombre de respaldo dentro de la carpeta del equipo.
func (s Store) Prune(device string, keep int) (int, error) {
	if keep < 1 {
		return 0, i18n.New("backup.store.min_keep", nil)
	}
	es, err := s.entries(device)
	if err != nil {
		return 0, err
	}
	seen := map[Kind]int{}
	removed := 0
	for _, e := range es { // más nuevos primero
		if seen[e.Kind]++; seen[e.Kind] <= keep {
			continue
		}
		cfg := e.Path(s.Root)
		if err := os.Remove(cfg); err != nil {
			return removed, fmt.Errorf("backup: %w", err)
		}
		removed++
		if fi, err := os.Lstat(metaPath(cfg)); err == nil && fi.Mode().IsRegular() {
			os.Remove(metaPath(cfg))
		}
	}
	return removed, nil
}
