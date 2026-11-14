// Package analyze convierte la evidencia que guarda Patrol en diagnóstico:
// hallazgos por reglas declarativas, diferencias entre rondas y una línea de
// tiempo correlacionada.
//
// No hace: red ni cambios en los equipos. Solo lee archivos locales.
package analyze

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Section es la salida de un comando en una ronda de un equipo.
type Section struct {
	Device  string // carpeta del equipo: <hostname>_<ip>
	Round   int
	At      time.Time
	Command string
	Invalid bool
	// Truncated: el tope por salida cortó el texto; no es la salida completa.
	Truncated bool
	// Incomplete: el comando falló o se cortó y Text es solo lo que alcanzó a llegar.
	Incomplete bool
	Text       string
}

// Bundle es el paquete de salida de un trabajo de Patrol ya leído.
type Bundle struct {
	Dir      string
	Sections []Section
	Warnings []Warning
	// Files: archivos sueltos leídos por completo (carpeta equipo/archivo → tamaño visto al listarlos).
	Files   map[string]int64
	upTo    int   // 0 = todas las rondas
	total   int64 // bytes de texto guardados
	capped  bool
	skipped int
}

type Warning struct {
	Device  string    `json:"device,omitempty"`
	Round   int       `json:"round,omitempty"`
	Command string    `json:"command,omitempty"`
	Msg     string    `json:"msg"`
	MsgTx   i18n.Text `json:"-"` // Msg como texto de catálogo
}

// Warn arma un aviso con su texto de catálogo (Msg en español y MsgTx).
func Warn(device string, round int, command, key string, kv ...any) Warning {
	return warnTx(device, round, command, i18n.Tx(key, kv...))
}

// WarnText es Warn con el texto ya armado.
func WarnText(device string, round int, command string, t i18n.Text) Warning {
	return warnTx(device, round, command, t)
}

func warnTx(device string, round int, command string, t i18n.Text) Warning {
	return Warning{Device: device, Round: round, Command: command, Msg: t.In(i18n.Es), MsgTx: t}
}

// wkey identifica un aviso para no repetirlo (Warning lleva un Text, que no se compara).
type wkey struct {
	device, command, msg string
	round                int
}

func (w Warning) key() wkey { return wkey{w.Device, w.Command, w.Msg, w.Round} }

// Límites para que un show tech enorme o un zip malicioso no agoten la memoria del núcleo.
const maxFile = 256 << 20

var (
	maxSection int64 = 8 << 20
	// maxTotal acota el texto descomprimido de todo el paquete.
	maxTotal int64 = 512 << 20
)

// SetLimits cambia el tope por salida y el total del paquete; es para pruebas de otros paquetes.
// Devuelve la función que restaura los valores.
func SetLimits(section, total int64) (restore func()) {
	s, t := maxSection, maxTotal
	maxSection, maxTotal = section, total
	return func() { maxSection, maxTotal = s, t }
}

// Cabeceras que escribe patrol.Writer (internal/patrol/output.go).
var (
	headerRe    = regexp.MustCompile(`^===== (?:ronda (\d+) · )?(\S+) · (.*?)( · comando inválido)?( · incompleto)? =====$`)
	roundFileRe = regexp.MustCompile(`^r(\d+)_\d{8}-\d{6}\.txt$`)
)

// Load lee una carpeta de trabajo de Patrol: archivos sueltos por ronda o
// consolidados y, si se borraron los sueltos, los zips que dejó Patrol.
func Load(dir string) (*Bundle, error) { return loadWith(dir, 0, nil) }

// LoadSkipping es Load sin abrir los archivos sueltos para los que skip(equipo/archivo, tamaño) es
// verdadero: quien ya importó una ronda no la relee. Si todo se omite, el paquete sale vacío sin error.
func LoadSkipping(dir string, skip func(rel string, size int64) bool) (*Bundle, error) {
	return loadWith(dir, 0, skip)
}

// LoadUpTo lee solo hasta la ronda upTo (0 = todas). Los archivos por ronda
// posteriores ni se abren.
func LoadUpTo(dir string, upTo int) (*Bundle, error) { return loadWith(dir, upTo, nil) }

func loadWith(dir string, upTo int, skip func(string, int64) bool) (*Bundle, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, i18n.Wrap("analyze.err.read", err, nil)
	}
	if !fi.IsDir() {
		return nil, i18n.New("analyze.err.not_dir", i18n.A("path", dir))
	}
	b := &Bundle{Dir: dir, upTo: upTo, Files: map[string]int64{}}
	seen := map[string]bool{}
	devs, err := os.ReadDir(dir)
	if err != nil {
		return nil, i18n.Wrap("analyze.err.read", err, nil)
	}
	for _, d := range devs {
		if !d.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(dir, d.Name()))
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".txt") || b.capped || b.skipFile(f.Name()) {
				continue
			}
			rel := d.Name() + "/" + f.Name()
			var size int64
			if info, err := f.Info(); err == nil {
				size = info.Size()
			}
			if skip != nil && skip(rel, size) {
				seen[rel] = true
				b.skipped++
				continue
			}
			fh, err := sys.OpenRegular(filepath.Join(dir, d.Name(), f.Name()))
			if err != nil {
				b.Warnings = append(b.Warnings, Warn(d.Name(), 0, "", "analyze.warn.system", "error", err))
				continue
			}
			full := b.parseFile(rel, io.LimitReader(fh, maxFile))
			fh.Close()
			seen[rel] = true
			if full {
				b.Files[rel] = size
			}
		}
	}
	zips, _ := filepath.Glob(filepath.Join(dir, "*.zip"))
	sort.Strings(zips)
	for _, z := range zips {
		if err := b.readZip(z, seen); err != nil {
			b.Warnings = append(b.Warnings, Warn("", 0, "", "analyze.warn.file_error", "file", filepath.Base(z), "error", err))
		}
	}
	if len(b.Sections) == 0 && b.skipped == 0 {
		return nil, i18n.New("analyze.err.no_outputs", i18n.A("path", dir))
	}
	sort.SliceStable(b.Sections, func(i, j int) bool {
		x, y := b.Sections[i], b.Sections[j]
		if x.Device != y.Device {
			return x.Device < y.Device
		}
		if x.Round != y.Round {
			return x.Round < y.Round
		}
		return x.At.Before(y.At)
	})
	return b, nil
}

func (b *Bundle) readZip(p string, seen map[string]bool) error {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		name := path.Clean(f.Name)
		if seen[name] || strings.Count(name, "/") != 1 || !strings.HasSuffix(name, ".txt") || b.skipFile(path.Base(name)) {
			continue
		}
		if b.capped {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b.parseFile(name, io.LimitReader(rc, maxFile))
		rc.Close()
		seen[name] = true
	}
	return nil
}

func (b *Bundle) skipFile(name string) bool {
	m := roundFileRe.FindStringSubmatch(name)
	if m == nil || b.upTo == 0 {
		return false
	}
	r, _ := strconv.Atoi(m[1])
	return r > b.upTo
}

// overCap marca el paquete como leído parcialmente, con un solo aviso.
func (b *Bundle) overCap(extra int) bool {
	if b.total+int64(extra) <= maxTotal {
		return false
	}
	if !b.capped {
		b.capped = true
		b.Warnings = append(b.Warnings, Warn("", 0, "", "analyze.warn.over_total", "mib", maxTotal>>20))
	}
	return true
}

// unescapeHeader deshace el escape de patrol.Writer: una línea "\\*===== " pierde una barra.
// Un paquete anterior al escape no trae barras y se lee igual.
func unescapeHeader(ln string) string {
	if strings.HasPrefix(ln, `\`) && strings.HasPrefix(strings.TrimLeft(ln, `\`), "===== ") {
		return ln[1:]
	}
	return ln
}

// parseFile corta el archivo en secciones por cabecera. rel es <equipo>/<archivo>.
func (b *Bundle) parseFile(rel string, r io.Reader) (complete bool) {
	dev, file := path.Split(rel)
	dev = strings.TrimSuffix(dev, "/")
	fileRound := 0
	if m := roundFileRe.FindStringSubmatch(file); m != nil {
		fileRound, _ = strconv.Atoi(m[1])
	}
	var cur *Section
	var buf bytes.Buffer
	truncated, partial := false, false
	flush := func() {
		if cur == nil {
			return
		}
		if b.upTo > 0 && cur.Round > b.upTo || b.overCap(buf.Len()) {
			partial = true
			cur, truncated = nil, false
			buf.Reset()
			return
		}
		cur.Text, cur.Truncated = buf.String(), truncated
		b.total += int64(len(cur.Text))
		if truncated {
			partial = true
			b.Warnings = append(b.Warnings, Warn(dev, cur.Round, cur.Command, "analyze.warn.trimmed", "bytes", maxSection))
		}
		b.Sections = append(b.Sections, *cur)
		cur, truncated = nil, false
		buf.Reset()
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		ln := sc.Text()
		if m := headerRe.FindStringSubmatch(ln); m != nil {
			at, err := time.Parse(time.RFC3339, m[2])
			if err == nil {
				flush()
				round := fileRound
				if m[1] != "" {
					round, _ = strconv.Atoi(m[1])
				}
				cur = &Section{Device: dev, Round: round, At: at.UTC(), Command: m[3], Invalid: m[4] != "", Incomplete: m[5] != ""}
				continue
			}
		}
		if cur == nil {
			continue
		}
		ln = unescapeHeader(ln)
		if b.overCap(buf.Len() + len(ln)) {
			flush() // lo leído de esta salida sí cabe; el resto del paquete ya no se lee
			return false
		}
		if int64(buf.Len()+len(ln)) > maxSection {
			truncated = true
			continue
		}
		buf.WriteString(ln)
		buf.WriteByte('\n')
	}
	flush()
	if err := sc.Err(); err != nil {
		b.Warnings = append(b.Warnings, Warn(dev, 0, "", "analyze.warn.file_error", "file", file, "error", err))
		return false
	}
	return !partial
}

// Devices lista los equipos en orden.
func (b *Bundle) Devices() []string {
	set := map[string]bool{}
	for _, s := range b.Sections {
		set[s.Device] = true
	}
	return sortedKeys(set)
}

// Rounds lista las rondas presentes (de un equipo, o de todos con "").
func (b *Bundle) Rounds(device string) []int {
	set := map[int]bool{}
	for _, s := range b.Sections {
		if device == "" || s.Device == device {
			set[s.Round] = true
		}
	}
	out := make([]int, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Ints(out)
	return out
}

func (b *Bundle) find(device string, round int, cmd string) *Section {
	for i := range b.Sections {
		s := &b.Sections[i]
		if s.Device == device && s.Round == round && s.Command == cmd {
			return s
		}
	}
	return nil
}

// matchDevice: el filtro de equipo acepta nombre, IP o cualquier parte de la carpeta.
func matchDevice(device, filter string) bool {
	return filter == "" || strings.Contains(strings.ToLower(device), strings.ToLower(filter))
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
