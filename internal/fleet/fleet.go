// Package fleet responde preguntas del día a día sobre "la flota": la salida más
// reciente de cada equipo entre todos los trabajos de Patrol en outputs/.
// Solo lee archivos locales (cero red). Cada resultado lleva la hora de la
// evidencia que lo respalda; un formato que no se reconoce se avisa, nunca se
// convierte en un resultado vacío o falso.
//
// Los parsers viven en internal/parse/iosxe (ADR 0008).
package fleet

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Evidence es la salida de un comando tal como la guardó Patrol.
type Evidence struct {
	Text    string
	At      time.Time
	Job     string
	Invalid bool
	// Truncated: un tope de tamaño o un error de lectura cortó la salida; no es la salida completa.
	Truncated bool
}

// Dev es un equipo de la flota. Key es la carpeta <host>_<ip> de Patrol.
type Dev struct {
	Key, Name, IP string
	ev            map[string]Evidence // comando en minúsculas → lo más reciente
}

// Fleet es la última evidencia de cada equipo.
type Fleet struct {
	Dir      string
	Now      time.Time
	Devs     []*Dev
	Warnings []string
	WarnTx   []i18n.Text `json:"-"` // los avisos como texto de catálogo (mismo orden)
	lim      struct {
		bytes   int64
		entries int
		devs    bool // se alcanzó maxDevs
	}
}

// capped avisa (una vez) y dice si la carga ya alcanzó un tope total: lo leído
// hasta ahí es parcial y quien use la flota debe saberlo.
func (f *Fleet) capped(w *ws) bool {
	switch {
	case f.lim.devs:
		w.tx("fleet.warn.cap_devs", "max", maxDevs)
	case f.lim.entries > maxEntries:
		w.tx("fleet.warn.cap_entries", "max", maxEntries)
	case f.lim.bytes >= maxTotal:
		w.tx("fleet.warn.cap_bytes", "mib", maxTotal>>20)
	default:
		return false
	}
	return true
}

// Topes de lectura (variables para poder bajarlos en las pruebas).
var (
	maxFile    int64 = 64 << 20 // por archivo de ronda
	maxSection       = 8 << 20  // por salida de comando
	maxLine          = 4 << 20  // por línea

	// Topes de toda la carga, contra un zip o una carpeta hostil.
	maxTotal   int64 = 512 << 20 // bytes leídos en total
	maxEntries       = 20000     // archivos y entradas de zip revisados
	maxDevs          = 2000      // equipos
)

var headerRe = regexp.MustCompile(`^===== (?:ronda \d+ · )?(\S+) · (.*?)( · comando inválido)? =====$`)

// NewDev arma un equipo en memoria (pruebas).
func NewDev(key string, ev map[string]Evidence) *Dev {
	d := &Dev{Key: key, Name: key, ev: map[string]Evidence{}}
	if i := strings.LastIndexByte(key, '_'); i > 0 {
		d.Name, d.IP = key[:i], key[i+1:]
	}
	for c, e := range ev {
		d.ev[strings.ToLower(strings.TrimSpace(c))] = e
	}
	return d
}

// New arma una flota en memoria.
func New(devs []*Dev, now time.Time) *Fleet {
	sort.Slice(devs, func(i, j int) bool { return devs[i].Key < devs[j].Key })
	return &Fleet{Now: now, Devs: devs}
}

func (d *Dev) set(cmd string, e Evidence) {
	k := strings.ToLower(strings.TrimSpace(cmd))
	if old, ok := d.ev[k]; !ok || !e.At.Before(old.At) {
		d.ev[k] = e
	}
}

// Get busca la salida completa de un comando aceptando las abreviaturas de IOS
// ("sh ip arp"); devuelve la más reciente. Las salidas filtradas con pipe
// (`| include`) no son una tabla completa y no cuentan: ver filtered.
func (d *Dev) Get(full string) (Evidence, bool) { return d.match(full, false) }

// filtered es la salida más reciente del comando con pipe, si la hay.
func (d *Dev) filtered(full string) (Evidence, bool) { return d.match(full, true) }

func (d *Dev) match(full string, filtered bool) (Evidence, bool) {
	want := strings.Fields(strings.ToLower(full))
	var best Evidence
	found := false
	for cmd, e := range d.ev {
		base, _, piped := strings.Cut(cmd, "|")
		got := strings.Fields(base)
		if piped != filtered || len(got) != len(want) {
			continue
		}
		ok := true
		for i := range got {
			ok = ok && strings.HasPrefix(want[i], got[i])
		}
		if ok && (!found || e.At.After(best.At)) {
			best, found = e, true
		}
	}
	return best, found
}

// hostDirRe: carpeta de equipo de Patrol, <host>_<ip>. Cualquier otra carpeta
// (outputs/diag, un trabajo) no es un equipo.
var hostDirRe = regexp.MustCompile(`^.+_\d{1,3}(?:\.\d{1,3}){3}$`)

// Load lee dir: o es un trabajo de Patrol (subcarpetas <equipo>_<ip>) o una
// carpeta con varios trabajos (outputs/). Por equipo y comando gana la hora más reciente.
// extra suma otras carpetas de trabajos (los output_dir fuera de outputs/); si dir falla pero
// alguna extra se lee, sigue con ellas.
func Load(dir string, now time.Time, extra ...string) (*Fleet, error) {
	var roots []string
	var first error
	for i, r := range append([]string{dir}, extra...) {
		fi, err := os.Stat(r)
		if err == nil && !fi.IsDir() {
			err = i18n.New("fleet.err.not_dir", i18n.A("path", r))
		}
		if err != nil {
			if i == 0 {
				first = i18n.Wrap("fleet.err.load", err, nil)
			}
			continue
		}
		roots = append(roots, r)
	}
	if len(roots) == 0 {
		return nil, first
	}
	f := &Fleet{Dir: dir, Now: now}
	w := &ws{}
	devs := map[string]*Dev{}
	var readJob func(string, int)
	readJob = func(jd string, depth int) {
		ents, err := os.ReadDir(jd)
		if err != nil {
			w.tx("fleet.warn.dir_unreadable", "dir", jd, "error", err)
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			if !hostDirRe.MatchString(e.Name()) {
				if depth == 0 { // outputs/ → trabajos
					readJob(filepath.Join(jd, e.Name()), 1)
				}
				continue
			}
			files, _ := filepath.Glob(filepath.Join(jd, e.Name(), "*.txt"))
			sort.Strings(files)
			n := 0
			for _, fn := range files {
				f.lim.entries++
				if f.capped(w) {
					return
				}
				fh, err := os.Open(fn)
				if err != nil {
					w.tx("fleet.warn.system", "error", err)
					continue
				}
				n += f.parse(w, devs, e.Name(), filepath.Base(jd), fh)
				fh.Close()
			}
			if n == 0 && !f.lim.devs {
				w.tx("fleet.warn.no_outputs", "job", filepath.Base(jd), "dir", e.Name())
			}
		}
		zips, _ := filepath.Glob(filepath.Join(jd, "*.zip"))
		for _, z := range zips {
			if err := f.readZip(w, devs, z, filepath.Base(jd)); err != nil {
				w.tx("fleet.warn.file_error", "file", filepath.Base(z), "error", err)
			}
		}
	}
	for _, r := range roots {
		readJob(r, 0)
	}
	f.Warnings, f.WarnTx = w.list, w.txs
	if len(devs) == 0 {
		return nil, i18n.New("fleet.err.no_outputs", i18n.A("dir", dir))
	}
	for _, d := range devs {
		if e, ok := d.Get("show version"); ok && !rejected(e) {
			if v, ok := iosxe.ParseVersion(e.Text); ok {
				d.Name = v.Host
			}
		}
		f.Devs = append(f.Devs, d)
	}
	sort.Slice(f.Devs, func(i, j int) bool { return f.Devs[i].Key < f.Devs[j].Key })
	return f, nil
}

func (f *Fleet) readZip(w *ws, devs map[string]*Dev, p, job string) error {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		f.lim.entries++
		if f.capped(w) {
			return nil
		}
		n := path.Clean(zf.Name)
		if strings.Count(n, "/") != 1 || !strings.HasSuffix(n, ".txt") || !hostDirRe.MatchString(path.Dir(n)) {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			w.tx("fleet.warn.zip_entry", "file", filepath.Base(p), "entry", n, "error", err)
			continue
		}
		f.parse(w, devs, path.Dir(n), job, rc)
		rc.Close()
	}
	return nil
}

// capReader lee hasta maxFile bytes y anota si el archivo seguía.
type capReader struct {
	r    io.Reader
	tot  *int64
	n    int64
	over bool
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n > maxFile || *c.tot >= maxTotal {
		c.over = true
		return 0, io.EOF
	}
	if room := maxFile + 1 - c.n; int64(len(p)) > room { // un byte de más delata que el archivo no cabía
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	*c.tot += int64(n)
	return n, err
}

// readLine lee una línea completa; si pasa de maxLine descarta el resto y avisa con cut.
func readLine(rd *bufio.Reader) (ln string, cut bool, err error) {
	var sb []byte
	for {
		part, more, e := rd.ReadLine()
		if e != nil && len(sb) == 0 && len(part) == 0 {
			return "", false, e
		}
		if room := maxLine - len(sb); len(part) > room {
			part, cut = part[:room], true
		}
		sb = append(sb, part...)
		if !more || e != nil {
			return string(sb), cut, nil
		}
	}
}

// parse lee un archivo de ronda y devuelve cuántas secciones reconoció.
func (f *Fleet) parse(w *ws, devs map[string]*Dev, key, job string, r io.Reader) (sections int) {
	var d *Dev
	var cur *Evidence
	var cmd string
	var sb strings.Builder
	flush := func() {
		if cur != nil {
			cur.Text = sb.String()
			if cur.Truncated {
				w.tx("fleet.warn.output_over", "key", key, "cmd", cmd)
			}
			d.set(cmd, *cur)
		}
		cur = nil
		sb.Reset()
	}
	cr := &capReader{r: r, tot: &f.lim.bytes}
	rd := bufio.NewReaderSize(cr, 64<<10)
	for {
		ln, cut, err := readLine(rd)
		if err != nil {
			if err != io.EOF {
				w.tx("fleet.warn.read_error", "key", key, "error", err)
				if cur != nil {
					cur.Truncated = true
				}
			}
			break
		}
		if m := headerRe.FindStringSubmatch(ln); m != nil && !cut {
			if at, err := time.Parse(time.RFC3339, m[1]); err == nil {
				flush()
				if d = devs[key]; d == nil {
					if len(devs) >= maxDevs {
						f.lim.devs = true
						return sections
					}
					d = NewDev(key, nil)
					devs[key] = d
				}
				sections++
				cmd, cur = m[2], &Evidence{At: at.UTC(), Job: job, Invalid: m[3] != ""}
				continue
			}
		}
		if cur == nil {
			continue
		}
		if cut || sb.Len()+len(ln) > maxSection {
			cur.Truncated = true
			continue
		}
		sb.WriteString(ln)
		sb.WriteByte('\n')
	}
	if cr.over {
		w.tx("fleet.warn.file_cap", "key", key, "mib", maxFile>>20)
		if cur != nil {
			cur.Truncated = true
		}
	}
	flush()
	return sections
}

// newWS arranca los avisos de un resultado con los de la carga de la flota.
func (f *Fleet) newWS() *ws {
	w := &ws{}
	for i, m := range f.Warnings {
		tx := i18n.Lit(m, "") // sin su texto de catálogo, el aviso se conserva tal cual
		if i < len(f.WarnTx) && !f.WarnTx[i].Empty() {
			tx = f.WarnTx[i]
		}
		w.put(m, tx)
	}
	return w
}

// ws junta avisos sin repetirlos: el texto en español y su texto de catálogo, en el mismo orden.
type ws struct {
	seen map[string]bool
	list []string
	txs  []i18n.Text
}

// tx agrega un aviso del catálogo.
func (w *ws) tx(key string, kv ...any) {
	t := i18n.Tx(key, kv...)
	w.put(t.In(i18n.Es), t)
}

func (w *ws) put(s string, t i18n.Text) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if !w.seen[s] {
		w.seen[s] = true
		w.list = append(w.list, s)
		w.txs = append(w.txs, t)
	}
}

func rejected(e Evidence) bool {
	t := strings.TrimSpace(e.Text)
	return e.Invalid || e.Truncated || strings.HasPrefix(t, "%")
}

// read ejecuta un parser de tabla sobre la última evidencia de cmd. Sin evidencia
// devuelve ok=false sin aviso; con evidencia ilegible avisa.
func read[T any](w *ws, d *Dev, cmd string, p func(string) ([]T, bool)) ([]T, Evidence, bool) {
	e, ok := d.Get(cmd)
	if fe, fok := d.filtered(cmd); fok {
		switch {
		case !ok:
			w.tx("fleet.warn.only_filtered", "dev", d.Name, "cmd", cmd, "at", fe.At.Format("2006-01-02 15:04Z"))
		case fe.At.After(e.At):
			w.tx("fleet.warn.newer_filtered", "dev", d.Name, "cmd", cmd, "at", fe.At.Format("2006-01-02 15:04Z"), "full", e.At.Format("2006-01-02 15:04Z"))
		}
	}
	if !ok {
		return nil, e, false
	}
	if e.Truncated {
		w.tx("fleet.warn.truncated", "dev", d.Name, "cmd", cmd, "at", e.At.Format("2006-01-02 15:04Z"))
		return nil, e, false
	}
	if rejected(e) {
		w.tx("fleet.warn.rejected", "dev", d.Name, "cmd", cmd, "at", e.At.Format("2006-01-02 15:04Z"))
		return nil, e, false
	}
	rows, ok := p(e.Text)
	if !ok {
		w.tx("fleet.warn.format", "dev", d.Name, "cmd", cmd, "at", e.At.Format("2006-01-02 15:04Z"))
		return nil, e, false
	}
	return rows, e, true
}

func readOne[T any](w *ws, d *Dev, cmd string, p func(string) (T, bool)) (T, Evidence, bool) {
	var out T
	rows, e, ok := read(w, d, cmd, func(s string) ([]T, bool) {
		v, ok := p(s)
		return []T{v}, ok
	})
	if ok {
		out = rows[0]
	}
	return out, e, ok
}

// Ago escribe la antigüedad de una evidencia.
func Ago(now, at time.Time) string {
	d := now.Sub(at)
	switch {
	case d < time.Minute:
		return "ahora"
	case d < time.Hour:
		return fmt.Sprintf("hace %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("hace %d h", int(d.Hours()))
	}
	return fmt.Sprintf("hace %d d", int(d.Hours()/24))
}

// Stamp: hora de la evidencia con su antigüedad; avisa si pasa de un día.
func (f *Fleet) Stamp(at time.Time) string {
	s := at.UTC().Format("2006-01-02 15:04Z") + " (" + Ago(f.Now, at) + ")"
	if f.Now.Sub(at) > 24*time.Hour {
		s += " DATO VIEJO"
	}
	return s
}

// shortName quita el dominio de un Device ID (SW2.lab.local → sw2).
func shortName(s string) string {
	s = strings.ToLower(s)
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '('); i > 0 { // NX-OS: N9K-2(FDO123)
		s = s[:i]
	}
	return s
}
