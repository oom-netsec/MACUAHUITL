// Package metrics arma series de tiempo (CPU, memoria e interfaces) a partir de la evidencia
// que dejó Patrol, una ronda tras otra. Lee texto con los parsers de internal/parse/iosxe.
//
// No hace: conectarse a equipos (la recolección es de Patrol), ni leer trabajos comprimidos
// (solo los .txt; con ZIP_POLICY_AT_END o PER_ROUND borra los sueltos), ni valores en vivo.
package metrics

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Límites de lectura. Se leen por streaming y solo se guardan los valores ya parseados, así que
// la memoria no crece con el texto; los topes acotan el tiempo. Pasarse es un aviso de ese
// equipo, no una falla del trabajo.
var (
	maxFile  int64 = 64 << 20 // por archivo
	maxTotal int64 = 1 << 30  // por equipo
	// readHook, si no es nil, se llama con la ruta de cada archivo antes de abrirlo (solo las pruebas).
	readHook func(path string)
)

const (
	maxManifest = 8 << 20
	maxLine     = 1 << 20
	// portLookback: cuántos archivos hacia atrás busca el estado de puertos si la última ronda
	// (que puede estar a medias en un trabajo en curso) no trae los tres comandos.
	portLookback = 3
)

// Comandos que se leen; el resto de las secciones se descarta al cargar.
var (
	cmdCPU     = []string{"show processes cpu sorted", "show processes cpu"}
	cmdMem     = []string{"show memory statistics", "show processes memory sorted", "show processes memory"}
	cmdIfaces  = "show interfaces"
	cmdVersion = "show version"
)

// section es la salida ya interpretada de un comando en una ronda. Val es lo que devolvió el
// parser (OK dice si entendió la salida); el texto no se conserva.
type section struct {
	Round int
	At    time.Time
	Cmd   string
	Val   any
	OK    bool
}

type rawDevice struct {
	Host, IP string
	Secs     []section
	Warnings []string
}

// parseFn interpreta la salida de un comando que se quiere leer.
type parseFn func(cmd, text string) (any, bool)

var (
	hdrRe   = regexp.MustCompile(`^===== (?:ronda (\d+) · )?(\S+) · (.+?)( · comando inválido)? =====$`)
	roundRe = regexp.MustCompile(`^r(\d+)_`)
)

func metricsWanted() map[string]bool {
	w := map[string]bool{cmdIfaces: true, cmdVersion: true}
	for _, c := range append(append([]string{}, cmdCPU...), cmdMem...) {
		w[c] = true
	}
	return w
}

func parseMetric(cmd, text string) (any, bool) {
	switch {
	case contains(cmdCPU, cmd):
		v, ok := iosxe.ParseCPU(text)
		return v, ok
	case contains(cmdMem, cmd):
		v, ok := iosxe.ParseMemPools(text)
		return v, ok
	case cmd == cmdIfaces:
		v, ok := iosxe.ParseInterfaces(text)
		return v, ok
	case cmd == cmdVersion:
		v, ok := iosxe.ParseVersion(text)
		return v, ok
	}
	return nil, false
}

func parseText(_, text string) (any, bool) { return text, true }

// devDir es la carpeta de un equipo dentro del trabajo y su identidad.
type devDir struct{ Dir, Host, IP string }

func (d devDir) matches(q string) bool {
	return q == "" || strings.EqualFold(q, d.IP) || strings.EqualFold(q, d.Host)
}

// listDevices lista las carpetas de equipos. El nombre y la dirección salen del manifest.json del
// trabajo (el nombre de la carpeta cambia los ":" de una IPv6 por "_" y no se puede deshacer); sin
// manifest (trabajo en curso) o con una carpeta que no está en él, se corta el nombre en el último "_".
// No sigue enlaces simbólicos.
func listDevices(dir string) ([]devDir, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	known := map[string]devDir{}
	if fi, err := os.Lstat(filepath.Join(dir, "manifest.json")); err == nil && fi.Mode().IsRegular() && fi.Size() <= maxManifest {
		if b, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil {
			var m struct {
				Devices []struct {
					Target   struct{ Address string }
					Hostname string
				} `json:"devices"`
			}
			if json.Unmarshal(b, &m) == nil {
				for _, d := range m.Devices {
					n := patrol.DeviceDir(d.Hostname, d.Target.Address)
					known[n] = devDir{Dir: n, Host: d.Hostname, IP: d.Target.Address}
				}
			}
		}
	}
	var out []devDir
	for _, e := range ents {
		if !e.IsDir() || len(regularTxt(filepath.Join(dir, e.Name()))) == 0 { // DirEntry no sigue enlaces: un symlink no es carpeta
			continue
		}
		d, ok := known[e.Name()]
		if !ok {
			d = devDir{Dir: e.Name(), Host: e.Name()}
			if i := strings.LastIndexByte(e.Name(), '_'); i > 0 {
				d.Host, d.IP = e.Name()[:i], e.Name()[i+1:]
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// loadDevice lee <dir>/<equipo>/*.txt por streaming y se queda con las secciones de want ya
// parseadas, ordenadas por ronda y hora. Un equipo con archivos pero sin esos comandos se
// conserva (sin secciones): así se puede avisar qué le falta. Con lastOnly solo lee los archivos
// más recientes y se queda con la última sección de cada comando. ok es false si no tiene .txt.
func loadDevice(dir string, dd devDir, want map[string]bool, parse parseFn, lastOnly bool) (rawDevice, bool) {
	d := rawDevice{Host: dd.Host, IP: dd.IP}
	files := regularTxt(filepath.Join(dir, dd.Dir))
	if len(files) == 0 {
		return d, false
	}
	var used int64
	latest := map[string]section{}
	if lastOnly { // de la ronda más reciente hacia atrás
		slices.Reverse(files)
		files = files[:min(len(files), portLookback)]
	}
	for _, f := range files {
		if readHook != nil {
			readHook(f.path)
		}
		if f.size > maxFile {
			d.Warnings = append(d.Warnings, fmt.Sprintf("no se leyó %s: supera %s", filepath.Base(f.path), size(maxFile)))
			continue
		}
		if used += f.size; used > maxTotal {
			d.Warnings = append(d.Warnings, fmt.Sprintf("el equipo pasa del tope de %s de texto: se dejó de leer en %s", size(maxTotal), filepath.Base(f.path)))
			break
		}
		fileLatest := map[string]section{}
		err := scanFile(f.path, roundOf(f.path), want, parse, func(s section) {
			if lastOnly {
				fileLatest[s.Cmd] = s
			} else {
				d.Secs = append(d.Secs, s)
			}
		})
		if err != nil {
			d.Warnings = append(d.Warnings, fmt.Sprintf("no se pudo leer %s: %v", filepath.Base(f.path), err))
		}
		for c, s := range fileLatest {
			if _, ok := latest[c]; !ok {
				latest[c] = s
			}
		}
		if lastOnly && len(latest) == len(want) {
			break
		}
	}
	for _, s := range latest {
		d.Secs = append(d.Secs, s)
	}
	sort.SliceStable(d.Secs, func(i, j int) bool {
		a, b := d.Secs[i], d.Secs[j]
		if a.Round != b.Round {
			return a.Round < b.Round
		}
		return a.At.Before(b.At)
	})
	return d, true
}

type txtFile struct {
	path string
	size int64
}

// regularTxt lista los .txt de una carpeta que son archivos regulares (Lstat: un enlace simbólico no
// cuenta), por ronda y nombre.
func regularTxt(dir string) []txtFile {
	names, _ := filepath.Glob(filepath.Join(dir, "*.txt"))
	var out []txtFile
	for _, n := range names {
		if fi, err := os.Lstat(n); err == nil && fi.Mode().IsRegular() {
			out = append(out, txtFile{n, fi.Size()})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := roundOf(a.path), roundOf(b.path); ra != rb {
			return ra < rb
		}
		return a.path < b.path
	})
	return out
}

func size(n int64) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d KiB", (n+1023)>>10)
}

var errTooBig = errors.New("el archivo creció más allá del tope mientras se leía")

// capReader falla en vez de truncar si el archivo (que puede estar creciendo) pasa del tope.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.n -= int64(n); c.n < 0 {
		return n, errTooBig
	}
	return n, err
}

func roundOf(path string) int {
	if m := roundRe.FindStringSubmatch(filepath.Base(path)); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// scanFile lee un archivo de Patrol sección por sección; fileRound es la ronda del nombre (r003_…),
// 0 si es consolidado. Cada sección de un comando de want se parsea al cerrarla y se entrega a emit.
func scanFile(path string, fileRound int, want map[string]bool, parse parseFn, emit func(section)) error {
	f, err := sys.OpenRegular(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(&capReader{r: f, n: maxFile})
	sc.Buffer(make([]byte, 64<<10), maxLine)
	var cur *section
	var b strings.Builder
	flush := func() {
		if cur != nil {
			cur.Val, cur.OK = parse(cur.Cmd, b.String())
			emit(*cur)
		}
		cur = nil
		b.Reset()
	}
	for sc.Scan() {
		ln := sc.Text()
		if m := hdrRe.FindStringSubmatch(ln); m != nil {
			flush()
			if m[4] != "" { // el equipo rechazó el comando: su salida no son datos
				continue
			}
			round := fileRound
			if m[1] != "" {
				round, _ = strconv.Atoi(m[1])
			}
			at, err := time.Parse(time.RFC3339, m[2])
			cmd := capture.Key(m[3])
			if err != nil || !want[cmd] {
				continue
			}
			cur = &section{Round: round, At: at, Cmd: cmd}
			continue
		}
		if cur != nil {
			b.WriteString(ln)
			b.WriteByte('\n')
		}
	}
	flush()
	return sc.Err()
}
