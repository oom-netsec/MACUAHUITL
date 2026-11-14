package patrol

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
)

const stamp = "20060102-150405"

// fakeHeader: línea de la salida del equipo que podría pasar por cabecera de sección (o ya viene escapada).
var fakeHeader = regexp.MustCompile(`(?m)^(\\*===== )`)

// escapeHeaders antepone "\" a esas líneas para que un banner o un comentario del equipo no fabrique
// secciones al leer el paquete; analyze.Load quita una barra. Es reversible.
func escapeHeaders(text string) string { return fakeHeader.ReplaceAllString(text, `\${1}`) }

type Device struct {
	Host, IP, Platform string
	Port               uint16 // 0 = 22
}

// Writer escribe los outputs de un trabajo bajo <root>/<trabajo>_<AAAAMMDD-HHMMSS>/.
type Writer struct {
	dir        string
	split      SplitStrategy
	mu         sync.Mutex
	files      map[string]bool
	byRound    map[int]map[string]bool
	maskCounts map[string]int
	hostKeys   []HostKeyChange
	skipped    []int
	started    time.Time
}

// NoteSkippedRound registra una ronda omitida (bóveda cerrada o ronda anterior en curso), spec §10.4.
func (w *Writer) NoteSkippedRound(round int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.skipped = append(w.skipped, round)
}

// NoteHostKeyChange registra una llave cambiada aceptada en el Login Test, para el manifest.
func (w *Writer) NoteHostKeyChange(c HostKeyChange) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hostKeys = append(w.hostKeys, c)
}

func NewWriter(root string, s Spec, startedAt time.Time) (*Writer, error) {
	base := filepath.Join(root, dirName(s.Name)+"_"+startedAt.Format(stamp))
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("patrol: %w", err)
	}
	dir := base
	for n := 2; ; n++ { // Mkdir sin MkdirAll: si la carpeta ya existe es de otro trabajo
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || n > 1000 {
			return nil, fmt.Errorf("patrol: %w", err)
		}
		dir = fmt.Sprintf("%s-%d", base, n)
	}
	return &Writer{dir: dir, split: s.Split, files: map[string]bool{}, byRound: map[int]map[string]bool{}, maskCounts: map[string]int{}, started: startedAt}, nil
}

func (w *Writer) Dir() string { return w.dir }

// Write agrega la salida de un comando. roundStart fija el nombre del archivo de la ronda.
func (w *Writer) Write(dev Device, round int, roundStart time.Time, out platform.Output, applyMask bool) error {
	text := out.Text
	if applyMask {
		var counts map[string]int
		text, counts = mask.Apply(dev.Platform, text)
		w.mu.Lock()
		for k, v := range counts {
			w.maskCounts[k] += v
		}
		w.mu.Unlock()
	}
	text = escapeHeaders(text)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	note := ""
	if out.Invalid {
		note = " · comando inválido"
	}
	if out.Incomplete {
		note += " · incompleto" // salida parcial de un comando cortado o fallido; los lectores no la toman por completa
	}
	devDir := DeviceDirOf(dev.Host, Target{Address: dev.IP, Port: dev.Port})
	var rel, header string
	if w.split == SplitConsolidated {
		rel = filepath.Join(devDir, dirName(dev.Host)+".txt")
		header = fmt.Sprintf("===== ronda %d · %s · %s%s =====\n", round, out.Started.UTC().Format(time.RFC3339), out.Command, note)
	} else {
		rel = filepath.Join(devDir, fmt.Sprintf("r%03d_%s.txt", round, roundStart.Format(stamp)))
		header = fmt.Sprintf("===== %s · %s%s =====\n", out.Started.UTC().Format(time.RFC3339), out.Command, note)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(filepath.Join(w.dir, devDir), 0o700); err != nil {
		return fmt.Errorf("patrol: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(w.dir, rel), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("patrol: %w", err)
	}
	if _, err := f.WriteString(header + text); err != nil {
		f.Close()
		return fmt.Errorf("patrol: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("patrol: %w", err)
	}
	w.files[rel] = true
	if w.byRound[round] == nil {
		w.byRound[round] = map[string]bool{}
	}
	w.byRound[round][rel] = true
	return nil
}

// DeviceDir es la carpeta de un equipo dentro del trabajo; capture la usa para leer la evidencia.
func DeviceDir(host, ip string) string { return dirName(host + "_" + ip) }

// DeviceDirOf es DeviceDir de un destino: el puerto entra en el nombre solo cuando no es 22 (así no cambian las
// carpetas de siempre y dos equipos con la misma dirección y distinto puerto no se mezclan).
func DeviceDirOf(host string, t Target) string {
	if p := EffectivePort(t.Port); p != 22 {
		return DeviceDir(host, t.Address+":"+strconv.Itoa(int(p)))
	}
	return DeviceDir(host, t.Address)
}

var dirWithPort = regexp.MustCompile(`^(.+)_(\d{1,3}(?:\.\d{1,3}){3})_\d{1,5}$`)

// SplitDeviceDir saca equipo y dirección de la carpeta de un equipo (<equipo>_<dirección>, o con «_<puerto>»
// al final cuando el puerto no es 22 y la dirección es IPv4); sin puerto corta en el último «_» como siempre.
// La dirección sale sin el puerto.
func SplitDeviceDir(name string) (host, ip string) {
	if m := dirWithPort.FindStringSubmatch(name); m != nil {
		return m[1], m[2]
	}
	if i := strings.LastIndexByte(name, '_'); i > 0 {
		return name[:i], name[i+1:]
	}
	return name, ""
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (w *Writer) Files() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return sorted(w.files)
}

func (w *Writer) roundFiles(round int) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return sorted(w.byRound[round])
}

func (w *Writer) masks() map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]int{}
	for k, v := range w.maskCounts {
		out[k] = v
	}
	return out
}
