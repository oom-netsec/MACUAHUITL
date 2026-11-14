package forensic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/logintel"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// maxLogBytes acota lo que se lee de un archivo de log o de toda la carpeta del receptor.
const maxLogBytes = 32 << 20

// loaded es lo que salió de leer una fuente de mensajes.
type loaded struct {
	entries  []logintel.Entry
	stats    logintel.Stats
	source   srcName
	warnings []string
	warnT    []i18n.Text     // los warnings como texto de catálogo, en paralelo
	bundle   *analyze.Bundle // solo con un trabajo de Patrol
}

// bundle acepta el ID de un trabajo de esta sesión o la ruta absoluta de su carpeta.
func (s *forensicSvc) bundle(ctx context.Context, job string) (*analyze.Bundle, error) {
	dir := filepath.Clean(job)
	if !filepath.IsAbs(job) {
		j, err := s.d.Job(ctx, job)
		if err != nil {
			return nil, err
		}
		if j.Dir == "" {
			return nil, service.Err(ctx, codes.FailedPrecondition, "forensic.err.job_empty", nil)
		}
		dir = j.Dir
	}
	b, err := analyze.Load(dir)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	return b, nil
}

// srcName es el nombre de la fuente: una ruta (dato) o un texto de catálogo.
type srcName struct {
	raw string
	t   i18n.Text
}

func (n srcName) in(loc string) string {
	if n.raw != "" {
		return n.raw
	}
	return n.t.In(loc)
}

func (l *loaded) warn(key string, kv ...any) { i18n.Note(&l.warnings, &l.warnT, key, kv...) }

func (l *loaded) add(es []logintel.Entry, st logintel.Stats) {
	l.entries = append(l.entries, es...)
	l.stats.Lines += st.Lines
	l.stats.Parsed += st.Parsed
	l.stats.WithTime += st.WithTime
	l.stats.Skipped += st.Skipped
	l.stats.Truncated = l.stats.Truncated || st.Truncated
}

// readTail lee a lo más max bytes del final del archivo (lo más reciente) sin cargarlo entero;
// si recortó, descarta la línea cortada del principio.
func readTail(path string, max int64) (b []byte, cut bool, err error) {
	f, err := sys.OpenRegular(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if fi.Size() > max {
		if _, err = f.Seek(fi.Size()-max, io.SeekStart); err != nil {
			return nil, false, err
		}
		cut = true
	}
	if b, err = io.ReadAll(io.LimitReader(f, max)); err != nil {
		return nil, false, err
	}
	if cut {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b, cut, nil
}

// loadLogs lee la fuente pedida (exactamente una) y la lleva a mensajes.
func (s *forensicSvc) loadLogs(ctx context.Context, src *v1.LogSource) (*loaded, error) {
	n := 0
	for _, on := range []bool{src.GetText() != "", src.GetPath() != "", src.GetCapture(), src.GetJob() != ""} {
		if on {
			n++
		}
	}
	if n != 1 {
		return nil, service.Err(ctx, codes.InvalidArgument, "forensic.err.one_source", nil)
	}
	o := logintel.ParseOptions{Now: s.d.Now()}
	l := &loaded{}
	switch {
	case src.Text != "" || src.Path != "":
		text, err := readSource(ctx, src.Text, src.Path, maxLogBytes)
		if err != nil {
			return nil, err
		}
		if len(text) > maxLogBytes {
			text = text[:maxLogBytes]
			l.warn("forensic.warn.file_cap")
		}
		l.source = srcName{t: i18n.Tx("forensic.source.text")}
		if src.Path != "" {
			l.source = srcName{raw: src.Path}
		}
		l.add(logintel.ParseLines(text, o))
	case src.Capture:
		l.source = srcName{t: i18n.Tx("forensic.source.capture")}
		files, _ := filepath.Glob(filepath.Join(s.d.Outputs(), "syslog", "*.log"))
		sort.Sort(sort.Reverse(sort.StringSlice(files))) // los nombres llevan la hora: primero los más nuevos
		left := s.logBytes()
		if src.MaxKib > 0 {
			left = min(left, int64(src.MaxKib)<<10)
		}
		for _, f := range files {
			if left <= 0 || len(l.entries) >= logintel.MaxLines {
				l.warn("forensic.warn.more_caps")
				break
			}
			b, cut, err := readTail(f, left)
			if err != nil {
				l.warnings, l.warnT = append(l.warnings, err.Error()), append(l.warnT, i18n.Text{}) // texto del sistema
				continue
			}
			if cut {
				l.warn("forensic.warn.cap_tail", "file", filepath.Base(f))
			}
			left -= int64(len(b))
			l.add(logintel.ParseLines(string(b), o))
		}
		if len(files) == 0 {
			l.warn("forensic.warn.no_caps")
		}
	default:
		b, err := s.bundle(ctx, src.Job)
		if err != nil {
			return nil, err
		}
		l.source = srcName{t: i18n.Tx("forensic.source.job", "dir", b.Dir)}
		l.bundle = b
		seen := map[string]bool{}     // mensajes con hora: una vez por equipo, hora y texto
		prev := map[string][]string{} // textos sin hora de la ronda anterior de cada equipo
		offs := analyze.ClockOffsets(b)
		noZone := map[string]bool{}
		for _, sec := range b.Sections {
			cmd := strings.ToLower(strings.Join(strings.Fields(sec.Command), " "))
			if sec.Invalid || sec.Incomplete || !strings.HasPrefix(cmd, "show logging") {
				continue
			}
			if d := strings.ToLower(src.Device); d != "" && !strings.Contains(strings.ToLower(sec.Device), d) {
				continue
			}
			off, has := analyze.OffsetFor(offs[sec.Device], sec.Round)
			es, st := logintel.ParseLines(sec.Text, logintel.ParseOptions{Host: sec.Device, Now: sec.At, Offset: off, HasOffset: has})
			if st.Local > 0 && !has {
				noZone[sec.Device] = true
			}
			// El búfer de log se arrastra de una ronda a la siguiente: lo que ya se vio no entra otra vez.
			var untimed []string
			for _, e := range es {
				if e.At.IsZero() {
					untimed = append(untimed, e.Text)
				}
			}
			skip := overlap(prev[sec.Device], untimed)
			prev[sec.Device] = untimed
			kept := es[:0]
			for _, e := range es {
				if e.At.IsZero() {
					if skip > 0 {
						skip--
						continue
					}
				} else {
					k := fmt.Sprintf("%s\x00%d\x00%s", e.Host, e.At.UnixNano(), e.Text)
					if seen[k] {
						continue
					}
					seen[k] = true
				}
				kept = append(kept, e)
			}
			l.add(kept, st)
		}
		for _, dev := range slices.Sorted(maps.Keys(noZone)) {
			l.warn("forensic.warn.no_zone", "device", dev)
		}
		if len(l.entries) == 0 {
			l.warn("forensic.warn.no_logging")
		}
	}
	if l.stats.Truncated {
		l.warn("logintel.warn.max_lines", "max", logintel.MaxLines)
	}
	return l, nil
}

// overlap devuelve cuántos mensajes del principio de cur ya estaban al final de prev: el búfer de
// log que se arrastra de una ronda a la siguiente (KMP, lineal). Un mensaje que de verdad se
// repite fuera del solape no se pierde.
func overlap(prev, cur []string) int {
	if len(prev) == 0 || len(cur) == 0 {
		return 0
	}
	fail := make([]int, len(cur)) // fail[i]: borde más largo de cur[:i+1]
	for i, k := 1, 0; i < len(cur); i++ {
		for k > 0 && cur[i] != cur[k] {
			k = fail[k-1]
		}
		if cur[i] == cur[k] {
			k++
		}
		fail[i] = k
	}
	k := 0
	for _, p := range prev {
		for k > 0 && (k == len(cur) || p != cur[k]) {
			k = fail[k-1]
		}
		if p == cur[k] {
			k++
		}
	}
	return k
}
