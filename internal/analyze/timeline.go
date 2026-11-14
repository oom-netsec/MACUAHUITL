package analyze

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/msgkb"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
)

// Event es un punto en la línea de tiempo. Source: patrol, hallazgo,
// log-equipo, syslog, auditoria o pcap. Device vacío = evento global.
type Event struct {
	At       time.Time `json:"at"`
	Source   string    `json:"source"`
	Device   string    `json:"device,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Text     string    `json:"text"`
	Note     string    `json:"note,omitempty"`
	TextTx   i18n.Text `json:"-"` // Text y Note como texto de catálogo (solo los que arma la app)
	NoteTx   i18n.Text `json:"-"`
	// KB es la ficha de la base de mensajes (internal/msgkb) del mnemónico del evento: qué significa y qué hacer.
	KB string `json:"kb,omitempty"`
}

// syslogSev traduce la severidad syslog (0-7) a la escala de los hallazgos.
var syslogSev = []string{"critica", "critica", "critica", "alta", "media", "baja", "info", "info"}

func isLogging(cmd string) bool {
	c := normCmd(cmd)
	return c == "show logging" || strings.HasPrefix(c, "show logging |")
}

// BundleEvents saca del paquete las rondas, los hallazgos y los mensajes de
// show logging con su hora. Un mismo mensaje repetido en rondas siguientes
// (el búfer se arrastra) entra una sola vez.
func BundleEvents(b *Bundle, findings []Finding) ([]Event, []Warning) {
	var evs []Event
	var warns []Warning
	type key struct {
		dev   string
		round int
	}
	first := map[key]time.Time{}
	count := map[key]int{}
	seen := map[string]bool{}
	offsets := ClockOffsets(b)
	noRef := map[string]bool{}
	for _, s := range b.Sections {
		k := key{s.Device, s.Round}
		if t, ok := first[k]; !ok || s.At.Before(t) {
			first[k] = s.At
		}
		count[k]++
		if !isLogging(s.Command) || s.Invalid || s.Incomplete {
			continue
		}
		uptime := 0
		for _, ln := range lines(s.Text) {
			if iosxe.LogUptimeStamp(ln) {
				uptime++
				continue
			}
			off, hasOff := OffsetFor(offsets[s.Device], s.Round)
			e, local, ok := logEvent(ln, s.At, off, hasOff)
			if !ok || seen[s.Device+"\x00"+ln] {
				continue
			}
			noRef[s.Device] = noRef[s.Device] || local && !hasOff
			seen[s.Device+"\x00"+ln] = true
			e.Device = s.Device
			evs = append(evs, e)
		}
		if uptime > 0 {
			warns = append(warns, Warn(s.Device, s.Round, s.Command, "analyze.warn.uptime_stamps", "n", uptime))
		}
	}
	for _, dev := range sortedKeys(noRef) {
		if noRef[dev] {
			warns = append(warns, Warn(dev, 0, "show logging", "analyze.warn.log_no_zone"))
		}
	}
	for k, at := range first {
		t := i18n.Tx("analyze.event.round", "round", k.round, "n", count[k])
		evs = append(evs, Event{At: at, Source: "patrol", Device: k.dev, Text: t.In(i18n.Es), TextTx: t})
	}
	for _, f := range findings {
		t := i18n.Tx("analyze.event.finding", "round", f.Round).With("title", f.TitleTx).With("detail", f.DetailTx)
		evs = append(evs, Event{At: f.At, Source: "hallazgo", Device: f.Device, Severity: f.Severity, Text: t.In(i18n.Es), TextTx: t})
	}
	return evs, warns
}

// ClockOffsets: por equipo y ronda, desfase entre la hora local que muestra
// show clock detail y la hora UTC de la ronda, redondeado a 15 min.
func ClockOffsets(b *Bundle) map[string]map[int]time.Duration {
	out := map[string]map[int]time.Duration{}
	for _, s := range b.Sections {
		if normCmd(s.Command) != "show clock detail" || s.Invalid || s.Incomplete {
			continue
		}
		if local, ok := iosxe.ParseClock(s.Text); ok {
			if out[s.Device] == nil {
				out[s.Device] = map[int]time.Duration{}
			}
			out[s.Device][s.Round] = local.Sub(s.At).Round(15 * time.Minute)
		}
	}
	return out
}

// OffsetFor prefiere el reloj de la misma ronda; si falta, el de la ronda más baja del equipo.
func OffsetFor(m map[int]time.Duration, round int) (time.Duration, bool) {
	if d, ok := m[round]; ok {
		return d, true
	}
	best := 0
	for r := range m {
		if best == 0 || r < best {
			best = r
		}
	}
	d, ok := m[best]
	return d, ok
}

func fmtOffset(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	return fmt.Sprintf("%s%02d:%02d", sign, d/time.Hour, (d%time.Hour)/time.Minute)
}

// kbNote resume la ficha de la base de mensajes del mnemónico de la línea ("" si no lo conoce).
func kbNote(text string) string {
	kb, err := msgkb.Default()
	if err != nil {
		return ""
	}
	e, ok := kb.ForLine(text)
	if !ok {
		return ""
	}
	return e.ID + ": " + e.Meaning + " Acción: " + e.Action
}

// logEvent fecha una línea del log del equipo. Sin año, toma el de la ronda (y
// el anterior si quedaría más de un día en el futuro). Si la línea no dice UTC/GMT
// es hora local: con desfase conocido (show clock detail) se pasa a UTC; sin él se
// toma como UTC. local indica que la línea dependía de la zona del equipo.
func logEvent(ln string, ref time.Time, off time.Duration, hasOff bool) (e Event, local, ok bool) {
	l, ok := iosxe.ParseLogLine(ln)
	if !ok {
		return Event{}, false, false
	}
	year := ref.Year()
	if l.Year != 0 {
		year = l.Year
	}
	at, err := l.At(year)
	if err != nil {
		return Event{}, false, false
	}
	local = l.Zone != "UTC" && l.Zone != "GMT"
	if !local || !hasOff {
		off = 0
	}
	if l.Year == 0 && at.After(ref.Add(off).Add(24*time.Hour)) {
		at = at.AddDate(-1, 0, 0)
	}
	at = at.Add(-off)
	var notes []i18n.Text
	if l.Unsynced {
		notes = append(notes, i18n.Tx("analyze.event.clock_unsync"))
	}
	switch {
	case local && hasOff && off != 0:
		notes = append(notes, i18n.Tx("analyze.event.local_to_utc", "offset", fmtOffset(off)))
	case local && !hasOff && l.Zone != "":
		notes = append(notes, i18n.Tx("analyze.event.local_raw", "zone", l.Zone))
	}
	note := i18n.Join("; ", notes...)
	e = Event{At: at, Source: "log-equipo", Text: l.Text, Note: note.In(i18n.Es), NoteTx: note, KB: kbNote(l.Text)}
	if l.Severity >= 0 {
		e.Severity = syslogSev[l.Severity]
	}
	return e, local, true
}

var priRe = regexp.MustCompile(`^<(\d{1,3})>`)

// SyslogEvents lee un archivo del receptor syslog (internal/diag/syslogd):
// "<RFC3339> <origen> <mensaje crudo>" por línea. Con from/to no cero, descarta al
// leer lo que cae fuera de [from, to].
func SyslogEvents(r io.Reader, name string, from, to time.Time) ([]Event, []Warning) {
	var evs []Event
	bad := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), " ", 3)
		if len(f) < 3 {
			bad++
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, f[0])
		if err != nil {
			bad++
			continue
		}
		host := f[1]
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		if !from.IsZero() && at.Before(from) || !to.IsZero() && at.After(to) {
			continue
		}
		e := Event{At: at.UTC(), Source: "syslog", Device: strings.Trim(host, "[]"), Text: f[2], KB: kbNote(f[2])}
		if m := priRe.FindStringSubmatch(f[2]); m != nil {
			n, _ := strconv.Atoi(m[1])
			e.Severity = syslogSev[n%8]
		}
		evs = append(evs, e)
	}
	var warns []Warning
	if bad > 0 {
		warns = append(warns, Warn("", 0, "", "analyze.warn.syslog_bad_lines", "name", name, "n", bad))
	}
	if err := sc.Err(); err != nil {
		warns = append(warns, Warn("", 0, "", "analyze.warn.file_error", "file", name, "error", err))
	}
	return evs, warns
}

var syslogNameRe = regexp.MustCompile(`syslog_(\d{8}-\d{6})\.log$`)

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// SyslogFiles lee los archivos del receptor syslog quedándose con [from, to].
// Omite sin abrir los que empezaron después de to (el nombre lleva la hora local
// del núcleo al abrir la escucha) y deja de leer al pasar maxBytes en total.
func SyslogFiles(paths []string, from, to time.Time, maxBytes int64) ([]Event, []Warning) {
	var evs []Event
	var warns []Warning
	ps := append([]string(nil), paths...)
	sort.Strings(ps)
	left := maxBytes
	for _, p := range ps {
		if m := syslogNameRe.FindStringSubmatch(p); m != nil {
			if start, err := time.ParseInLocation("20060102-150405", m[1], time.Local); err == nil && start.After(to) {
				continue
			}
		}
		f, err := os.Open(p)
		if err != nil {
			warns = append(warns, Warn("", 0, "", "analyze.warn.system", "error", err))
			continue
		}
		cr := &countReader{r: f}
		e, w := SyslogEvents(io.LimitReader(cr, left), filepath.Base(p), from, to)
		evs, warns = append(evs, e...), append(warns, w...)
		left -= cr.n
		more := false
		if left <= 0 {
			n, _ := f.Read(make([]byte, 1))
			more = n > 0
		}
		f.Close()
		if left <= 0 {
			if more {
				warns = append(warns, Warn("", 0, "", "analyze.warn.syslog_cap", "mib", maxBytes>>20, "file", filepath.Base(p)))
			}
			break
		}
	}
	return evs, warns
}

// Resolve pone el nombre de carpeta del equipo a los eventos que solo traen su IP.
func (b *Bundle) Resolve(evs []Event) {
	devs := b.Devices()
	for i := range evs {
		ip := strings.ReplaceAll(evs[i].Device, ":", "_") // dirName de patrol cambia ':' por '_'
		for _, d := range devs {
			if ip != "" && strings.HasSuffix(d, "_"+ip) {
				evs[i].Device = d
				break
			}
		}
	}
}

// AuditEvents lee la exportación JSON por línea de la auditoría.
func AuditEvents(r io.Reader) []Event {
	var evs []Event
	dec := json.NewDecoder(r)
	for {
		var rec audit.Record
		if err := dec.Decode(&rec); err != nil {
			break // fin o línea dañada: lo leído hasta ahí sirve
		}
		note := i18n.Tx("analyze.event.by", "actor", rec.Actor)
		evs = append(evs, Event{At: rec.At.UTC(), Source: "auditoria", Text: strings.TrimSpace(fmt.Sprintf("%s %s %s", rec.Action, rec.Target, rec.Detail)), Note: note.In(i18n.Es), NoteTx: note})
	}
	return evs
}

// PcapEvents saca de un reporte pcapan los eventos con hora: RST, retransmisiones,
// DNS lento, con error o sin respuesta, e ICMP inalcanzable o TTL excedido.
func PcapEvents(rep pcapan.Report) []Event {
	var evs []Event
	add := func(at time.Time, sev, key string, kv ...any) {
		t := i18n.Tx(key, kv...)
		evs = append(evs, Event{At: at.UTC(), Source: "pcap", Severity: sev, Text: t.In(i18n.Es), TextTx: t})
	}
	for _, e := range rep.TCP.Events {
		key := "analyze.event.rst"
		if e.Kind != "rst" {
			key = "analyze.event.retransmit"
		}
		add(e.At, "media", key, "client", e.Client, "server", e.Server)
	}
	for _, q := range rep.DNS.Slow {
		add(q.At, "media", "analyze.event.dns_slow", "name", q.Name, "type", q.Type, "latency", q.Latency, "client", q.Client, "server", q.Server)
	}
	for _, q := range rep.DNS.Errors {
		add(q.At, "baja", "analyze.event.dns_error", "rcode", q.RCode, "name", q.Name, "type", q.Type)
	}
	for _, q := range rep.DNS.Unanswered {
		add(q.At, "media", "analyze.event.dns_none", "name", q.Name, "type", q.Type, "client", q.Client, "server", q.Server)
	}
	for _, x := range rep.ICMP.Unreachable {
		add(x.At, "media", "analyze.event.icmp_unreach", "code", x.Code, "from", x.From, "target", x.Target)
	}
	for _, x := range rep.ICMP.TTLExceeded {
		add(x.At, "baja", "analyze.event.icmp_ttl", "from", x.From, "target", x.Target)
	}
	return evs
}

type TimelineOptions struct {
	Device string        // los eventos globales (sin equipo) siempre quedan
	Around time.Time     // cero = sin ventana
	Window time.Duration // ± alrededor de Around
}

// Timeline filtra y ordena los eventos por hora.
func Timeline(evs []Event, o TimelineOptions) []Event {
	out := []Event{}
	for _, e := range evs {
		if e.Device != "" && !matchDevice(e.Device, o.Device) {
			continue
		}
		if !o.Around.IsZero() && (e.At.Before(o.Around.Add(-o.Window)) || e.At.After(o.Around.Add(o.Window))) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Span es el intervalo que cubren las salidas del paquete.
func (b *Bundle) Span() (from, to time.Time) {
	for _, s := range b.Sections {
		if from.IsZero() || s.At.Before(from) {
			from = s.At
		}
		if s.At.After(to) {
			to = s.At
		}
	}
	return from, to
}

type TimelineReport struct {
	Dir      string    `json:"dir"`
	Around   time.Time `json:"around,omitempty"`
	Window   string    `json:"window,omitempty"`
	Events   []Event   `json:"events"`
	Warnings []Warning `json:"warnings"`
}

// Text es el resumen legible para mctl, en español.
func (r TimelineReport) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el resumen en el idioma pedido (con es, el de siempre).
func (r TimelineReport) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	fmt.Fprintf(&b, "%s\n", r.Dir)
	if !r.Around.IsZero() {
		fmt.Fprintf(&b, "%s\n", m("analyze.text.window", "around", r.Around.Format(time.RFC3339), "window", r.Window))
	}
	for _, e := range r.Events {
		dev := e.Device
		if dev == "" {
			dev = "-"
		}
		sev := ""
		if e.Severity != "" {
			sev = "[" + m("analyze.sev."+e.Severity) + "] "
		}
		fmt.Fprintf(&b, "%s  %-10s %-20s %s%s", e.At.Format("2006-01-02 15:04:05.000"), e.Source, dev, sev, e.Text)
		if e.Note != "" {
			fmt.Fprintf(&b, "  (%s)", e.Note)
		}
		if e.KB != "" {
			fmt.Fprintf(&b, "  [%s]", e.KB)
		}
		b.WriteString("\n")
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "%s\n", m("analyze.text.warning", "message", w.in(loc)))
	}
	return b.String()
}
