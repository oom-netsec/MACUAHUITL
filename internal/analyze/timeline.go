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
		if !isLogging(s.Command) || s.Invalid {
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
			warns = append(warns, Warning{Device: s.Device, Round: s.Round, Command: s.Command,
				Msg: fmt.Sprintf("%d mensaje(s) con marca de uptime, sin hora absoluta: se omiten (configura service timestamps log datetime msec)", uptime)})
		}
	}
	for _, dev := range sortedKeys(noRef) {
		if noRef[dev] {
			warns = append(warns, Warning{Device: dev, Command: "show logging",
				Msg: "hora del log sin referencia de zona: sin show clock detail se toma como UTC (recolecta show clock detail o usa show-timezone)"})
		}
	}
	for k, at := range first {
		evs = append(evs, Event{At: at, Source: "patrol", Device: k.dev, Text: fmt.Sprintf("ronda %d: %d comando(s)", k.round, count[k])})
	}
	for _, f := range findings {
		evs = append(evs, Event{At: f.At, Source: "hallazgo", Device: f.Device, Severity: f.Severity, Text: fmt.Sprintf("%s (ronda %d): %s", f.Title, f.Round, f.Detail)})
	}
	return evs, warns
}

// ClockOffsets: por equipo y ronda, desfase entre la hora local que muestra
// show clock detail y la hora UTC de la ronda, redondeado a 15 min.
func ClockOffsets(b *Bundle) map[string]map[int]time.Duration {
	out := map[string]map[int]time.Duration{}
	for _, s := range b.Sections {
		if normCmd(s.Command) != "show clock detail" || s.Invalid {
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
	var notes []string
	if l.Unsynced {
		notes = append(notes, "reloj sin sincronizar en el equipo")
	}
	switch {
	case local && hasOff && off != 0:
		notes = append(notes, "hora local del equipo pasada a UTC con show clock detail (desfase "+fmtOffset(off)+")")
	case local && !hasOff && l.Zone != "":
		notes = append(notes, "hora local del equipo ("+l.Zone+"), sin convertir a UTC")
	}
	e = Event{At: at, Source: "log-equipo", Text: l.Text, Note: strings.Join(notes, "; "), KB: kbNote(l.Text)}
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
		warns = append(warns, Warning{Msg: fmt.Sprintf("%s: %d línea(s) sin el formato del receptor syslog", name, bad)})
	}
	if err := sc.Err(); err != nil {
		warns = append(warns, Warning{Msg: fmt.Sprintf("%s: %v", name, err)})
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
			warns = append(warns, Warning{Msg: err.Error()})
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
				warns = append(warns, Warning{Msg: fmt.Sprintf("syslog: tope de %d MiB leído; el resto de %s y los archivos siguientes se omiten", maxBytes>>20, filepath.Base(p))})
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
		evs = append(evs, Event{At: rec.At.UTC(), Source: "auditoria", Text: strings.TrimSpace(fmt.Sprintf("%s %s %s", rec.Action, rec.Target, rec.Detail)), Note: "por " + rec.Actor})
	}
	return evs
}

// PcapEvents saca de un reporte pcapan los eventos con hora: RST, retransmisiones,
// DNS lento, con error o sin respuesta, e ICMP inalcanzable o TTL excedido.
func PcapEvents(rep pcapan.Report) []Event {
	var evs []Event
	add := func(at time.Time, sev, text string) {
		evs = append(evs, Event{At: at.UTC(), Source: "pcap", Severity: sev, Text: text})
	}
	for _, e := range rep.TCP.Events {
		kind := "RST"
		if e.Kind != "rst" {
			kind = "retransmisión"
		}
		add(e.At, "media", fmt.Sprintf("%s %s → %s", kind, e.Client, e.Server))
	}
	for _, q := range rep.DNS.Slow {
		add(q.At, "media", fmt.Sprintf("DNS lento %s %s (%v) %s → %s", q.Name, q.Type, q.Latency, q.Client, q.Server))
	}
	for _, q := range rep.DNS.Errors {
		add(q.At, "baja", fmt.Sprintf("DNS %s %s %s", q.RCode, q.Name, q.Type))
	}
	for _, q := range rep.DNS.Unanswered {
		add(q.At, "media", fmt.Sprintf("DNS sin respuesta %s %s %s → %s", q.Name, q.Type, q.Client, q.Server))
	}
	for _, x := range rep.ICMP.Unreachable {
		add(x.At, "media", fmt.Sprintf("ICMP inalcanzable (código %d) de %s para %s", x.Code, x.From, x.Target))
	}
	for _, x := range rep.ICMP.TTLExceeded {
		add(x.At, "baja", fmt.Sprintf("ICMP TTL excedido de %s para %s", x.From, x.Target))
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

// Text es el resumen legible para mctl.
func (r TimelineReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.Dir)
	if !r.Around.IsZero() {
		fmt.Fprintf(&b, "ventana: %s ± %s\n", r.Around.Format(time.RFC3339), r.Window)
	}
	for _, e := range r.Events {
		dev := e.Device
		if dev == "" {
			dev = "-"
		}
		sev := ""
		if e.Severity != "" {
			sev = "[" + sevLabel[e.Severity] + "] "
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
		fmt.Fprintf(&b, "aviso: %s\n", w.String())
	}
	return b.String()
}
