package fleet

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Umbrales del tablero matutino.
const (
	CPUMax       = 80.0 // %
	MemUsedMax   = 90.0 // % del pool de procesador
	FlashUsedMax = 90.0 // %
	RebootUnder  = 24 * time.Hour
)

// ---- salud de interfaces ----

type Problem struct {
	Kind     string `json:"kind"` // err-disabled, half-duplex, crc, input_errors, output_errors, runts, giants, drops
	Value    int64  `json:"value,omitempty"`
	Evidence string `json:"evidence"`
	// EvidenceTx es la evidencia como texto de catálogo cuando la arma la app (no cuando es salida del equipo).
	EvidenceTx i18n.Text `json:"-"`
}

type IfIssue struct {
	Device   string    `json:"device"`
	Port     string    `json:"port"`
	Severity string    `json:"severity"` // critica, alta, media, baja
	Problems []Problem `json:"problems"`
	Source   string    `json:"source"`
	At       time.Time `json:"at"`
}

type HealthResult struct {
	Issues     []IfIssue      `json:"issues"`
	Devices    int            `json:"devices"`
	Checked    map[string]int `json:"checked"` // equipos con dato por fuente: status, counters
	Warnings   []string       `json:"warnings"`
	WarningsTx []i18n.Text    `json:"-"`
}

var sevRank = map[string]int{"critica": 4, "alta": 3, "media": 2, "baja": 1}

func countSev(kind string, n int64) string {
	switch {
	case kind == "drops" && n >= 1000, n >= 1000:
		return "alta"
	case kind == "drops":
		return "baja"
	}
	return "media"
}

// Health lista solo las interfaces con problema, de la más grave a la menos.
// Los contadores son acumulados desde el último clear counters.
func (f *Fleet) Health() HealthResult {
	w := f.newWS()
	res := HealthResult{Devices: len(f.Devs), Checked: map[string]int{}}
	for _, d := range f.Devs {
		issues := map[string]*IfIssue{}
		get := func(port, src string, at time.Time) *IfIssue {
			if issues[port] == nil {
				issues[port] = &IfIssue{Device: d.Name, Port: port, Source: src, At: at}
			}
			return issues[port]
		}
		st, e, ok := read(w, d, "show interfaces status", iosxe.ParseIfStatus)
		if ok {
			res.Checked["status"]++
		} else {
			w.tx("fleet.warn.no_status", "dev", d.Name)
		}
		if ok {
			for _, r := range st {
				switch {
				case strings.Contains(r.Status, "err-disabled"):
					i := get(r.Port, "show interfaces status", e.At)
					i.Problems = append(i.Problems, Problem{Kind: "err-disabled", Evidence: fmt.Sprintf("%s %s %s", r.Port, r.Name, r.Status)})
				case strings.Contains(r.Duplex, "half") && r.Status == "connected":
					i := get(r.Port, "show interfaces status", e.At)
					p := Problem{Kind: "half-duplex"}
					i18n.Put(&p.Evidence, &p.EvidenceTx, "fleet.evidence.half", "port", r.Port, "duplex", r.Duplex, "speed", r.Speed)
					i.Problems = append(i.Problems, p)
				}
			}
		}
		ifs, e, ok := read(w, d, "show interfaces", iosxe.ParseInterfaces)
		if ok {
			res.Checked["counters"]++
		} else {
			w.tx("fleet.warn.no_counters", "dev", d.Name)
		}
		if ok {
			for _, r := range ifs {
				var ps []Problem
				add := func(kind string, n int64) {
					if n > 0 {
						ps = append(ps, Problem{Kind: kind, Value: n, Evidence: strings.TrimSpace(r.Evidence[kind])})
					}
				}
				add("crc", r.CRC)
				add("input_errors", r.InErrors)
				add("output_errors", r.OutErrors)
				add("runts", r.Runts)
				add("giants", r.Giants)
				add("drops", r.OutDrops)
				if r.Duplex == "Half" && !r.AdminDown {
					ps = append(ps, Problem{Kind: "half-duplex", Evidence: strings.TrimSpace(r.Evidence["duplex"])})
				}
				if len(ps) > 0 {
					i := get(r.Name, "show interfaces", e.At)
					for _, p := range ps {
						dup := false
						for _, q := range i.Problems {
							dup = dup || q.Kind == p.Kind
						}
						if !dup {
							i.Problems = append(i.Problems, p)
						}
					}
					i.Source, i.At = "show interfaces", e.At
				}
			}
		}
		for _, i := range issues {
			for _, p := range i.Problems {
				s := "media"
				switch p.Kind {
				case "err-disabled":
					s = "critica"
				case "half-duplex":
					s = "alta"
				default:
					s = countSev(p.Kind, p.Value)
				}
				if sevRank[s] > sevRank[i.Severity] {
					i.Severity = s
				}
			}
			res.Issues = append(res.Issues, *i)
		}
	}
	total := func(i IfIssue) (n int64) {
		for _, p := range i.Problems {
			n += p.Value
		}
		return
	}
	sort.Slice(res.Issues, func(a, b int) bool {
		x, y := res.Issues[a], res.Issues[b]
		if sevRank[x.Severity] != sevRank[y.Severity] {
			return sevRank[x.Severity] > sevRank[y.Severity]
		}
		if total(x) != total(y) {
			return total(x) > total(y)
		}
		return x.Device+x.Port < y.Device+y.Port
	})
	res.Warnings, res.WarningsTx = w.list, w.txs
	return res
}

// ---- tablero matutino ----

type Row struct {
	Device string    `json:"device"`
	Check  string    `json:"check"` // cpu, ntp, reboot, memory, flash
	Value  string    `json:"value"`
	Detail string    `json:"detail,omitempty"`
	Source string    `json:"source"`
	At     time.Time `json:"at"`
	// ValueTx y DetailTx son Value y Detail como texto de catálogo cuando traen palabras de la app.
	ValueTx  i18n.Text `json:"-"`
	DetailTx i18n.Text `json:"-"`
}

type SummaryResult struct {
	Rows       []Row          `json:"rows"`
	Checked    map[string]int `json:"checked"` // equipos con dato por revisión
	Devices    int            `json:"devices"`
	Warnings   []string       `json:"warnings"`
	WarningsTx []i18n.Text    `json:"-"`
}

func (f *Fleet) Summary() SummaryResult {
	w := f.newWS()
	res := SummaryResult{Devices: len(f.Devs), Checked: map[string]int{}}
	for _, d := range f.Devs {
		if c, e, ok := readOne(w, d, "show processes cpu", iosxe.ParseCPU); ok {
			res.Checked["cpu"]++
			if m := max(c.FiveSec, c.OneMin, c.FiveMin); m > CPUMax {
				res.Rows = append(res.Rows, Row{Device: d.Name, Check: "cpu", Value: fmt.Sprintf("%.0f %%", m), Detail: fmt.Sprintf("5 s %.0f %% · 1 min %.0f %% · 5 min %.0f %%", c.FiveSec, c.OneMin, c.FiveMin), Source: "show processes cpu", At: e.At})
			}
		}
		if n, e, ok := readOne(w, d, "show ntp status", iosxe.ParseNTP); ok {
			res.Checked["ntp"]++
			if !n.Synced {
				row := Row{Device: d.Name, Check: "ntp", Detail: n.Line, Source: "show ntp status", At: e.At}
				i18n.Put(&row.Value, &row.ValueTx, "fleet.value.ntp_unsynced")
				res.Rows = append(res.Rows, row)
			}
		}
		if v, e, ok := readOne(w, d, "show version", iosxe.ParseVersion); ok {
			res.Checked["reboot"]++
			if v.Uptime < RebootUnder {
				row := Row{Device: d.Name, Check: "reboot", Value: "uptime " + v.Uptime.Round(time.Minute).String(), Source: "show version", At: e.At}
				i18n.Put(&row.Detail, &row.DetailTx, "fleet.detail.reboot")
				res.Rows = append(res.Rows, row)
			}
		}
		if m, e, ok := readOne(w, d, "show processes memory", iosxe.ParseMem); ok {
			res.Checked["memory"]++
			if used := 100 * float64(m.Total-m.Free) / float64(m.Total); used > MemUsedMax {
				row := Row{Device: d.Name, Check: "memory", Source: "show processes memory", At: e.At}
				i18n.Put(&row.Value, &row.ValueTx, "fleet.value.used", "pct", fmt.Sprintf("%.0f", used))
				i18n.Put(&row.Detail, &row.DetailTx, "fleet.detail.mem_free", "free", Bytes(m.Free), "total", Bytes(m.Total))
				res.Rows = append(res.Rows, row)
			}
		}
		for _, fs := range flashes(w, d) {
			res.Checked["flash"]++
			if used := fs.UsedPct(); used > FlashUsedMax {
				row := Row{Device: d.Name, Check: "flash", Source: "dir " + fs.FS, At: fs.At}
				i18n.Put(&row.Value, &row.ValueTx, "fleet.value.used", "pct", fmt.Sprintf("%.0f", used))
				i18n.Put(&row.Detail, &row.DetailTx, "fleet.detail.flash_free", "free", Bytes(fs.Free), "total", Bytes(fs.Total))
				res.Rows = append(res.Rows, row)
			}
		}
	}
	res.Warnings, res.WarningsTx = w.list, w.txs
	return res
}

// ---- flash y DRAM ----

type Flash struct {
	Device string    `json:"device"`
	FS     string    `json:"fs"`
	Total  int64     `json:"total"`
	Free   int64     `json:"free"`
	Used   float64   `json:"used_pct"`
	Fits   *bool     `json:"fits,omitempty"` // solo si se pidió un tamaño
	At     time.Time `json:"at"`
}

func (x Flash) UsedPct() float64 { return 100 * float64(x.Total-x.Free) / float64(x.Total) }

func flashes(w *ws, d *Dev) []Flash {
	var out []Flash
	for _, fs := range []string{"flash:", "bootflash:"} {
		if r, e, ok := readOne(w, d, "dir "+fs, iosxe.ParseDir); ok {
			x := Flash{Device: d.Name, FS: fs, Total: r.Total, Free: r.Free, At: e.At}
			x.Used = x.UsedPct()
			out = append(out, x)
		}
	}
	return out
}

type DRAM struct {
	Device   string    `json:"device"`
	Total    int64     `json:"total"`
	PoolFree int64     `json:"pool_free,omitempty"` // libre del pool de procesador
	PoolUsed float64   `json:"pool_used_pct,omitempty"`
	At       time.Time `json:"at"`
}

type CapacityResult struct {
	Need        int64       `json:"need,omitempty"`
	Flash       []Flash     `json:"flash"`
	DRAM        []DRAM      `json:"dram"`
	FlashNoData []string    `json:"flash_no_data"` // equipos sin dir flash:/bootflash: utilizable
	DRAMNoData  []string    `json:"dram_no_data"`
	Devices     int         `json:"devices"`
	Warnings    []string    `json:"warnings"`
	WarningsTx  []i18n.Text `json:"-"`
}

var sizeRe = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?$`)

// ParseSize entiende 500M, 1.2G, 2048K, 1000000 (potencias de 1024).
func ParseSize(s string) (int64, error) {
	m := sizeRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("tamaño %q inválido: usa 800M, 1.2G, 500000", s)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	mul := map[string]float64{"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}[m[2]]
	return int64(v * mul), nil
}

// Capacity: flash libre y DRAM de la flota; con need (>0) indica a quién le cabe.
func (f *Fleet) Capacity(need int64) CapacityResult {
	w := f.newWS()
	res := CapacityResult{Need: need, Devices: len(f.Devs)}
	for _, d := range f.Devs {
		fl := flashes(w, d)
		if len(fl) == 0 {
			res.FlashNoData = append(res.FlashNoData, d.Name)
			w.tx("fleet.warn.no_flash", "dev", d.Name)
		}
		for _, x := range fl {
			if need > 0 {
				fit := x.Free >= need
				x.Fits = &fit
			}
			res.Flash = append(res.Flash, x)
		}
		if v, e, ok := readOne(w, d, "show version", iosxe.ParseVersion); ok && v.DRAMKB > 0 {
			x := DRAM{Device: d.Name, Total: v.DRAMKB << 10, At: e.At}
			if m, _, ok := readOne(w, d, "show processes memory", iosxe.ParseMem); ok {
				x.PoolFree, x.PoolUsed = m.Free, 100*float64(m.Total-m.Free)/float64(m.Total)
			}
			res.DRAM = append(res.DRAM, x)
		} else {
			res.DRAMNoData = append(res.DRAMNoData, d.Name)
		}
	}
	res.Warnings, res.WarningsTx = w.list, w.txs
	return res
}

// Bytes escribe un tamaño legible.
func Bytes(n int64) string {
	f, u := float64(n), "B"
	for _, x := range []string{"KiB", "MiB", "GiB", "TiB"} {
		if f < 1024 {
			break
		}
		f, u = f/1024, x
	}
	if u == "B" {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, u)
}

// ---- inventario ----

type InvRow struct {
	Device  string    `json:"device"`
	Kind    string    `json:"kind"` // equipo, modulo, sfp
	Name    string    `json:"name,omitempty"`
	Descr   string    `json:"descr,omitempty"`
	PID     string    `json:"pid,omitempty"`
	VID     string    `json:"vid,omitempty"`
	Serial  string    `json:"serial,omitempty"`
	Model   string    `json:"model,omitempty"`
	Version string    `json:"version,omitempty"`
	Source  string    `json:"source"`
	At      time.Time `json:"at"`
}

type InventoryResult struct {
	Rows       []InvRow    `json:"rows"`
	Devices    int         `json:"devices"`
	Warnings   []string    `json:"warnings"`
	WarningsTx []i18n.Text `json:"-"`
}

var sfpRe = regexp.MustCompile(`(?i)^(SFP|GLC|QSFP|XCVR|DWDM|CWDM|CFP|QDD)|sfp|transceiver`)
var ifNameRe = regexp.MustCompile(`^[A-Za-z]+\d+(/\d+)+`)

func (f *Fleet) Inventory() InventoryResult {
	w := f.newWS()
	res := InventoryResult{Devices: len(f.Devs)}
	for _, d := range f.Devs {
		if v, e, ok := readOne(w, d, "show version", iosxe.ParseVersion); ok {
			res.Rows = append(res.Rows, InvRow{Device: d.Name, Kind: "equipo", Model: v.Model, Version: v.Version, Serial: v.Serial, Source: "show version", At: e.At})
		}
		if items, e, ok := read(w, d, "show inventory", iosxe.ParseInventory); ok {
			for _, it := range items {
				k := "modulo"
				if sfpRe.MatchString(it.PID) || sfpRe.MatchString(it.Descr) || ifNameRe.MatchString(it.Name) {
					k = "sfp"
				}
				res.Rows = append(res.Rows, InvRow{Device: d.Name, Kind: k, Name: it.Name, Descr: it.Descr, PID: it.PID, VID: it.VID, Serial: it.SN, Source: "show inventory", At: e.At})
			}
		}
	}
	res.Warnings, res.WarningsTx = w.list, w.txs
	return res
}

// cell neutraliza fórmulas de hoja de cálculo (=, +, -, @) en datos que vienen de la red.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

var invHead = []string{"Equipo", "Tipo", "Nombre", "Descripción", "PID", "VID", "Serie", "Modelo", "Versión", "Fuente", "Evidencia"}

func (r InvRow) cells() []string {
	return []string{r.Device, r.Kind, r.Name, r.Descr, r.PID, r.VID, r.Serial, r.Model, r.Version, r.Source, r.At.UTC().Format(time.RFC3339)}
}

func (r InventoryResult) CSV() string {
	var b bytes.Buffer
	cw := csv.NewWriter(&b)
	_ = cw.Write(invHead)
	for _, x := range r.Rows {
		c := x.cells()
		for i := range c {
			c[i] = cell(c[i])
		}
		_ = cw.Write(c)
	}
	cw.Flush()
	return b.String()
}

func (r InventoryResult) Markdown() string {
	esc := strings.NewReplacer("|", `\|`, "\n", " ")
	var b strings.Builder
	b.WriteString("| " + strings.Join(invHead, " | ") + " |\n|" + strings.Repeat(" --- |", len(invHead)) + "\n")
	for _, x := range r.Rows {
		c := x.cells()
		for i := range c {
			c[i] = esc.Replace(c[i])
		}
		b.WriteString("| " + strings.Join(c, " | ") + " |\n")
	}
	return b.String()
}
