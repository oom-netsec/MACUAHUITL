package fleet

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func tw(b *strings.Builder) *tabwriter.Writer { return tabwriter.NewWriter(b, 0, 4, 2, ' ', 0) }

// In devuelve la flota con los textos de sus informes en el idioma dado (es es el de siempre); los datos no cambian.
func (f *Fleet) In(loc string) *Fleet {
	c := *f
	c.loc = loc
	return &c
}

// t es el texto del código en el idioma de la flota.
func (f *Fleet) t(code string, kv ...any) string { return i18n.Msg(f.loc, code, i18n.A(kv...)) }

func (f *Fleet) warns(b *strings.Builder, l []string) {
	for _, w := range l {
		b.WriteString(f.t("fleet.text.warn", "w", w) + "\n")
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (f *Fleet) FindText(r FindResult) string {
	var b strings.Builder
	b.WriteString(f.t("fleet.text.find_head", "query", r.Query, "mode", r.Mode, "n", r.Devices, "hits", len(r.Hits)) + "\n")
	t := tw(&b)
	for _, h := range r.Hits {
		src := h.Source
		if h.SourceKey != "" {
			src = f.t(h.SourceKey)
		}
		fmt.Fprintf(t, "%s\t%s\t%s\tVLAN %s\t%s\t%s\t%s\t%s | %s\n", h.Device, h.Kind, dash(h.Port), dash(h.VLAN), dash(h.MAC), dash(h.IP), dash(h.Name), src, f.Stamp(h.At))
	}
	t.Flush()
	f.warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) TraceText(r TraceResult) string {
	var b strings.Builder
	b.WriteString(f.t("fleet.text.trace_head", "query", r.Query, "mac", dash(strings.TrimSpace(r.MAC))) + "\n")
	for i, h := range r.Hops {
		fmt.Fprintf(&b, "%d. %s %s VLAN %s", i+1, h.Device, h.Port, dash(h.VLAN))
		if h.Neighbor != "" {
			fmt.Fprintf(&b, " -> %s %s", h.Neighbor, h.NeighborPort)
		}
		if h.Note != "" {
			fmt.Fprintf(&b, " [%s]", h.Note)
		}
		fmt.Fprintf(&b, "  (%s)\n", f.Stamp(h.At))
	}
	switch r.End {
	case "access":
		b.WriteString(f.t("fleet.text.trace_access", "device", r.Access.Device, "port", r.Access.Port, "vlan", dash(r.Access.VLAN)) + "\n")
	default:
		b.WriteString(f.t("fleet.text.trace_noend", "end", r.End) + "\n")
	}
	f.warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) PathText(r PathResult) string {
	var b strings.Builder
	b.WriteString(f.t("fleet.text.path_head", "src", r.Src, "dst", r.Dst) + "\n")
	for _, h := range r.Hops {
		ind := strings.Repeat("  ", f.depth(r, h))
		fmt.Fprintf(&b, "%s#%d %s", ind, h.ID, h.Device)
		if h.Via != "" {
			code := "fleet.text.path_via"
			if h.ECMP {
				code += "_ecmp"
			}
			b.WriteString(f.t(code, "via", h.Via, "out", dash(h.OutIf)))
		}
		if h.Route != "" {
			b.WriteString(f.t("fleet.text.path_route", "route", h.Route))
		}
		if h.Segment != nil {
			fmt.Fprintf(&b, " L2[%s %s", h.Segment.Interface, h.Segment.Mode)
			if h.Segment.VLAN != "" {
				fmt.Fprintf(&b, " VLAN %s", h.Segment.VLAN)
			}
			for _, x := range h.Segment.L2 {
				fmt.Fprintf(&b, " > %s %s", x.Device, x.Port)
			}
			b.WriteString("]")
		}
		if h.Final != nil {
			fmt.Fprintf(&b, " L2 final[%s", h.Final.Interface)
			for _, x := range h.Final.L2 {
				fmt.Fprintf(&b, " > %s %s", x.Device, x.Port)
			}
			b.WriteString("]")
		}
		switch h.Status {
		case "arrived":
			b.WriteString(f.t("fleet.text.path_arrived", "reason", h.Reason))
		case "cut":
			b.WriteString(f.t("fleet.text.path_cut", "reason", h.Reason))
		}
		if !h.At.IsZero() {
			fmt.Fprintf(&b, "  [%s %s]", h.Source, f.Stamp(h.At))
		}
		b.WriteString("\n")
	}
	f.warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) depth(r PathResult, h PathHop) int {
	n := 0
	for h.Parent >= 0 {
		h = r.Hops[h.Parent]
		n++
	}
	return n
}

func (f *Fleet) HealthText(r HealthResult) string {
	var b strings.Builder
	b.WriteString(f.t("fleet.text.health_head", "n", len(r.Issues), "st", r.Checked["status"], "dev", r.Devices, "ct", r.Checked["counters"]) + "\n")
	for _, i := range r.Issues {
		fmt.Fprintf(&b, "[%s] %s %s  %s | %s\n", i.Severity, i.Device, i.Port, i.Source, f.Stamp(i.At))
		for _, p := range i.Problems {
			fmt.Fprintf(&b, "    %s %s  <- %s\n", p.Kind, map[bool]string{true: fmt.Sprint(p.Value)}[p.Value > 0], p.Evidence)
		}
	}
	f.warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) SummaryText(r SummaryResult) string {
	var b strings.Builder
	b.WriteString(f.t("fleet.text.summary_head", "dev", r.Devices, "cpu", r.Checked["cpu"], "ntp", r.Checked["ntp"], "reboot", r.Checked["reboot"], "mem", r.Checked["memory"], "flash", r.Checked["flash"]) + "\n")
	if len(r.Rows) == 0 {
		b.WriteString(f.t("fleet.text.no_alerts") + "\n")
	}
	t := tw(&b)
	for _, x := range r.Rows {
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n", x.Device, x.Check, x.Value, x.Detail, f.Stamp(x.At))
	}
	t.Flush()
	f.warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) CapacityText(r CapacityResult) string {
	var b strings.Builder
	if r.Need > 0 {
		b.WriteString(f.t("fleet.text.need", "size", Bytes(r.Need)) + "\n")
	}
	t := tw(&b)
	for _, x := range r.Flash {
		fit := ""
		if x.Fits != nil {
			fit = f.t(map[bool]string{true: "fleet.text.fits", false: "fleet.text.no_fit"}[*x.Fits])
		}
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\t%s\n", x.Device, x.FS, f.t("fleet.text.free_of", "free", Bytes(x.Free), "total", Bytes(x.Total)), f.t("fleet.text.used", "pct", fmt.Sprintf("%.0f", x.Used)), fit, f.Stamp(x.At))
	}
	t.Flush()
	for _, n := range r.FlashNoData {
		fmt.Fprintf(&b, "%s\t%s\n", n, f.t("fleet.text.no_flash"))
	}
	b.WriteString("DRAM\n")
	t = tw(&b)
	for _, x := range r.DRAM {
		pool := ""
		if x.PoolFree > 0 {
			pool = f.t("fleet.text.pool", "free", Bytes(x.PoolFree), "pct", fmt.Sprintf("%.0f", x.PoolUsed))
		}
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\n", x.Device, Bytes(x.Total), pool, f.Stamp(x.At))
	}
	t.Flush()
	for _, n := range r.DRAMNoData {
		fmt.Fprintf(&b, "%s\t%s\n", n, f.t("fleet.text.no_dram"))
	}
	f.warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) InventoryText(r InventoryResult) string {
	var b strings.Builder
	t := tw(&b)
	for _, x := range r.Rows {
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.Device, invCells(f.loc, x)[1], dash(x.Name), dash(x.PID), dash(x.Serial), dash(x.Model), dash(x.Version), f.Stamp(x.At))
	}
	t.Flush()
	f.warns(&b, r.Warnings)
	return b.String()
}
