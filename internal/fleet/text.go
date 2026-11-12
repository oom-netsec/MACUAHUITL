package fleet

import (
	"fmt"
	"strings"
	"text/tabwriter"
)

func tw(b *strings.Builder) *tabwriter.Writer { return tabwriter.NewWriter(b, 0, 4, 2, ' ', 0) }

func warns(b *strings.Builder, l []string) {
	for _, w := range l {
		fmt.Fprintf(b, "AVISO: %s\n", w)
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
	fmt.Fprintf(&b, "Búsqueda %q (%s) en %d equipos: %d coincidencia(s)\n", r.Query, r.Mode, r.Devices, len(r.Hits))
	t := tw(&b)
	for _, h := range r.Hits {
		fmt.Fprintf(t, "%s\t%s\t%s\tVLAN %s\t%s\t%s\t%s\t%s | %s\n", h.Device, h.Kind, dash(h.Port), dash(h.VLAN), dash(h.MAC), dash(h.IP), dash(h.Name), h.Source, f.Stamp(h.At))
	}
	t.Flush()
	warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) TraceText(r TraceResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rastreo L2 de %s %s\n", r.Query, dash(strings.TrimSpace(r.MAC)))
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
		fmt.Fprintf(&b, "Puerto de acceso: %s %s VLAN %s\n", r.Access.Device, r.Access.Port, dash(r.Access.VLAN))
	default:
		fmt.Fprintf(&b, "Sin llegar al puerto de acceso (%s)\n", r.End)
	}
	warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) PathText(r PathResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Camino %s -> %s\n", r.Src, r.Dst)
	for _, h := range r.Hops {
		ind := strings.Repeat("  ", f.depth(r, h))
		fmt.Fprintf(&b, "%s#%d %s", ind, h.ID, h.Device)
		if h.Via != "" {
			fmt.Fprintf(&b, " (vía %s por %s%s)", h.Via, dash(h.OutIf), map[bool]string{true: ", rama ECMP"}[h.ECMP])
		}
		if h.Route != "" {
			fmt.Fprintf(&b, " ruta %s", h.Route)
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
			fmt.Fprintf(&b, " LLEGÓ: %s", h.Reason)
		case "cut":
			fmt.Fprintf(&b, " CORTE: %s", h.Reason)
		}
		if !h.At.IsZero() {
			fmt.Fprintf(&b, "  [%s %s]", h.Source, f.Stamp(h.At))
		}
		b.WriteString("\n")
	}
	warns(&b, r.Warnings)
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
	fmt.Fprintf(&b, "Interfaces con problema: %d (contadores acumulados desde el último clear counters); equipos con dato: estado %d/%d · contadores %d/%d\n", len(r.Issues), r.Checked["status"], r.Devices, r.Checked["counters"], r.Devices)
	for _, i := range r.Issues {
		fmt.Fprintf(&b, "[%s] %s %s  %s | %s\n", i.Severity, i.Device, i.Port, i.Source, f.Stamp(i.At))
		for _, p := range i.Problems {
			fmt.Fprintf(&b, "    %s %s  <- %s\n", p.Kind, map[bool]string{true: fmt.Sprint(p.Value)}[p.Value > 0], p.Evidence)
		}
	}
	warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) SummaryText(r SummaryResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Tablero: %d equipos; con dato: cpu %d · ntp %d · reinicio %d · memoria %d · flash %d\n", r.Devices, r.Checked["cpu"], r.Checked["ntp"], r.Checked["reboot"], r.Checked["memory"], r.Checked["flash"])
	if len(r.Rows) == 0 {
		b.WriteString("Sin alertas.\n")
	}
	t := tw(&b)
	for _, x := range r.Rows {
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\n", x.Device, x.Check, x.Value, x.Detail, f.Stamp(x.At))
	}
	t.Flush()
	warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) CapacityText(r CapacityResult) string {
	var b strings.Builder
	if r.Need > 0 {
		fmt.Fprintf(&b, "Flash: se necesitan %s\n", Bytes(r.Need))
	}
	t := tw(&b)
	for _, x := range r.Flash {
		fit := ""
		if x.Fits != nil {
			fit = map[bool]string{true: "CABE", false: "NO CABE"}[*x.Fits]
		}
		fmt.Fprintf(t, "%s\t%s\tlibre %s de %s\t%.0f %% usada\t%s\t%s\n", x.Device, x.FS, Bytes(x.Free), Bytes(x.Total), x.Used, fit, f.Stamp(x.At))
	}
	t.Flush()
	for _, n := range r.FlashNoData {
		fmt.Fprintf(&b, "%s\tsin dato de flash\n", n)
	}
	b.WriteString("DRAM\n")
	t = tw(&b)
	for _, x := range r.DRAM {
		pool := ""
		if x.PoolFree > 0 {
			pool = fmt.Sprintf("pool libre %s (%.0f %% usado)", Bytes(x.PoolFree), x.PoolUsed)
		}
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\n", x.Device, Bytes(x.Total), pool, f.Stamp(x.At))
	}
	t.Flush()
	for _, n := range r.DRAMNoData {
		fmt.Fprintf(&b, "%s\tsin dato de DRAM\n", n)
	}
	warns(&b, r.Warnings)
	return b.String()
}

func (f *Fleet) InventoryText(r InventoryResult) string {
	var b strings.Builder
	t := tw(&b)
	for _, x := range r.Rows {
		fmt.Fprintf(t, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.Device, x.Kind, dash(x.Name), dash(x.PID), dash(x.Serial), dash(x.Model), dash(x.Version), f.Stamp(x.At))
	}
	t.Flush()
	warns(&b, r.Warnings)
	return b.String()
}
