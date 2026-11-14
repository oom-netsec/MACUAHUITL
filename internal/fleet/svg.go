package fleet

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func esc(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

// SVG dibuja el camino: una columna por salto, ramas ECMP en filas distintas,
// cortes en rojo. Sin scripts ni recursos externos; los nombres vienen de la red y se escapan.
func (r PathResult) SVG() string { return r.SVGIn(i18n.Es) }

// SVGIn es SVG con la etiqueta de corte en el idioma loc.
func (r PathResult) SVGIn(loc string) string {
	const colW, rowH, pad = 190.0, 90.0, 70.0
	depth := make([]int, len(r.Hops))
	rows := map[int]int{}
	pos := make([][2]float64, len(r.Hops))
	maxD, maxR := 0, 0
	for i, h := range r.Hops {
		if h.Parent >= 0 {
			depth[i] = depth[h.Parent] + 1
		}
		row := rows[depth[i]]
		rows[depth[i]]++
		pos[i] = [2]float64{pad + float64(depth[i])*colW, pad + float64(row)*rowH}
		maxD, maxR = max(maxD, depth[i]), max(maxR, row)
	}
	w, h := 2*pad+float64(maxD)*colW+40, 2*pad+float64(maxR)*rowH
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" font-family="sans-serif" font-size="11"><rect width="100%%" height="100%%" fill="#ffffff"/>`, w, h, w, h)
	for i, hp := range r.Hops {
		if hp.Parent < 0 {
			continue
		}
		a, b := pos[hp.Parent], pos[i]
		fmt.Fprintf(&sb, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#64748b" stroke-width="2"/>`, a[0], a[1], b[0], b[1])
		label := strings.TrimSpace(hp.OutIf + " " + hp.Via)
		if hp.Segment != nil && hp.Segment.VLAN != "" {
			label += " VLAN " + hp.Segment.VLAN
		}
		fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" text-anchor="middle" fill="#334155">%s</text>`, (a[0]+b[0])/2, (a[1]+b[1])/2-6, esc(label))
	}
	for i, hp := range r.Hops {
		fill, stroke := "#bfdbfe", "#1e293b"
		switch hp.Status {
		case "cut":
			fill, stroke = "#fecaca", "#dc2626"
		case "arrived":
			fill = "#bbf7d0"
		}
		fmt.Fprintf(&sb, `<g><circle cx="%.1f" cy="%.1f" r="18" fill="%s" stroke="%s"/><text x="%.1f" y="%.1f" text-anchor="middle" font-weight="bold" fill="#0f172a">%s</text>`, pos[i][0], pos[i][1], fill, stroke, pos[i][0], pos[i][1]+32, esc(hp.Device))
		if hp.Status == "cut" {
			fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" text-anchor="middle" fill="#b91c1c">%s</text>`, pos[i][0], pos[i][1]+45, esc(i18n.Msg(loc, "fleet.svg.cut", i18n.A("reason", trunc(hp.Reason, 34)))))
		}
		sb.WriteString(`</g>`)
	}
	sb.WriteString(`</svg>`)
	return sb.String()
}

func trunc(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}
