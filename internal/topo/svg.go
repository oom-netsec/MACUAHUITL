package topo

import (
	"encoding/xml"
	"fmt"
	"strings"
)

func esc(s string) string {
	var sb strings.Builder
	xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

// SVG dibuja el grafo sin scripts ni recursos externos: se puede abrir o adjuntar tal cual.
// Los nombres vienen de la red (CDP/LLDP) y siempre se escapan.
func (g Graph) SVG() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" font-family="sans-serif" font-size="11">`, Width, Height, Width, Height)
	sb.WriteString(`<rect width="100%" height="100%" fill="#ffffff"/>`)
	for _, l := range g.Links {
		a, b := g.node(l.A), g.node(l.B)
		color, dash := "#64748b", ""
		if l.vlanMismatch() || l.duplexMismatch() {
			color = "#dc2626"
		}
		if len(l.SeenBy) == 1 && a.Collected && b.Collected {
			dash = ` stroke-dasharray="6 4"`
		}
		fmt.Fprintf(&sb, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="2"%s/>`, a.X, a.Y, b.X, b.Y, color, dash)
		// Interfaz junto a cada extremo (a un cuarto del enlace).
		fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" fill="#334155" text-anchor="middle">%s</text>`, a.X+(b.X-a.X)/4, a.Y+(b.Y-a.Y)/4-4, esc(l.AIf))
		fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" fill="#334155" text-anchor="middle">%s</text>`, b.X+(a.X-b.X)/4, b.Y+(a.Y-b.Y)/4-4, esc(l.BIf))
	}
	for _, n := range g.Nodes {
		fill := "#e2e8f0"
		if n.Collected {
			fill = "#bfdbfe"
		}
		fmt.Fprintf(&sb, `<g><circle cx="%.1f" cy="%.1f" r="18" fill="%s" stroke="#1e293b"/>`, n.X, n.Y, fill)
		fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" text-anchor="middle" font-weight="bold" fill="#0f172a">%s</text>`, n.X, n.Y+32, esc(n.Name))
		sub := strings.TrimSpace(n.Platform + " " + n.MgmtIP)
		if len(n.RootVLANs) > 0 {
			sub += fmt.Sprintf(" · root %v", n.RootVLANs)
		}
		fmt.Fprintf(&sb, `<text x="%.1f" y="%.1f" text-anchor="middle" fill="#475569">%s</text></g>`, n.X, n.Y+45, esc(sub))
	}
	sb.WriteString(`</svg>`)
	return sb.String()
}
