package asa

import (
	"encoding/xml"
	"regexp"
	"strings"
)

// PTPhase es una fase de packet-tracer.
type PTPhase struct {
	ID                    int
	Type, Subtype, Result string
	Config, Extra         string
}

// PacketTrace es el resultado de packet-tracer, en texto o en `xml`.
type PacketTrace struct {
	Phases                             []PTPhase
	InputIf, InputStatus, InputLine    string
	OutputIf, OutputStatus, OutputLine string
	Action                             string // allow o drop
	DropReason, DropLocation           string
}

// Allowed es true si el paquete salió permitido.
func (p PacketTrace) Allowed() bool {
	return strings.EqualFold(p.Action, "allow") && p.DropReason == ""
}

// setFinal asigna un campo del bloque "Result:" final (clave en minúsculas, con guiones).
func (p *PacketTrace) setFinal(k, v string) {
	switch strings.ToLower(k) {
	case "input-interface":
		p.InputIf = v
	case "input-status":
		p.InputStatus = v
	case "input-line-status":
		p.InputLine = v
	case "output-interface":
		p.OutputIf = v
	case "output-status":
		p.OutputStatus = v
	case "output-line-status":
		p.OutputLine = v
	case "action":
		p.Action = v
	case "drop-reason":
		// 9.22 imprime motivo y ubicación en una sola línea
		if r, loc, found := strings.Cut(v, ", Drop-location:"); found {
			v, p.DropLocation = r, strings.TrimSpace(loc)
		}
		p.DropReason = v
	case "drop-location":
		p.DropLocation = v
	}
}

func (ph *PTPhase) set(k, v string) {
	switch strings.ToLower(k) {
	case "id":
		ph.ID = int(atoi(v))
	case "type":
		ph.Type = v
	case "subtype":
		ph.Subtype = v
	case "result":
		ph.Result = v
	case "config":
		ph.Config = v
	case "extra":
		ph.Extra = v
	}
}

var rePTKey = regexp.MustCompile(`^(Phase|Type|Subtype|Result|Config|Additional Information|input-interface|input-status|input-line-status|output-interface|output-status|output-line-status|Action|Drop-reason|Drop-location):\s*(.*)$`)

// ParsePacketTrace lee la salida de packet-tracer; si trae etiquetas XML usa la forma `xml`, que es
// la estable. ok=false sin ninguna fase ni acción.
func ParsePacketTrace(s string) (PacketTrace, bool) {
	var p PacketTrace
	if startsWithXML(s) {
		p = parsePTXML(s)
	} else {
		p = parsePTText(s)
	}
	return p, len(p.Phases) > 0 || p.Action != ""
}

var rePTEcho = regexp.MustCompile(`^\S+# `)

// startsWithXML: la primera línea con contenido, sin contar el eco del comando, empieza con "<".
func startsWithXML(s string) bool {
	for _, l := range lines(s) {
		t := strings.TrimSpace(l)
		if t == "" || rePTEcho.MatchString(t) || strings.Contains(t, "# packet-tracer") {
			continue
		}
		return strings.HasPrefix(t, "<")
	}
	return false
}

func parsePTText(s string) PacketTrace {
	var p PacketTrace
	sec := "" // config, extra o final
	var cur *PTPhase
	var buf []string
	flush := func() {
		if cur != nil && (sec == "config" || sec == "extra") {
			t := strings.Join(buf, "\n")
			if sec == "config" {
				cur.Config = t
			} else {
				cur.Extra = t
			}
		}
		buf = nil
	}
	for _, l := range lines(s) {
		m := rePTKey.FindStringSubmatch(l)
		if m == nil { // continuación de Config o de Additional Information
			if (sec == "config" || sec == "extra") && strings.TrimSpace(l) != "" {
				buf = append(buf, strings.TrimSpace(l))
			}
			continue
		}
		k, v := m[1], strings.TrimSpace(m[2])
		if sec == "final" {
			p.setFinal(k, v)
			continue
		}
		switch k {
		case "Phase":
			flush()
			p.Phases = append(p.Phases, PTPhase{ID: int(atoi(v))})
			cur, sec = &p.Phases[len(p.Phases)-1], ""
		case "Config":
			flush()
			sec = "config"
		case "Additional Information":
			flush()
			sec = "extra"
		case "Result":
			flush()
			if v == "" { // "Result:" sin valor abre el bloque final
				sec = "final"
			} else if cur != nil {
				cur.Result, sec = v, ""
			}
		default:
			if cur != nil && sec != "config" && sec != "extra" {
				cur.set(k, v)
			}
		}
	}
	flush()
	return p
}

func parsePTXML(s string) PacketTrace {
	var p PacketTrace
	var body []string
	for _, l := range lines(s) {
		if t := strings.TrimSpace(l); !strings.HasPrefix(t, "<?xml") && !rePTEcho.MatchString(t) {
			body = append(body, l)
		}
	}
	d := xml.NewDecoder(strings.NewReader("<root>" + strings.Join(body, "\n") + "</root>"))
	d.Strict = false
	var stack []string
	var txt strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := strings.ToLower(t.Name.Local)
			stack = append(stack, n)
			txt.Reset()
			if n == "phase" && len(stack) == 2 {
				p.Phases = append(p.Phases, PTPhase{})
			}
		case xml.CharData:
			txt.Write(t)
		case xml.EndElement:
			if len(stack) == 3 {
				v := strings.TrimSpace(txt.String())
				switch stack[1] {
				case "phase":
					if n := len(p.Phases); n > 0 {
						p.Phases[n-1].set(stack[2], v)
					}
				case "result":
					p.setFinal(stack[2], v)
				}
			}
			txt.Reset()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return p
}
