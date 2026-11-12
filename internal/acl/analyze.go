package acl

import "fmt"

// Finding es un hallazgo sobre la regla Index (base 0).
type Finding struct {
	Index  int
	Kind   string // shadowed, redundant, impossible
	Detail string
}

// portsCover: el conjunto a (vacío = todos) contiene al conjunto b (vacío = todos).
func portsCover(a, b []PortRange) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, y := range b {
		covered := false
		for _, x := range a {
			if x.Lo <= y.Lo && y.Hi <= x.Hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Covers: todo paquete que coincide con b también coincide con a.
func (a Rule) Covers(b Rule) bool {
	if a.Protocol != "ip" && CanonProtocol(a.Protocol) != CanonProtocol(b.Protocol) {
		return false
	}
	if a.Established && !b.Established {
		return false
	}
	return a.Src.Overlaps(b.Src) && a.Src.Bits() <= b.Src.Bits() &&
		a.Dst.Overlaps(b.Dst) && a.Dst.Bits() <= b.Dst.Bits() &&
		portsCover(NormalizePorts(a.SrcPorts), NormalizePorts(b.SrcPorts)) && portsCover(NormalizePorts(a.DstPorts), NormalizePorts(b.DstPorts))
}

// Analyze detecta reglas imposibles, sombreadas (cubiertas antes por otra acción) y
// redundantes (cubiertas antes por la misma acción). Una regla cubierta por una
// anterior nunca se evalúa, cualquiera que sea su intención.
//
// La comparación es por pares: una regla cubierta solo por la unión de varias
// anteriores (dos /25 y luego el /24) no se detecta. shortcut: pares; subir a
// cobertura por unión cuando se pida.
func Analyze(a ACL) []Finding {
	var out []Finding
	for i, r := range a.Rules {
		if err := r.Validate(); err != nil {
			out = append(out, Finding{i, "impossible", err.Error()})
			continue
		}
		for j := 0; j < i; j++ {
			prev := a.Rules[j]
			if prev.Validate() != nil || !prev.Covers(r) {
				continue
			}
			kind := "redundant"
			if prev.Action != r.Action {
				kind = "shadowed"
			}
			out = append(out, Finding{i, kind, fmt.Sprintf("la regla %d (%s) ya cubre todo lo que esta coincide", j+1, prev.Action)})
			break
		}
	}
	return out
}
