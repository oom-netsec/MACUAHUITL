package playbook

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Param es un dato que el playbook pide al armar el trabajo; los comandos lo usan como {name}.
type Param struct{ Name, Kind string }

// ParamKinds son los tipos de dato válidos.
var ParamKinds = []string{"mac", "ap", "interface", "ip"}

var (
	placeholder = regexp.MustCompile(`\{[A-Za-z0-9_-]+\}`)
	paramName   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	// aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff o aabbccddeeff
	macRe    = regexp.MustCompile(`^(?:(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|[0-9A-Fa-f]{12})$`)
	apRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	ifaceRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9/.:-]{1,47}$`)
	errValue = errors.New("valor inválido")
)

// ValidateValue revisa v contra su tipo y lo devuelve normalizado (la MAC como aaaa.bbbb.cccc).
// Nada de espacios, |, ;, saltos ni Unicode: las expresiones son ASCII anclado.
func ValidateValue(kind, v string) (string, error) {
	switch kind {
	case "mac":
		if !macRe.MatchString(v) {
			return "", errValue
		}
		h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.ToLower(v))
		return h[0:4] + "." + h[4:8] + "." + h[8:12], nil
	case "ap":
		if apRe.MatchString(v) {
			return v, nil
		}
	case "interface":
		if ifaceRe.MatchString(v) {
			return v, nil
		}
	case "ip":
		if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" && len(v) <= 45 {
			return v, nil
		}
	}
	return "", errValue
}

// checkParams valida las declaraciones y que cada {x} de los comandos esté declarado y cada dato declarado se use.
func checkParams(ps []Param, pre []string, cmds []fileCommand) error {
	declared := map[string]bool{}
	for _, p := range ps {
		switch {
		case !paramName.MatchString(p.Name):
			return i18n.New("playbook.err.param_name", i18n.A("name", p.Name))
		case declared[p.Name]:
			return i18n.New("playbook.err.param_dup", i18n.A("name", p.Name))
		case !slices.Contains(ParamKinds, p.Kind):
			return i18n.New("playbook.err.param_kind", i18n.A("name", p.Name, "kind", p.Kind))
		}
		declared[p.Name] = true
	}
	for _, c := range pre {
		if m := placeholder.FindString(c); m != "" {
			return i18n.New("playbook.err.param_in_pre", i18n.A("name", m[1:len(m)-1]))
		}
	}
	used := map[string]bool{}
	for _, c := range cmds {
		for _, m := range placeholder.FindAllString(c.Cmd, -1) {
			n := m[1 : len(m)-1]
			if !declared[n] {
				return i18n.New("playbook.err.param_undeclared", i18n.A("name", n))
			}
			used[n] = true
		}
	}
	for _, p := range ps {
		if !used[p.Name] {
			return i18n.New("playbook.err.param_unused", i18n.A("name", p.Name))
		}
	}
	return nil
}

// Expand da los comandos del playbook con los datos sustituidos. Cada dato se valida por su tipo, la MAC se
// normaliza, y el resultado vuelve a pasar CheckDenied. Falta de un dato o un dato que el playbook no pide es
// error: nunca sale un comando con {x} literal. Sin params devuelve los comandos tal cual. (Pre no admite datos.)
func (p Playbook) Expand(vals map[string]string) ([]Command, error) {
	for k := range vals {
		if !slices.ContainsFunc(p.Params, func(q Param) bool { return q.Name == k }) {
			return nil, i18n.New("playbook.err.param_unknown", i18n.A("name", k))
		}
	}
	if len(p.Params) == 0 {
		return p.Commands, nil
	}
	norm := make([]string, 0, 2*len(p.Params))
	for _, q := range p.Params {
		raw, ok := vals[q.Name]
		if !ok || raw == "" {
			return nil, i18n.New("playbook.err.param_missing", i18n.A("name", q.Name, "kind", q.Kind))
		}
		v, err := ValidateValue(q.Kind, raw)
		if err != nil {
			return nil, i18n.New("playbook.err.param_invalid", i18n.A("name", q.Name, "kind", q.Kind))
		}
		norm = append(norm, "{"+q.Name+"}", v)
	}
	r := strings.NewReplacer(norm...)
	out := make([]Command, len(p.Commands))
	for i, c := range p.Commands {
		c.Text = r.Replace(c.Text)
		if err := CheckDenied(p.Platform, c.Text); err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}
