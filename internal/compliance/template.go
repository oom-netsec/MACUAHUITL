package compliance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

// Plantilla dorada: texto con la misma sangría que la configuración.
//
//	# comentario
//	+ service password-encryption      línea obligatoria (expresión regular, línea completa)
//	- ip http server                   línea prohibida
//	hostname SW-.*                     sin prefijo y sin hijos: obligatoria (pegar una config dorada funciona)
//	line vty .*                        con hijos: sección; las reglas aplican a cada sección que coincida
//	 + transport input ssh
//	? interface Vlan\d+                sección opcional: si no existe, sus reglas no aplican
//	 + no ip proxy-arp
//
// Una sección obligatoria que no existe hace fallar todas sus reglas.
type Template struct{ rules []tplRule }

type tplRule struct {
	kind     byte // '+', '-', 's' (sección), '?' (sección opcional)
	text     string
	re       *regexp.Regexp
	children []tplRule
	num      int
}

func ParseTemplate(text string) (Template, error) {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			l = "" // conserva la numeración de líneas
		}
		lines = append(lines, l)
	}
	rules, err := build(iosconf.Parse(strings.Join(lines, "\n")).Children)
	if err != nil {
		return Template{}, err
	}
	if len(rules) == 0 {
		return Template{}, i18n.New("compliance.err.no_rules", nil)
	}
	return Template{rules}, nil
}

func build(ns []*iosconf.Node) ([]tplRule, error) {
	var out []tplRule
	for _, n := range ns {
		r := tplRule{text: n.Line, num: n.Num}
		pat := n.Line
		switch {
		case strings.HasPrefix(pat, "+ "), strings.HasPrefix(pat, "- "), strings.HasPrefix(pat, "? "):
			r.kind, pat = pat[0], pat[2:]
		case len(n.Children) > 0:
			r.kind = 's'
		default:
			r.kind = '+'
		}
		if r.kind == '+' && len(n.Children) > 0 {
			r.kind = 's'
		}
		if r.kind == '-' && len(n.Children) > 0 {
			return nil, i18n.New("compliance.err.forbidden_children", i18n.A("n", n.Num))
		}
		if r.kind == '?' && len(n.Children) == 0 {
			return nil, i18n.New("compliance.err.optional_empty", i18n.A("n", n.Num))
		}
		re, err := iosconf.Compile(pat)
		if err != nil {
			return nil, i18n.New("compliance.err.regex", i18n.A("n", n.Num, "error", err))
		}
		r.re = re
		if r.children, err = build(n.Children); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Check devuelve un hallazgo por regla hoja; el título lleva sus secciones ("line vty .* > + transport input ssh").
func (t Template) Check(cfg *iosconf.Node) []Finding {
	var out []Finding
	eval(t.rules, []*iosconf.Node{cfg}, "", i18n.Text{}, &out)
	return out
}

// eval aplica rules a cada sección de scopes. missing explica por qué no hay secciones.
func eval(rules []tplRule, scopes []*iosconf.Node, prefix string, missing i18n.Text, out *[]Finding) {
	for _, r := range rules {
		title := prefix + r.text
		if r.kind == 's' || r.kind == '?' {
			var sub []*iosconf.Node
			for _, s := range scopes {
				sub = append(sub, s.FindRe(r.re)...)
			}
			why := missing
			if len(sub) == 0 && why.Empty() && r.kind == 's' {
				why = i18n.Tx("compliance.detail.tpl_no_section", "name", strings.TrimPrefix(r.text, "+ "))
			}
			if len(sub) == 0 && r.kind == '?' && why.Empty() {
				why = optionalAbsent
			}
			eval(r.children, sub, title+" > ", why, out)
			continue
		}
		f := Finding{Rule: fmt.Sprintf("plantilla:%d", r.num), Title: title, Status: Pass}
		switch {
		case missing.Key == optionalAbsent.Key:
			f.DetailTx = i18n.Tx("compliance.detail.tpl_optional")
		case !missing.Empty():
			f.Status, f.DetailTx = Fail, missing
		case r.kind == '+':
			var lacking []i18n.Text
			for _, s := range scopes {
				if len(s.FindRe(r.re)) == 0 {
					lacking = append(lacking, scopeName(s))
				}
			}
			if len(lacking) > 0 {
				f.Status, f.DetailTx = Fail, i18n.Tx("compliance.detail.tpl_lacking").With("scopes", i18n.Join("; ", lacking...))
			}
		case r.kind == '-':
			var hits []*iosconf.Node
			for _, s := range scopes {
				hits = append(hits, s.FindRe(r.re)...)
			}
			if len(hits) > 0 {
				f.Status, f.DetailTx, f.Lines = Fail, i18n.Tx("compliance.detail.tpl_present").With("lines", lineListTx(hits)), lineNums(hits)
			}
		}
		f.Detail = f.DetailTx.In(i18n.Es)
		*out = append(*out, f)
	}
}

// optionalAbsent marca «sección opcional ausente: no aplica» al bajar por la plantilla.
var optionalAbsent = i18n.Tx("compliance.optional_absent")

func scopeName(n *iosconf.Node) i18n.Text {
	if n.Parent == nil {
		return i18n.Tx("compliance.scope.global")
	}
	return i18n.Tx("compliance.scope.section", "path", n.Path(), "n", n.Num)
}
