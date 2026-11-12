package compliance

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

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
		return Template{}, errors.New("compliance: la plantilla no tiene reglas")
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
			return nil, fmt.Errorf("compliance: plantilla línea %d: una línea prohibida no puede tener hijos", n.Num)
		}
		if r.kind == '?' && len(n.Children) == 0 {
			return nil, fmt.Errorf("compliance: plantilla línea %d: una sección opcional necesita reglas", n.Num)
		}
		re, err := iosconf.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compliance: plantilla línea %d: %v", n.Num, err)
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
	eval(t.rules, []*iosconf.Node{cfg}, "", "", &out)
	return out
}

// eval aplica rules a cada sección de scopes. missing explica por qué no hay secciones.
func eval(rules []tplRule, scopes []*iosconf.Node, prefix, missing string, out *[]Finding) {
	for _, r := range rules {
		title := prefix + r.text
		if r.kind == 's' || r.kind == '?' {
			var sub []*iosconf.Node
			for _, s := range scopes {
				sub = append(sub, s.FindRe(r.re)...)
			}
			why := missing
			if len(sub) == 0 && why == "" && r.kind == 's' {
				why = fmt.Sprintf("la sección %q no existe", strings.TrimPrefix(r.text, "+ "))
			}
			if len(sub) == 0 && r.kind == '?' && why == "" {
				why = "-" // opcional ausente: no aplica
			}
			eval(r.children, sub, title+" > ", why, out)
			continue
		}
		f := Finding{Rule: fmt.Sprintf("plantilla:%d", r.num), Title: title, Status: Pass}
		switch {
		case missing == "-":
			f.Detail = "la sección opcional no existe; no aplica"
		case missing != "":
			f.Status, f.Detail = Fail, missing
		case r.kind == '+':
			var lacking []string
			for _, s := range scopes {
				if len(s.FindRe(r.re)) == 0 {
					lacking = append(lacking, scopeName(s))
				}
			}
			if len(lacking) > 0 {
				f.Status, f.Detail = Fail, "falta en "+strings.Join(lacking, "; ")
			}
		case r.kind == '-':
			var hits []*iosconf.Node
			for _, s := range scopes {
				hits = append(hits, s.FindRe(r.re)...)
			}
			if len(hits) > 0 {
				f.Status, f.Detail, f.Lines = Fail, "presente en "+lineList(hits), lineNums(hits)
			}
		}
		*out = append(*out, f)
	}
}

func scopeName(n *iosconf.Node) string {
	if n.Parent == nil {
		return "la configuración global"
	}
	return fmt.Sprintf("%q (línea %d)", n.Path(), n.Num)
}
