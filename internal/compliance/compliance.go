// Package compliance evalúa una running-config IOS/IOS-XE contra una plantilla
// dorada del usuario y contra reglas de endurecimiento basadas en la guía pública
// de Cisco para endurecer IOS/IOS-XE. Solo lee texto: nunca toca un equipo.
//
// Reglas escritas sobre la documentación pública de Cisco, sin validar en laboratorio.
//
// No hace: corregir la configuración ni generar comandos de remediación.
package compliance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Warn Status = "warn"
)

type Finding struct {
	Rule      string `json:"rule"`
	Title     string `json:"title"`
	Status    Status `json:"status"`
	Detail    string `json:"detail"`
	Lines     []int  `json:"lines,omitempty"`
	Reference string `json:"reference,omitempty"`
	// TitleTx y DetailTx son Title y Detail como texto de catálogo (es/en); no viajan en el JSON.
	TitleTx, DetailTx i18n.Text `json:"-"`
}

type Report struct {
	Template  []Finding `json:"template"`
	Hardening []Finding `json:"hardening"`
	Pass      int       `json:"pass"`
	Fail      int       `json:"fail"`
	Warn      int       `json:"warn"`
	Note      string    `json:"note"`
	NoteTx    i18n.Text `json:"-"`
}

var noteTx = i18n.Tx("compliance.note")

// Check evalúa config contra las reglas de endurecimiento y, si template no está vacía, contra la plantilla.
func Check(config, template string) (Report, error) {
	cfg := iosconf.Parse(config)
	if len(cfg.Children) == 0 {
		return Report{}, i18n.New("compliance.err.empty", nil)
	}
	r := Report{Hardening: Hardening(cfg), Note: noteTx.In(i18n.Es), NoteTx: noteTx}
	if strings.TrimSpace(template) != "" {
		t, err := ParseTemplate(template)
		if err != nil {
			return Report{}, err
		}
		r.Template = t.Check(cfg)
	}
	for _, f := range append(append([]Finding{}, r.Template...), r.Hardening...) {
		switch f.Status {
		case Pass:
			r.Pass++
		case Fail:
			r.Fail++
		case Warn:
			r.Warn++
		}
	}
	return r, nil
}

// Text es el informe legible, en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el informe en el idioma pedido (con es, el de siempre); los títulos, detalles y la nota ya vienen
// en ese idioma si el informe pasó por i18n.Localize.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	section := func(title string, fs []Finding) {
		if len(fs) == 0 {
			return
		}
		b.WriteString(title + "\n")
		for _, f := range fs {
			fmt.Fprintf(&b, "  %-7s %-20s %s", m("compliance.status."+string(f.Status)), f.Rule, f.Title)
			if f.Status != Pass && f.Detail != "" {
				b.WriteString(": " + f.Detail)
			}
			b.WriteString("\n")
		}
	}
	section(m("compliance.text.template"), r.Template)
	section(m("compliance.text.hardening"), r.Hardening)
	fmt.Fprintf(&b, "%s\n%s\n", m("compliance.text.summary", "pass", r.Pass, "fail", r.Fail, "warn", r.Warn), r.Note)
	return b.String()
}

func lineNums(ns []*iosconf.Node) []int {
	var out []int
	for _, n := range ns {
		out = append(out, n.Num)
	}
	return out
}

// secretVal: el valor de password/secret nunca debe salir en el reporte.
var secretVal = regexp.MustCompile(`\b(password|secret)( [0-9])? \S.*$`)

// lineListTx es la lista «línea N: texto» de los nodos, sin el valor de los secretos.
func lineListTx(ns []*iosconf.Node) i18n.Text {
	var parts []i18n.Text
	for _, n := range ns {
		parts = append(parts, i18n.Tx("compliance.line", "n", n.Num, "text", secretVal.ReplaceAllString(n.Path(), "${1}${2} <oculto>")))
	}
	return i18n.Join("; ", parts...)
}
