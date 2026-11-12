// Package compliance evalúa una running-config IOS/IOS-XE contra una plantilla
// dorada del usuario y contra reglas de endurecimiento basadas en la guía pública
// de Cisco para endurecer IOS/IOS-XE. Solo lee texto: nunca toca un equipo.
//
// Reglas escritas sobre la documentación pública de Cisco, sin validar en laboratorio.
//
// No hace: corregir la configuración ni generar comandos de remediación.
package compliance

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

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
}

type Report struct {
	Template  []Finding `json:"template"`
	Hardening []Finding `json:"hardening"`
	Pass      int       `json:"pass"`
	Fail      int       `json:"fail"`
	Warn      int       `json:"warn"`
	Note      string    `json:"note"`
}

const note = "Reglas basadas en la guía pública de Cisco para endurecer IOS/IOS-XE; sin validar en laboratorio. Con salidas enmascaradas por Patrol no se distinguen comunidades ni contraseñas por defecto."

// Check evalúa config contra las reglas de endurecimiento y, si template no está vacía, contra la plantilla.
func Check(config, template string) (Report, error) {
	cfg := iosconf.Parse(config)
	if len(cfg.Children) == 0 {
		return Report{}, errors.New("compliance: la configuración está vacía")
	}
	r := Report{Hardening: Hardening(cfg), Note: note}
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

var statusText = map[Status]string{Pass: "OK", Fail: "FALLA", Warn: "REVISAR"}

func (r Report) Text() string {
	var b strings.Builder
	section := func(title string, fs []Finding) {
		if len(fs) == 0 {
			return
		}
		b.WriteString(title + "\n")
		for _, f := range fs {
			fmt.Fprintf(&b, "  %-7s %-20s %s", statusText[f.Status], f.Rule, f.Title)
			if f.Status != Pass && f.Detail != "" {
				b.WriteString(": " + f.Detail)
			}
			b.WriteString("\n")
		}
	}
	section("Plantilla", r.Template)
	section("Endurecimiento", r.Hardening)
	fmt.Fprintf(&b, "%d OK, %d fallas, %d por revisar\n%s\n", r.Pass, r.Fail, r.Warn, r.Note)
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

func lineList(ns []*iosconf.Node) string {
	var parts []string
	for _, n := range ns {
		parts = append(parts, fmt.Sprintf("línea %d: %s", n.Num, secretVal.ReplaceAllString(n.Path(), "${1}${2} <oculto>")))
	}
	return strings.Join(parts, "; ")
}
