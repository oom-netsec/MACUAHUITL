// Package calc reúne las calculadoras de bolsillo del ingeniero de redes
// (direccionamiento, MTU, TCP, QoS, óptica, selección BGP). Todo es cálculo puro:
// sin red, sin archivos, sin estado. El núcleo lo expone por gRPC para que mctl y
// la UI lleguen al mismo resultado por el mismo camino.
package calc

import (
	"strings"
	"text/tabwriter"
)

// Table es una tabla lista para mostrar: la UI la pinta como <table> y mctl como
// texto alineado. Así cada calculadora define su presentación una sola vez.
type Table struct {
	Title string     `json:"title"`
	Head  []string   `json:"head"`
	Rows  [][]string `json:"rows"`
}

// Report es la vista legible de un resultado: tablas y notas explicativas.
type Report struct {
	Tables []Table  `json:"tables"`
	Notes  []string `json:"notes"`
}

// Reporter lo implementa cada resultado; el JSON crudo es el propio resultado.
type Reporter interface{ Report() Report }

func (r Report) Text() string {
	var b strings.Builder
	for i, t := range r.Tables {
		if i > 0 {
			b.WriteByte('\n')
		}
		if t.Title != "" {
			b.WriteString(t.Title + "\n")
		}
		w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		if len(t.Head) > 0 {
			w.Write([]byte(strings.Join(t.Head, "\t") + "\n"))
		}
		for _, row := range t.Rows {
			w.Write([]byte(strings.Join(row, "\t") + "\n"))
		}
		w.Flush()
	}
	for _, n := range r.Notes {
		b.WriteString("\n• " + n)
	}
	return strings.TrimRight(b.String(), "\n")
}

// kv arma una tabla de dos columnas campo/valor, omitiendo los valores vacíos.
func kv(title string, pairs ...string) Table {
	t := Table{Title: title, Head: []string{"Campo", "Valor"}}
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			t.Rows = append(t.Rows, []string{pairs[i], pairs[i+1]})
		}
	}
	return t
}
