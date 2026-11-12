// Package calc reúne las calculadoras de bolsillo del ingeniero de redes
// (direccionamiento, MTU, TCP, QoS, óptica, selección BGP). Todo es cálculo puro:
// sin red, sin archivos, sin estado. El núcleo lo expone por gRPC para que mctl y
// la UI lleguen al mismo resultado por el mismo camino.
package calc

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Table es una tabla lista para mostrar: la UI la pinta como <table> y mctl como
// texto alineado. Así cada calculadora define su presentación una sola vez.
//
// Título, encabezados y etiquetas de fila llevan además su clave del catálogo (calc.title.*, calc.col.*,
// calc.row.*): el texto en español sale de ese mismo catálogo y las claves viajan al front para no leer el texto.
type Table struct {
	Title     string      `json:"title"`
	TitleKey  string      `json:"titleKey,omitempty"`
	TitleArgs i18n.Args   `json:"titleArgs,omitempty"`
	Head      []string    `json:"head"`
	HeadKeys  []string    `json:"headKeys,omitempty"` // uno por celda de Head
	Rows      [][]string  `json:"rows"`
	RowKeys   []string    `json:"rowKeys,omitempty"` // uno por fila: clave de la etiqueta de la primera celda, o "" si es un dato
	RowArgs   []i18n.Args `json:"rowArgs,omitempty"`
}

// Note es una nota con su clave del catálogo (calc.note.*) y los valores de sus argumentos.
type Note struct {
	Key  string    `json:"key"`
	Args i18n.Args `json:"args,omitempty"`
}

// Report es la vista legible de un resultado: tablas y notas explicativas. NoteItems repite Notes con su clave.
type Report struct {
	Tables    []Table  `json:"tables"`
	Notes     []string `json:"notes"`
	NoteItems []Note   `json:"noteItems,omitempty"`
}

// addNote agrega una nota de catálogo (kv: pares nombre, valor) al texto en español y a su forma estructurada.
func addNote(texts *[]string, items *[]Note, key string, kv ...any) {
	n := Note{Key: key, Args: i18n.A(kv...)}
	*texts = append(*texts, i18n.Msg(i18n.Es, key, n.Args))
	*items = append(*items, n)
}

// titled es una tabla con título y encabezados de catálogo.
func titled(key string, args i18n.Args, headKeys ...string) Table {
	t := Table{Title: i18n.Msg(i18n.Es, key, args), TitleKey: key, TitleArgs: args, HeadKeys: headKeys}
	for _, k := range headKeys {
		t.Head = append(t.Head, i18n.Msg(i18n.Es, k, nil))
	}
	return t
}

// add agrega una fila; label es la clave de la etiqueta de la primera celda ("" si es un dato) y args sus argumentos.
func (t *Table) add(label string, args i18n.Args, cells ...string) {
	if label != "" {
		cells[0] = i18n.Msg(i18n.Es, label, args)
	}
	t.Rows = append(t.Rows, cells)
	t.RowKeys = append(t.RowKeys, label)
	t.RowArgs = append(t.RowArgs, args)
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

// kv arma una tabla de dos columnas campo/valor, omitiendo los valores vacíos. Las etiquetas son claves del
// catálogo (string) o lbl con argumentos.
func kv(titleKey string, titleArgs i18n.Args, pairs ...any) Table {
	t := titled(titleKey, titleArgs, "calc.col.field", "calc.col.value")
	for i := 0; i+1 < len(pairs); i += 2 {
		v := pairs[i+1].(string)
		if v == "" {
			continue
		}
		switch l := pairs[i].(type) {
		case string:
			t.add(l, nil, "", v)
		case lbl:
			t.add(l.key, l.args, "", v)
		default:
			panic(fmt.Sprintf("calc: etiqueta inválida %T", l))
		}
	}
	return t
}

// lbl es una etiqueta de fila con argumentos.
type lbl struct {
	key  string
	args i18n.Args
}
