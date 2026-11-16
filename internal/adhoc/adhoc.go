// Package adhoc valida los comandos de un lote ad-hoc y consolida lo que
// Patrol recolectó en una tabla por equipo y comando (texto, CSV o Markdown).
//
// Solo lee: todo comando pasa por playbook.CheckDenied. No hace: conectarse a
// equipos; el lote lo corre un trabajo de Patrol de una ronda.
package adhoc

import (
	"encoding/csv"
	"fmt"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// MaxCommands acota el lote: cada comando es una ida y vuelta por equipo.
const MaxCommands = 50

// Commands devuelve los comandos del texto (uno por línea; vacías y "!" se ignoran).
// Un solo comando que no sea de lectura rechaza todo el lote.
func Commands(text string) ([]string, error) {
	p, err := playbook.Ephemeral("ios-xe", text)
	if err != nil {
		return nil, err
	}
	if len(p.Commands) > MaxCommands {
		return nil, i18n.New("adhoc.err.max", i18n.A("n", len(p.Commands), "max", MaxCommands))
	}
	out := make([]string, len(p.Commands))
	for i, c := range p.Commands {
		out[i] = c.Text
	}
	return out, nil
}

// Row es la salida de un comando en un equipo. Note explica por qué no hay salida.
type Row struct {
	Device  string `json:"device"`
	Address string `json:"address"`
	Command string `json:"command"`
	OK      bool   `json:"ok"`
	Output  string `json:"output"`
	Note    string `json:"note,omitempty"`
	// NoteTx es Note como texto de catálogo (vacío si es el detalle del equipo tal cual): ReportL lo traduce en el JSON.
	NoteTx i18n.Text `json:"-"`
}

type Report struct {
	Commands []string `json:"commands"`
	Devices  int      `json:"devices"`
	Rows     []Row    `json:"rows"`
}

// Build cruza equipos y comandos. Un comando sin salida (inválido en el equipo,
// o el equipo no completó) queda como fila sin salida, nunca se omite.
func Build(devs []capture.Device, cmds []string) Report {
	r := Report{Commands: cmds, Devices: len(devs)}
	for _, d := range devs {
		name := d.Hostname
		if name == "" {
			name = d.Address
		}
		for _, c := range cmds {
			row := Row{Device: name, Address: d.Address, Command: c}
			// La evidencia y los cortados guardan el comando pasado por mask.Cmd: se busca por el crudo y por el enmascarado.
			k, km := capture.Key(c), capture.Key(mask.Cmd(d.Platform, c))
			out, ok := d.Outputs[k]
			if !ok {
				out, ok = d.Outputs[km]
			}
			if ok {
				row.OK, row.Output = true, strings.TrimRight(out, "\r\n")
			} else if d.State == "partial" && slices.ContainsFunc(d.Cut, func(x string) bool { kx := capture.Key(x); return kx == k || kx == km }) {
				row.Note = d.Detail // solo el comando cortado lleva el detalle del corte
			} else if d.State != "completed" && d.State != "partial" && d.Detail != "" {
				row.Note = d.Detail
			} else if d.State == "completed" || d.State == "partial" {
				row.NoteTx = i18n.Tx("adhoc.note.invalid")
			} else if d.State == "" {
				row.NoteTx = i18n.Tx("adhoc.note.no_round")
			} else {
				row.NoteTx = i18n.Tx("adhoc.note.device", "state", d.State)
			}
			if !row.NoteTx.Empty() {
				row.Note = row.NoteTx.In(i18n.Es)
			}
			r.Rows = append(r.Rows, row)
		}
	}
	return r
}

func (r Row) state(loc string) string {
	if r.OK {
		return "ok"
	}
	return i18n.Msg(loc, "adhoc.rep.state_none", nil)
}

// cell: lo que se escribe en la celda; sin salida va la nota.
func (r Row) cell() string {
	if r.OK {
		return r.Output
	}
	return r.Note
}

// CSV neutraliza celdas que una hoja de cálculo ejecutaría como fórmula: la salida es de un equipo, no de confianza.
func (r Report) CSV(loc string) string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	w.Write(strings.Split(i18n.Msg(loc, "adhoc.rep.csv_header", nil), ","))
	for _, x := range r.Rows {
		w.Write([]string{safe(x.Device), safe(x.Address), safe(x.Command), x.state(loc), safe(x.cell())})
	}
	w.Flush()
	return b.String()
}

func safe(c string) string {
	if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
		return "'" + c
	}
	return c
}

// Markdown escapa HTML, barras y comillas invertidas: nombres y salidas son de un equipo, no de confianza.
func (r Report) Markdown(loc string) string {
	var b strings.Builder
	b.WriteString(i18n.Msg(loc, "adhoc.rep.md_header", nil) + "\n|---|---|---|---|---|\n")
	html := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	esc := func(s string) string {
		return strings.NewReplacer("|", `\|`, "\r", "", "\n", "<br>").Replace(html.Replace(s))
	}
	for _, x := range r.Rows {
		cmd := strings.ReplaceAll(esc(x.Command), "`", "&#96;")
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n", esc(x.Device), esc(x.Address), cmd, x.state(loc), esc(x.cell()))
	}
	return b.String()
}

// Text es la vista por equipo en el idioma loc: encabezado y, por comando, su salida completa.
func (r Report) Text(loc string) string {
	var b strings.Builder
	whole, last := map[string]bool{}, ""
	for _, x := range r.Rows {
		if _, seen := whole[x.Address]; !seen {
			whole[x.Address] = true
		}
		whole[x.Address] = whole[x.Address] && x.OK
		if x.Address != last {
			fmt.Fprintf(&b, "== %s (%s) ==\n", x.Device, x.Address)
			last = x.Address
		}
		fmt.Fprintf(&b, "-- %s\n", x.Command)
		if x.OK {
			b.WriteString(x.Output + "\n")
		} else {
			b.WriteString(i18n.Msg(loc, "adhoc.rep.no_output", i18n.A("note", x.Note)) + "\n")
		}
	}
	n := 0
	for _, ok := range whole {
		if ok {
			n++
		}
	}
	b.WriteString("\n" + i18n.Msg(loc, "adhoc.rep.summary", i18n.A("n", r.Devices, "ok", n)) + "\n")
	return b.String()
}
