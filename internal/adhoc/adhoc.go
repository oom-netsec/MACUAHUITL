// Package adhoc valida los comandos de un lote ad-hoc y consolida lo que
// Patrol recolectó en una tabla por equipo y comando (texto, CSV o Markdown).
//
// Solo lee: todo comando pasa por playbook.CheckDenied. No hace: conectarse a
// equipos; el lote lo corre un trabajo de Patrol de una ronda.
package adhoc

import (
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
			if out, ok := d.Outputs[capture.Key(c)]; ok {
				row.OK, row.Output = true, strings.TrimRight(out, "\r\n")
			} else if d.State != "completed" && d.Detail != "" {
				row.Note = d.Detail
			} else if d.State == "completed" {
				row.Note = "sin salida (comando inválido en el equipo)"
			} else {
				row.Note = "sin salida (equipo " + or(d.State, "sin ronda") + ")"
			}
			r.Rows = append(r.Rows, row)
		}
	}
	return r
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (r Row) state() string {
	if r.OK {
		return "ok"
	}
	return "sin salida"
}

// cell: lo que se escribe en la celda; sin salida va la nota.
func (r Row) cell() string {
	if r.OK {
		return r.Output
	}
	return r.Note
}

// CSV neutraliza celdas que una hoja de cálculo ejecutaría como fórmula: la salida es de un equipo, no de confianza.
func (r Report) CSV() string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	w.Write([]string{"equipo", "direccion", "comando", "estado", "salida"})
	for _, x := range r.Rows {
		w.Write([]string{safe(x.Device), safe(x.Address), safe(x.Command), x.state(), safe(x.cell())})
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
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("| Equipo | Dirección | Comando | Estado | Salida |\n|---|---|---|---|---|\n")
	html := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	esc := func(s string) string {
		return strings.NewReplacer("|", `\|`, "\r", "", "\n", "<br>").Replace(html.Replace(s))
	}
	for _, x := range r.Rows {
		cmd := strings.ReplaceAll(esc(x.Command), "`", "&#96;")
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n", esc(x.Device), esc(x.Address), cmd, x.state(), esc(x.cell()))
	}
	return b.String()
}

// Text es la vista por equipo: encabezado y, por comando, su salida completa.
func (r Report) Text() string {
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
			fmt.Fprintf(&b, "SIN SALIDA: %s\n", x.Note)
		}
	}
	n := 0
	for _, ok := range whole {
		if ok {
			n++
		}
	}
	fmt.Fprintf(&b, "\n%d equipos, %d con salida completa\n", r.Devices, n)
	return b.String()
}
