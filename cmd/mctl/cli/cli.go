// Package cli es lo compartido por las áreas de mctl: el contexto de un comando
// (conexión, entrada, salida saneada), las banderas comunes y la tabla de comandos
// con la que main despacha y arma la ayuda.
package cli

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Env es lo que recibe cada comando: cada área arma sus clientes gRPC desde Conn.
type Env struct {
	In   *bufio.Reader
	TTY  *os.File  // entrada si es una terminal; nil si no
	Out  io.Writer // salida saneada (y pintada); cruda solo en comandos Raw
	Conn *ipc.ClientConn
}

// Command es una entrada de la tabla: Name es "área comando" o una palabra ("analyze").
type Command struct {
	Name string
	Run  func(*Env, []string) error
	Raw  bool // sesión cruda (console): sin sanear ni pintar
}

// Area agrupa los comandos de un módulo y las líneas que le tocan en la ayuda.
type Area struct {
	Usage    string
	Commands []Command
}

// Find busca el comando de args: primero por una palabra, luego por dos y por último por tres.
func Find(areas []Area, args []string) (Command, []string, bool) {
	for _, a := range areas {
		for _, c := range a.Commands {
			if c.Name == args[0] {
				return c, args[1:], true
			}
		}
	}
	if len(args) < 2 {
		return Command{}, nil, false
	}
	for _, a := range areas {
		for _, c := range a.Commands {
			if c.Name == args[0]+" "+args[1] {
				return c, args[2:], true
			}
		}
	}
	if len(args) < 3 {
		return Command{}, nil, false
	}
	for _, a := range areas {
		for _, c := range a.Commands {
			if c.Name == args[0]+" "+args[1]+" "+args[2] {
				return c, args[3:], true
			}
		}
	}
	return Command{}, nil, false
}

// helpEn es la ayuda en inglés (el idioma canónico), línea por línea la misma que los Usage de las áreas, que son la
// versión en español (--lang es). help_test.go vigila que tengan las mismas líneas.
//
//go:embed help_en.txt
var helpEn string

// Help arma el texto de uso en el idioma de mctl: cabecera, la ayuda de las áreas en orden (en inglés el texto
// embebido; con --lang es, el Usage de cada área) y --version.
func Help(areas []Area) string {
	var b strings.Builder
	if locale == "en" {
		b.WriteString("usage: mctl <command>\n")
		b.WriteString(helpEn)
	} else {
		b.WriteString("uso: mctl <comando>\n")
		for _, a := range areas {
			b.WriteString(a.Usage)
			b.WriteByte('\n')
		}
	}
	b.WriteString("  --version")
	return b.String()
}

// Wipe pone en ceros los secretos leídos al terminar el comando.
func Wipe(bs ...[]byte) {
	for _, b := range bs {
		for i := range b {
			b[i] = 0
		}
	}
}

// Secret lee un secreto sin eco en una terminal, o una línea de stdin si no lo es.
func (c *Env) Secret(prompt string) ([]byte, error) {
	if c.TTY != nil {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(c.TTY.Fd()))
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	line, err := c.In.ReadString('\n')
	if err != nil && line == "" {
		return nil, ErrWrap("mctl.cli.stdin_expected", err, "prompt", strings.TrimSpace(prompt))
	}
	return []byte(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")), nil
}

// PrintReport imprime el texto de un informe o, con --json, su JSON.
func (c *Env) PrintReport(r *v1.ToolReport, asJSON bool) {
	if asJSON {
		fmt.Fprintln(c.Out, r.Json)
		return
	}
	fmt.Fprintln(c.Out, r.Text)
}

// Flags acepta opciones antes o después de los argumentos: "diag ping HOST -o count=3".
func Flags(name string, args []string, setup func(*flag.FlagSet)) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if setup != nil {
		setup(fs)
	}
	var opts, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			rest = append(rest, a)
			continue
		}
		opts = append(opts, a)
		name := strings.TrimLeft(a, "-")
		if f := fs.Lookup(strings.SplitN(name, "=", 2)[0]); f != nil && !strings.Contains(name, "=") {
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
				if i+1 < len(args) {
					i++
					opts = append(opts, args[i])
				}
			}
		}
	}
	return fs, fs.Parse(append(opts, rest...))
}

// OneArg exige exactamente un argumento posicional (un ID).
func OneArg(name string, args []string) (string, error) {
	fs, err := Flags(name, args, nil)
	if err != nil {
		return "", err
	}
	if fs.NArg() != 1 {
		return "", Err("mctl.cli.needs_id", "name", name)
	}
	return fs.Arg(0), nil
}

// List es una bandera repetible.
type List []string

func (l *List) String() string     { return strings.Join(*l, ",") }
func (l *List) Set(v string) error { *l = append(*l, v); return nil }

// Common es la nota de las banderas comunes: no tiene comandos, solo su línea en la ayuda.
var Common = Area{Usage: `  (cualquier comando: --no-color o NO_COLOR desactivan el color; con --json o sin TTY no hay color)
  (antes del comando: --lang es|en pide los mensajes del núcleo en ese idioma; sin ella, inglés. mctl no lee LC_ALL, LC_MESSAGES ni LANG)`}
