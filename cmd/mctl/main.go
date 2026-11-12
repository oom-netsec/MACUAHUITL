// Command mctl es la CLI de MACUAHUITL: un cliente delgado del núcleo por el
// socket local. Los secretos se leen solo por la terminal o stdin, nunca por
// argumentos ni variables de entorno.
//
// Cada área vive en cmd/mctl/<área> y registra sus comandos en areas; este
// archivo solo despacha y arma la ayuda desde esa tabla.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/acl"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/adhoc"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/analysis"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/audit"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/backup"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/calc"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/change"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cleaner"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/credrotate"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/devices"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/diag"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/drift"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/field"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/fleet"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/forensic"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/metrics"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/patrol"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/ports"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/prefs"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/restore"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/scripts"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/security"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/snippet"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/tools"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/transfer"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/vault"
	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/visibility"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/termcolor"
	"github.com/oom-netsec/MACUAHUITL/internal/version"
)

// areas es la tabla de comandos; el orden es el de la ayuda. Un área nueva suma una línea.
var areas = []cli.Area{
	vault.Area(), patrol.Area(), audit.Area(), cli.Common,
	acl.Area(), diag.Area(), tools.Area(), security.Area(), change.Area(), visibility.Area(),
	analysis.Area(), calc.Area(), field.Area(), fleet.Area(),
	ports.Area(),
	adhoc.Area(), drift.Area(),
	cleaner.Area(),
	snippet.Area(), credrotate.Area(),
	backup.Area(),
	restore.Area(),
	forensic.Area(),
	transfer.Area(),
	metrics.Area(),
	devices.Area(),
	scripts.Area(),
	prefs.Area(),
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mctl:", err)
		os.Exit(1)
	}
}

// outIsTTY es variable para que las pruebas simulen una terminal.
var outIsTTY = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func run(args []string, stdin io.Reader, out io.Writer) error {
	usage := cli.Help(areas)
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintln(out, version.String())
		return nil
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprintln(out, usage)
		return nil
	}
	if len(args) < 1 {
		return errors.New(usage)
	}
	args, noColor := cli.StripFlag(args, "--no-color")
	if len(args) < 1 {
		return errors.New(usage)
	}
	args, lang, err := cli.StripLang(args)
	if err != nil {
		return err
	}
	if len(args) < 1 {
		return errors.New(usage)
	}
	cmd, rest, ok := cli.Find(areas, args)
	if !ok {
		return errors.New(usage)
	}
	c := &cli.Env{In: bufio.NewReader(stdin), Out: out}
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		c.TTY = f
	}
	// Conectar solo cuando el comando es válido: un error de uso no debe hablar del socket.
	// Solo --lang explícito pide idioma: mctl no lee LC_ALL, LC_MESSAGES ni LANG mientras sus textos sigan en español.
	var dialOpts []ipc.DialOption
	if lang != "" {
		dialOpts = ipc.WithLanguage(lang)
	}
	conn, err := ipc.Dial(context.Background(), dialOpts...)
	if err != nil {
		return err
	}
	defer conn.Close()
	c.Conn = conn
	color := termcolor.Enabled(outIsTTY(out), noColor, cli.HasJSON(rest), os.Getenv)
	var pal string
	if color {
		pal = c.Palette()
	}
	if !cmd.Raw { // la consola es una sesión cruda: sin sanear ni pintar
		c.Out = cli.NewOut(out, color, termcolor.Lookup(pal), termcolor.Truecolor(os.Getenv))
	}
	return cmd.Run(c, rest)
}
