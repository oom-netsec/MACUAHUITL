// Command macuahuitld es el núcleo de MACUAHUITL: corre como servicio de usuario
// de systemd (en Windows, lanzado por el usuario) y atiende a la UI y a mctl por un socket Unix o un named pipe (spec §5).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/core"
	"github.com/oom-netsec/MACUAHUITL/internal/core/power"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/internal/version"
)

func main() {
	sys.ConsoleUTF8() // en Windows, la consola cp437 rompe los acentos
	showVersion := flag.Bool("version", false, "imprime la versión y sale")
	lang := flag.String("lang", "", "idioma de los avisos de la consola: en (por omisión) o es")
	flag.Parse()
	l, err := parseLang(*lang)
	if err != nil {
		fmt.Fprintln(os.Stderr, "macuahuitld:", err)
		os.Exit(2)
	}
	consoleLang = l
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(sys.Harden); err != nil {
		msg := i18n.In(consoleLang, err)
		fmt.Fprintln(os.Stderr, "macuahuitld:", msg)
		// Sin consola el error se perdería: va al registro, salvo si otro núcleo ya tiene el canal (no se toca su registro).
		if st := core.ResolvePaths(os.Getenv).State; st != "" {
			if !errors.Is(err, ipc.ErrAlreadyRunning) && !sys.Privileged() { // elevado no se escribe en el registro
				sys.LogFailure(filepath.Join(st, logName), "macuahuitld: "+msg)
			}
			writeStartup(st, err, ipc.CoreRunning) // la UI lo lee; un proceso elevado no escribe (sys.WriteStartup)
		}
		os.Exit(1)
	}
}

// startupWanted dice si el fallo va a macuahuitld.startup (ADR 0012 g). No cuando ya corre un núcleo del mismo usuario (la
// app se conecta a ese), pero sí cuando el canal lo tiene otro usuario: eso lo envuelve en ErrAlreadyRunning.
func startupWanted(err error) bool {
	var ie *i18n.Error
	return err != nil && (!errors.Is(err, ipc.ErrAlreadyRunning) || (errors.As(err, &ie) && ie.Code == "ipc.err.pipe_other_user"))
}

// writeStartup deja la causa en macuahuitld.startup si startupWanted y no corre ya un núcleo sano del mismo usuario (una
// causa vieja sobre un núcleo que sirve sería falsa). running es la sonda, inyectable para probarla; si falla se escribe.
func writeStartup(state string, err error, running func() (bool, error)) {
	if !startupWanted(err) {
		return
	}
	if up, rerr := running(); rerr == nil && up {
		return
	}
	sys.WriteStartup(state, err)
}

// consoleErr es un error con código que se escribe en el idioma de la consola; conserva el código (Unwrap) para macuahuitld.startup.
type consoleErr struct{ err error }

func (e consoleErr) Error() string { return i18n.In(consoleLang, e.err) }
func (e consoleErr) Unwrap() error { return e.err }

// logName es el registro del núcleo dentro de State (Windows, ADR 0012 g).
const logName = "macuahuitld.log"

// consoleLang es el idioma de lo que el daemon imprime en su consola; sin --lang, el canónico (inglés).
var consoleLang = i18n.En

// run recibe el endurecimiento como dependencia: en producción sys.Harden; las pruebas pasan una falsa (mlockall no va en go test).
func run(harden func() ([]i18n.Text, error)) error {
	if sys.Privileged() {
		key := "harden.err.root"
		if runtime.GOOS == "windows" {
			key = "harden.err.elevated"
		}
		return consoleErr{i18n.New(key, nil)}
	}
	hw, err := harden() // antes de tocar cualquier secreto
	if err != nil {
		return consoleErr{err}
	}
	warns := make([]string, len(hw))
	for i, w := range hw {
		warns[i] = w.In(i18n.En) // la auditoría va siempre en inglés
	}
	p := core.ResolvePaths(os.Getenv)
	if p.Config == "" || p.Data == "" || p.State == "" {
		return consoleErr{i18n.New("harden.err.localappdata", nil)} // solo Windows: no se cae a %APPDATA%
	}
	if runtime.GOOS != "windows" && p.Runtime == "" { // en Windows no hay carpeta runtime: el canal es un named pipe
		return consoleErr{i18n.New("harden.err.runtime_dir", nil)}
	}
	// El canal primero: un segundo núcleo que pierde el pipe (o el socket) sale sin tocar nada del primero, ni su registro.
	addr, err := ipc.CoreAddr(p.Runtime)
	if err != nil {
		return err
	}
	l, err := ipc.Listen(addr)
	if err != nil {
		return err
	}
	sys.ClearStartup(p.State) // el núcleo arrancó: la causa de un fallo anterior ya no vale
	// Sin consola (-H windowsgui) la salida va a <State>\macuahuitld.log; en Linux no hace nada (stderr, journal).
	if err := sys.RedirectStderr(filepath.Join(p.State, logName)); err != nil {
		l.Close()
		return err
	}
	c, err := core.New(p, core.Options{Inhibitor: power.NewLogind(), HardenWarnings: warns})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, stop := sys.SignalContext()
	defer stop()
	go power.Watch(ctx, c.OnSleep, c.OnLock)
	for _, w := range hw {
		fmt.Fprintln(os.Stderr, consolePrefix(), w.In(consoleLang))
	}
	return c.Serve(ctx, l)
}

// consolePrefix es «warning:» o «aviso:» según el idioma de la consola.
func consolePrefix() string { return i18n.Msg(consoleLang, "harden.prefix", nil) }

// parseLang valida -lang: vacío es el canónico (inglés); es, en o una etiqueta es-MX/en-US. Otro valor es un error, no el
// idioma por omisión en silencio.
func parseLang(v string) (string, error) {
	if v == "" {
		return i18n.En, nil
	}
	t, n := strings.ToLower(strings.TrimSpace(v)), i18n.Normalize(v)
	if t != n && !strings.HasPrefix(t, n+"-") && !strings.HasPrefix(t, n+"_") {
		return "", fmt.Errorf("invalid -lang %q (use es or en)", v)
	}
	return n, nil
}
