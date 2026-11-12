// Package forensic son los comandos de la Fase 17 (forense de logs y fallas): todos leen.
package forensic

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// absFile lleva la ruta a absoluta: el núcleo lee el archivo, no la CLI.
func absFile(p string) (string, error) { return filepath.Abs(p) }

func msg(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("msg", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil || fs.NArg() > 1 {
		return errors.New("uso: mctl msg [MNEMONICO|PATRON] [--json]")
	}
	r, err := v1.NewForensicServiceClient(c.Conn).MsgLookup(context.Background(), &v1.MsgLookupRequest{Query: fs.Arg(0)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func crashinfo(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("crashinfo", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil || fs.NArg() != 1 {
		return errors.New("uso: mctl crashinfo ARCHIVO [--json]")
	}
	p, err := absFile(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewForensicServiceClient(c.Conn).Crashinfo(context.Background(), &v1.CrashinfoRequest{Path: p})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

// maxStdin acota el texto que se lee de la entrada estándar (el mismo tope que el núcleo).
const maxStdin = 8 << 20

// srcFlags son las opciones de fuente que comparten los comandos de logs.
type srcFlags struct {
	capture     bool
	job, device string
}

func (f *srcFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.capture, "capture", false, "usa lo que guardó el receptor syslog (outputs/syslog)")
	fs.StringVar(&f.job, "job", "", "show logging de un trabajo de Patrol (ID o carpeta)")
	fs.StringVar(&f.device, "device", "", "con --job: equipo (parte del nombre o la IP)")
}

// source arma la fuente con exactamente una de: ARCHIVO (o - para la entrada estándar), --capture o --job.
func (f srcFlags) source(c *cli.Env, fs *flag.FlagSet) (*v1.LogSource, error) {
	switch {
	case fs.NArg() == 1 && !f.capture && f.job == "":
		if fs.Arg(0) == "-" {
			b, err := io.ReadAll(io.LimitReader(c.In, maxStdin+1))
			if err != nil {
				return nil, err
			}
			if len(b) > maxStdin {
				return nil, fmt.Errorf("la entrada excede %d MiB", maxStdin>>20)
			}
			return &v1.LogSource{Text: string(b)}, nil
		}
		p, err := absFile(fs.Arg(0))
		return &v1.LogSource{Path: p}, err
	case fs.NArg() == 0 && f.capture && f.job == "":
		return &v1.LogSource{Capture: true}, nil
	case fs.NArg() == 0 && !f.capture && f.job != "":
		return &v1.LogSource{Job: jobArg(f.job), Device: f.device}, nil
	}
	return nil, errors.New("elige una fuente: ARCHIVO (o - para la entrada estándar), --capture o --job TRABAJO")
}

// jobArg: una carpeta se resuelve en el cliente; lo demás es el ID de un trabajo.
func jobArg(s string) string {
	if fi, err := os.Stat(s); err == nil && fi.IsDir() {
		if abs, err := filepath.Abs(s); err == nil {
			return abs
		}
	}
	return s
}

func patterns(c *cli.Env, args []string) error {
	var sf srcFlags
	var burst, window int
	var asJSON bool
	fs, err := cli.Flags("logs patterns", args, func(fs *flag.FlagSet) {
		sf.register(fs)
		fs.IntVar(&burst, "burst", 0, "ráfaga: N mensajes del mismo patrón (0 = 5)")
		fs.IntVar(&window, "window", 0, "ráfaga: en M segundos (0 = 60)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil || burst < 0 || window < 0 {
		return errors.New(usagePatterns)
	}
	src, err := sf.source(c, fs)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, usagePatterns)
	}
	r, err := v1.NewForensicServiceClient(c.Conn).LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: src, BurstCount: uint32(burst), BurstWindowSeconds: uint32(window)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func flaps(c *cli.Env, args []string) error {
	var sf srcFlags
	var count, window, minDelta int
	var asJSON bool
	fs, err := cli.Flags("logs flaps", args, func(fs *flag.FlagSet) {
		sf.register(fs)
		fs.IntVar(&count, "count", 0, "flapping: N transiciones (0 = 3)")
		fs.IntVar(&window, "window", 0, "flapping: en M segundos (0 = 60)")
		fs.IntVar(&minDelta, "min-delta", 0, "con --job: aviso si un contador sube N o más entre rondas (0 = 3)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil || count < 0 || window < 0 || minDelta < 0 {
		return errors.New(usageFlaps)
	}
	src, err := sf.source(c, fs)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, usageFlaps)
	}
	r, err := v1.NewForensicServiceClient(c.Conn).Flapping(context.Background(), &v1.FlappingRequest{Source: src, Count: uint32(count), WindowSeconds: uint32(window), MinDelta: uint32(minDelta)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

// listFlag acumula una opción repetida (--hide a --hide b).
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func debugs(c *cli.Env, args []string) error {
	var hide listFlag
	var famMin, rareMax, top int
	var asJSON bool
	fs, err := cli.Flags("logs debugs", args, func(fs *flag.FlagSet) {
		fs.Var(&hide, "hide", "oculta las líneas que contienen este texto (repetible)")
		fs.IntVar(&famMin, "family-min", 0, "rara si su familia tiene N líneas o más (0 = 20)")
		fs.IntVar(&rareMax, "rare-max", 0, "rara si su patrón aparece M veces o menos (0 = 2)")
		fs.IntVar(&top, "top", 0, "patrones frecuentes a listar (0 = 50)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil || fs.NArg() != 1 || famMin < 0 || rareMax < 0 || top < 0 {
		return errors.New(usageDebugs)
	}
	req := &v1.DebugFilterRequest{Noise: hide, FamilyMin: uint32(famMin), RareMax: uint32(rareMax), Top: uint32(top)}
	src, err := srcFlags{}.source(c, fs)
	if err != nil {
		return err
	}
	req.Text, req.Path = src.Text, src.Path
	r, err := v1.NewForensicServiceClient(c.Conn).DebugFilter(context.Background(), req)
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func leaks(c *cli.Env, args []string) error {
	var device string
	var rounds, growth int
	var asJSON bool
	fs, err := cli.Flags("logs leaks", args, func(fs *flag.FlagSet) {
		fs.StringVar(&device, "device", "", "equipo (parte del nombre o la IP)")
		fs.IntVar(&rounds, "rounds", 0, "rondas seguidas sin bajar (0 = 3)")
		fs.IntVar(&growth, "min-growth-kib", 0, "crecimiento mínimo en KiB (0 = 1024)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil || fs.NArg() != 1 || rounds < 0 || growth < 0 {
		return errors.New(usageLeaks)
	}
	r, err := v1.NewForensicServiceClient(c.Conn).MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: jobArg(fs.Arg(0)), Device: device, MinRounds: uint32(rounds), MinGrowthKib: uint32(growth)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

const usageLeaks = "uso: mctl logs leaks TRABAJO|CARPETA [--device EQ] [--rounds N] [--min-growth-kib K] [--json]"

const usageDebugs = "uso: mctl logs debugs ARCHIVO|- [--hide TEXTO]... [--family-min N] [--rare-max M] [--top N] [--json]"

const usageFlaps = "uso: mctl logs flaps ARCHIVO|-|--capture|--job TRABAJO [--device EQ] [--count N] [--window SEG] [--min-delta N] [--json]"

const usagePatterns = "uso: mctl logs patterns ARCHIVO|-|--capture|--job TRABAJO [--device EQ] [--burst N] [--window SEG] [--json]"

const help = `  msg [MNEMONICO|PATRON] [--json]
        (base de mensajes de Cisco: significado, causa, acción y comandos de lectura; acepta comodines: %PLATFORM-3-*)
  crashinfo ARCHIVO [--json]
        (motivo, proceso, traceback, versión y CPU/memoria de un crashinfo de texto; un core binario solo se identifica; solo lee)
  logs patterns ARCHIVO|-|--capture|--job TRABAJO [--device EQ] [--burst N] [--window SEG] [--json]
        (syslog agrupado por patrón: cuenta, marca ráfagas (N en M segundos, 5 en 60 por defecto) e inestabilidad y anota cada patrón con la base de mensajes; solo lee)
  logs flaps ARCHIVO|-|--capture|--job TRABAJO [--device EQ] [--count N] [--window SEG] [--min-delta N] [--json]
        (interfaces con N transiciones en M segundos (3 en 60) aunque duren milisegundos; con --job también los saltos de carrier/resets de show interfaces entre rondas; solo lee)
  logs debugs ARCHIVO|- [--hide TEXTO]... [--family-min N] [--rare-max M] [--top N] [--json]
        (debug pegado o en archivo: agrupa líneas repetidas, oculta el ruido y marca anomalías; sin conexión a ningún equipo)
  logs leaks TRABAJO|CARPETA [--device EQ] [--rounds N] [--min-growth-kib K] [--json]
        (procesos cuya memoria de show processes memory sorted crece sin bajar entre rondas de Patrol; solo lee)`

// Area registra los comandos de forense.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "msg", Run: msg},
		{Name: "crashinfo", Run: crashinfo},
		{Name: "logs patterns", Run: patterns},
		{Name: "logs flaps", Run: flaps},
		{Name: "logs debugs", Run: debugs},
		{Name: "logs leaks", Run: leaks},
	}}
}
