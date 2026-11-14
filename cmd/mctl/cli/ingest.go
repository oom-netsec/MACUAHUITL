package cli

import (
	"flag"
	"fmt"
	"io"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// IngestFlags son las banderas de topes y de archivo que comparten los receptores
// (syslog listen, snmp traps listen y flows listen).
type IngestFlags struct {
	Rate, Burst, RateG, BurstG, Queue, RotMB, RotMin, MaxFiles int
	Name, Format                                               string
}

// IngestValues son esas banderas ya en el int32 del contrato.
type IngestValues struct {
	Rate, Burst, RateG, BurstG, Queue, RotMB, RotMin, MaxFiles int32
}

// Register agrega las banderas; defName es la plantilla por defecto del receptor, solo para la ayuda.
func (f *IngestFlags) Register(fs *flag.FlagSet, defName string) {
	fs.IntVar(&f.Rate, "rate", 0, "mensajes/s por IP de origen (100 por defecto; 1-10000)")
	fs.IntVar(&f.Burst, "burst", 0, "ráfaga por origen (2x la tasa por defecto)")
	fs.IntVar(&f.RateG, "rate-global", 0, "mensajes/s en total (1000 por defecto; 1-100000)")
	fs.IntVar(&f.BurstG, "burst-global", 0, "ráfaga global (2x la tasa por defecto)")
	fs.IntVar(&f.Queue, "queue", 0, "cola antes de escribir (4096 por defecto; 64-65536)")
	fs.IntVar(&f.RotMB, "rotate-mb", 0, "con --save, rotar cada N MB (50 por defecto; 1-1024)")
	fs.IntVar(&f.RotMin, "rotate-min", 0, "con --save, rotar cada N minutos (0 = no; 1-10080)")
	fs.StringVar(&f.Name, "name", "", "con --save, plantilla del nombre con {fecha} {hora} {origen} ("+defName+")")
	fs.IntVar(&f.MaxFiles, "max-files", 0, "con --save, archivos que se conservan (20 por defecto; 1-1000)")
	fs.StringVar(&f.Format, "format", "", "con --save: texto (por defecto), crudo o jsonl")
}

// Int32 rechaza lo que no cabe en el int32 del contrato, en vez de truncarlo en silencio.
func Int32(flagName string, v int) (int32, error) {
	if int(int32(v)) != v {
		return 0, Err("mctl.cli.out_of_range", "flag", flagName, "value", v)
	}
	return int32(v), nil
}

// Values convierte las banderas numéricas a int32; los rangos los valida el núcleo.
func (f *IngestFlags) Values() (v IngestValues, err error) {
	for _, c := range []struct {
		flag string
		in   int
		out  *int32
	}{
		{"rate", f.Rate, &v.Rate}, {"burst", f.Burst, &v.Burst}, {"rate-global", f.RateG, &v.RateG}, {"burst-global", f.BurstG, &v.BurstG},
		{"queue", f.Queue, &v.Queue}, {"rotate-mb", f.RotMB, &v.RotMB}, {"rotate-min", f.RotMin, &v.RotMin}, {"max-files", f.MaxFiles, &v.MaxFiles},
	} {
		if *c.out, err = Int32(c.flag, c.in); err != nil {
			return v, err
		}
	}
	return v, nil
}

// PrintDrops escribe el acumulado de descartes en una línea.
func PrintDrops(w io.Writer, d *v1.SyslogDrops) {
	fmt.Fprint(w, T("mctl.cli.drops", "total", d.Total, "origin", d.PorOrigen, "global", d.Global, "queue", d.ColaLlena))
	for _, s := range d.Top {
		fmt.Fprintf(w, " %s=%d", s.Source, s.Count)
	}
	fmt.Fprintln(w)
}
