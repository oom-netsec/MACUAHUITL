package analysis

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// jobArg: el ID de un trabajo, o una carpeta de salida (relativa al directorio actual).
func jobArg(s string) string {
	if fi, err := os.Stat(s); err == nil && fi.IsDir() {
		if abs, err := filepath.Abs(s); err == nil {
			return abs
		}
	}
	return s
}

func analyzeJob(c *cli.Env, args []string) error {
	var round int
	var device string
	var asJSON bool
	fs, err := cli.Flags("analyze", args, func(fs *flag.FlagSet) {
		fs.IntVar(&round, "round", 0, "solo esta ronda (0 = todas)")
		fs.StringVar(&device, "device", "", "equipo (parte del nombre o la IP)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || round < 0 {
		return fmt.Errorf("uso: mctl analyze TRABAJO|CARPETA [--round N] [--device EQUIPO] [--json]")
	}
	r, err := v1.NewAnalysisServiceClient(c.Conn).AnalyzeJob(context.Background(), &v1.AnalyzeJobRequest{Job: jobArg(fs.Arg(0)), Round: uint32(round), Device: device})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func diffRounds(c *cli.Env, args []string) error {
	var from, to int
	var device string
	var asJSON bool
	fs, err := cli.Flags("diff", args, func(fs *flag.FlagSet) {
		fs.IntVar(&from, "from", 0, "ronda A")
		fs.IntVar(&to, "to", 0, "ronda B")
		fs.StringVar(&device, "device", "", "equipo (parte del nombre o la IP)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || from <= 0 || to <= 0 {
		return fmt.Errorf("uso: mctl diff TRABAJO|CARPETA --from A --to B [--device EQUIPO] [--json]")
	}
	r, err := v1.NewAnalysisServiceClient(c.Conn).DiffRounds(context.Background(), &v1.DiffRoundsRequest{Job: jobArg(fs.Arg(0)), From: uint32(from), To: uint32(to), Device: device})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func timeline(c *cli.Env, args []string) error {
	var around, device, pcap string
	var window time.Duration
	var asJSON bool
	fs, err := cli.Flags("timeline", args, func(fs *flag.FlagSet) {
		fs.StringVar(&around, "around", "", "instante RFC 3339 (2026-11-04T10:09:18Z)")
		fs.DurationVar(&window, "window", 30*time.Second, "± alrededor de --around")
		fs.StringVar(&device, "device", "", "equipo (parte del nombre o la IP)")
		fs.StringVar(&pcap, "pcap", "", "captura a correlacionar")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || window <= 0 {
		return fmt.Errorf("uso: mctl timeline TRABAJO|CARPETA [--around TS --window 30s] [--device EQUIPO] [--pcap ARCHIVO] [--json]")
	}
	req := &v1.TimelineRequest{Job: jobArg(fs.Arg(0)), Device: device, WindowSeconds: uint32(window / time.Second)}
	if around != "" {
		t, err := time.Parse(time.RFC3339, around)
		if err != nil {
			return fmt.Errorf("--around: usa RFC 3339, p. ej. 2026-11-04T10:09:18Z")
		}
		req.Around = timestamppb.New(t)
	}
	if pcap != "" {
		if req.PcapPath, err = filepath.Abs(pcap); err != nil {
			return err
		}
	}
	r, err := v1.NewAnalysisServiceClient(c.Conn).Timeline(context.Background(), req)
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  analyze  TRABAJO|CARPETA [--round N] [--device EQUIPO] [--json]   (reglas sin validar en laboratorio)
  diff     TRABAJO|CARPETA --from A --to B [--device EQUIPO] [--json]
  timeline TRABAJO|CARPETA [--around TS --window 30s] [--device EQUIPO] [--pcap ARCHIVO] [--json]`

// Area registra los comandos de analysis.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "analyze", Run: analyzeJob},
		{Name: "diff", Run: diffRounds},
		{Name: "timeline", Run: timeline},
	}}
}
