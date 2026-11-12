// Package metrics son los comandos de datos para gráficas y el frente del switch: `mctl job metrics` y `mctl ports status`.
package metrics

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// jobMetrics: job metrics TRABAJO|CARPETA [--device EQ] [--iface I]... [--top N] [--max-points N] [--csv|--json]
func jobMetrics(c *cli.Env, args []string) error {
	var device string
	var ifaces cli.List
	var top, maxPoints int
	var asCSV, asJSON bool
	fs, err := cli.Flags("job metrics", args, func(fs *flag.FlagSet) {
		fs.StringVar(&device, "device", "", "solo este equipo (dirección o nombre)")
		fs.Var(&ifaces, "iface", "interfaz concreta (repetible); anula --top")
		fs.IntVar(&top, "top", 0, "interfaces con más utilización (12 por omisión, máximo 64)")
		fs.IntVar(&maxPoints, "max-points", 0, "puntos por serie, los más recientes (500 por omisión, máximo 5000)")
		fs.BoolVar(&asCSV, "csv", false, "una fila por métrica y punto: equipo,serie,nombre,ronda,hora,metrica,valor")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || (asCSV && asJSON) {
		return errors.New("uso: mctl job metrics TRABAJO|CARPETA [--device EQ] [--iface I]... [--top N] [--max-points N] [--csv|--json]")
	}
	req := &v1.GetJobMetricsRequest{Device: device, Interfaces: ifaces, MaxInterfaces: int32(top), MaxPoints: int32(maxPoints)}
	if st, err := os.Stat(fs.Arg(0)); err == nil && st.IsDir() {
		if req.Dir, err = filepath.Abs(fs.Arg(0)); err != nil {
			return err
		}
	} else {
		req.JobId = fs.Arg(0)
	}
	r, err := v1.NewMetricsServiceClient(c.Conn).GetJobMetrics(context.Background(), req)
	if err != nil {
		return err
	}
	switch {
	case asJSON:
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(r)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
	case asCSV:
		return writeCSV(c, r)
	default:
		writeText(c, r)
	}
	return nil
}

func ts(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339) }

func f(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func writeCSV(c *cli.Env, r *v1.GetJobMetricsResponse) error {
	w := csv.NewWriter(c.Out)
	w.Write([]string{"equipo", "serie", "nombre", "ronda", "hora", "metrica", "valor"})
	for _, d := range r.Devices {
		who := d.Hostname
		if who == "" {
			who = d.Address
		}
		row := func(serie, name string, round int32, at int64, metric, val string) {
			w.Write([]string{who, serie, name, strconv.Itoa(int(round)), ts(at), metric, val})
		}
		for _, p := range d.Cpu {
			row("cpu", "", p.Round, p.AtMs, "5s", f(p.FiveSec))
			row("cpu", "", p.Round, p.AtMs, "1min", f(p.OneMin))
			row("cpu", "", p.Round, p.AtMs, "5min", f(p.FiveMin))
		}
		for _, m := range d.Memory {
			for _, p := range m.Points {
				row("memoria", m.Pool, p.Round, p.AtMs, "usado", strconv.FormatInt(p.Used, 10))
				row("memoria", m.Pool, p.Round, p.AtMs, "libre", strconv.FormatInt(p.Free, 10))
				row("memoria", m.Pool, p.Round, p.AtMs, "total", strconv.FormatInt(p.Total, 10))
			}
		}
		for _, s := range d.Interfaces {
			for _, p := range s.Points {
				row("interfaz", s.Name, p.Round, p.AtMs, "bps_entrada", f(p.InBps))
				row("interfaz", s.Name, p.Round, p.AtMs, "bps_salida", f(p.OutBps))
				if s.BwKbit > 0 {
					row("interfaz", s.Name, p.Round, p.AtMs, "util_entrada_pct", f(p.InUtilPct))
					row("interfaz", s.Name, p.Round, p.AtMs, "util_salida_pct", f(p.OutUtilPct))
				}
				if p.DeltaOk { // sin diferencias válidas no se escriben ceros que parezcan datos
					for _, m := range []struct {
						n string
						v int64
					}{{"errores_entrada", p.InErrors}, {"errores_salida", p.OutErrors}, {"crc", p.Crc}, {"resets", p.Resets}, {"descartes_entrada", p.InDrops}, {"descartes_salida", p.OutDrops}} {
						row("interfaz", s.Name, p.Round, p.AtMs, m.n, strconv.FormatInt(m.v, 10))
					}
				}
			}
		}
	}
	w.Flush()
	return w.Error()
}

func writeText(c *cli.Env, r *v1.GetJobMetricsResponse) {
	for _, d := range r.Devices {
		fmt.Fprintf(c.Out, "%s (%s) · %d rondas\n", d.Hostname, d.Address, d.Rounds)
		if n := len(d.Cpu); n > 0 {
			l := d.Cpu[n-1]
			var peak float64
			for _, p := range d.Cpu {
				peak = max(peak, p.FiveSec)
			}
			fmt.Fprintf(c.Out, "  CPU    último 5s/1min/5min: %s/%s/%s %%   pico 5s: %s %%\n", f(l.FiveSec), f(l.OneMin), f(l.FiveMin), f(peak))
		}
		for _, m := range d.Memory {
			if n := len(m.Points); n > 0 {
				l := m.Points[n-1]
				fmt.Fprintf(c.Out, "  Memoria %-10s usado %d de %d bytes (%.1f %%)\n", m.Pool, l.Used, l.Total, float64(l.Used)*100/float64(max(l.Total, 1)))
			}
		}
		if len(d.Interfaces) > 0 {
			tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  INTERFAZ\tBW\tPICO UTIL %\tENTRADA bps\tSALIDA bps\tERRORES\tDESCARTES\tCRC\tRESETS")
			for _, s := range d.Interfaces {
				var in, out float64
				var errs, drops, crc, resets int64
				for _, p := range s.Points {
					in, out = p.InBps, p.OutBps
					if p.DeltaOk {
						errs += p.InErrors + p.OutErrors
						drops += p.InDrops + p.OutDrops
						crc += p.Crc
						resets += p.Resets
					}
				}
				bw := "?"
				if s.BwKbit > 0 {
					bw = strconv.FormatInt(s.BwKbit/1000, 10) + "M"
				}
				fmt.Fprintf(tw, "  %s\t%s\t%.2f\t%.0f\t%.0f\t%d\t%d\t%d\t%d\n", s.Name, bw, s.PeakUtilPct, in, out, errs, drops, crc, resets)
			}
			tw.Flush()
			if int(d.InterfaceTotal) > len(d.Interfaces) {
				fmt.Fprintf(c.Out, "  (%d de %d interfaces; --top N o --iface NOMBRE para otras)\n", len(d.Interfaces), d.InterfaceTotal)
			}
		}
		for _, w := range d.Warnings {
			fmt.Fprintf(c.Out, "  aviso: %s\n", w)
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	if len(r.Devices) == 0 && len(r.Warnings) == 0 {
		fmt.Fprintln(c.Out, "el trabajo no tiene datos de equipos")
	}
}

// ports status TRABAJO|CARPETA [--device EQ] [--json]   |   ports status --device HOST[:PUERTO] --cred ID [--accept-host-key FP]... [--legacy-ssh] [--json]
func portsStatus(c *cli.Env, args []string) error {
	var device, cred string
	var accepted cli.List
	var legacy, asJSON bool
	fs, err := cli.Flags("ports status", args, func(fs *flag.FlagSet) {
		fs.StringVar(&device, "device", "", "con un trabajo: el equipo (si tiene varios); sin trabajo: el switch a consultar en vivo, HOST[:PUERTO]")
		fs.StringVar(&cred, "cred", "", "en vivo: ID de la credencial de la bóveda")
		fs.Var(&accepted, "accept-host-key", "en vivo: huella SHA256 de la llave de host a aceptar (repetible)")
		fs.BoolVar(&legacy, "legacy-ssh", false, "en vivo: equipos con SSH antiguo (queda auditado)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 0 && device == "") {
		return errors.New("uso: mctl ports status TRABAJO|CARPETA [--device EQ] [--json]  |  mctl ports status --device HOST[:PUERTO] --cred ID [--accept-host-key SHA256:...] [--legacy-ssh] [--json]")
	}
	req := &v1.GetPortStatusRequest{CredentialId: cred, AcceptedHostKeyFingerprints: accepted, LegacySsh: legacy}
	if a := fs.Arg(0); a != "" {
		req.Device = device
		if st, err := os.Stat(a); err == nil && st.IsDir() {
			if req.Dir, err = filepath.Abs(a); err != nil {
				return err
			}
		} else {
			req.JobId = a
		}
	} else if req.Device, req.Port, err = cli.SplitHost(device); err != nil {
		return err
	}
	r, err := v1.NewMetricsServiceClient(c.Conn).GetPortStatus(context.Background(), req)
	if err != nil {
		if i := strings.Index(err.Error(), "SHA256:"); i >= 0 && strings.Contains(err.Error(), "llave de host") {
			return fmt.Errorf("%w\nsi esa huella es la del equipo, repite con --accept-host-key %s", err, strings.Fields(err.Error()[i:])[0])
		}
		return err
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(r)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
		return nil
	}
	fmt.Fprintf(c.Out, "%s (%s) · %s · %s\n", r.Hostname, r.Address, r.Source, ts(r.AtMs))
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PUERTO\tM/S/N\tESTADO\tVLAN\tDÚPLEX\tVELOCIDAD\tTIPO\tNOTAS\tDESCRIPCIÓN")
	for _, p := range r.Ports {
		var notes []string
		if p.Trunk {
			notes = append(notes, "trunk")
		}
		if p.Channel != "" {
			notes = append(notes, p.Channel+"("+p.ChannelFlags+")")
		}
		fmt.Fprintf(tw, "%s\t%d/%d/%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Module, p.Stack, p.Number, p.Status, p.Vlan, p.Duplex, p.Speed, p.Type, strings.Join(notes, " "), p.Description)
	}
	tw.Flush()
	for _, ch := range r.Channels {
		var m []string
		for _, x := range ch.Members {
			m = append(m, x.Port+"("+x.Flags+")")
		}
		fmt.Fprintf(c.Out, "canal %s (%s, %s): %s\n", ch.Name, ch.State, ch.Protocol, strings.Join(m, " "))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	return nil
}

const help = `  job metrics TRABAJO|CARPETA [--device EQ] [--iface I]... [--top N] [--max-points N] [--csv|--json]
        (CPU, memoria por pool y tráfico/errores por interfaz, ronda por ronda; lo que el playbook no recolectó viene con aviso. Playbook: ios-xe/metricas)
  ports status TRABAJO|CARPETA [--device EQ] [--json]  |  ports status --device HOST[:PUERTO] --cred ID [--accept-host-key SHA256:...] [--legacy-ssh] [--json]
        (estado de los puertos físicos de un switch para el frente: de la evidencia de un trabajo (show interfaces status, trunk y etherchannel summary) o en vivo por SSH, solo lectura)`

// Area registra los comandos de métricas.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "job metrics", Run: jobMetrics},
		{Name: "ports status", Run: portsStatus},
	}}
}
