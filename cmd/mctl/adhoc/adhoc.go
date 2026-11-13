package adhoc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const usage = "run -d EQUIPO[:PUERTO]... (-c COMANDO... | -f ARCHIVO) --cred ID [--accept HUELLA] [--exclude EQUIPO] [--csv|--md|--json] [--timeout 10m]"

// target acepta "host" o "host:puerto" (un solo ':'; IPv6 va sin puerto).
func target(s string) (*v1.Target, error) {
	if i := strings.LastIndex(s, ":"); i > 0 && strings.Count(s, ":") == 1 {
		p, err := strconv.ParseUint(s[i+1:], 10, 16)
		if err != nil {
			return nil, cli.Err("mctl.backup.port_invalid", "value", s)
		}
		return &v1.Target{Address: s[:i], Port: uint32(p)}, nil
	}
	return &v1.Target{Address: s}, nil
}

func runBatch(c *cli.Env, args []string) error {
	var devs, cmds, accept, exclude cli.List
	var file, cred string
	var csv, md, asJSON bool
	timeout := 10 * time.Minute
	if _, err := cli.Flags("run", args, func(fs *flag.FlagSet) {
		fs.Var(&devs, "d", "equipo (repetible)")
		fs.Var(&cmds, "c", "comando de lectura (repetible)")
		fs.StringVar(&file, "f", "", "archivo con un comando por línea")
		fs.StringVar(&cred, "cred", "", "ID de la credencial de la bóveda")
		fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
		fs.Var(&exclude, "exclude", "equipo a excluir (repetible)")
		fs.BoolVar(&csv, "csv", false, "salida CSV")
		fs.BoolVar(&md, "md", false, "salida Markdown")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
		fs.DurationVar(&timeout, "timeout", timeout, "espera máxima del resultado")
	}); err != nil || len(devs) == 0 || cred == "" {
		return errors.New("uso: mctl " + usage)
	}
	text := strings.Join(cmds, "\n")
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		text += "\n" + string(b)
	}
	req := &v1.StartAdhocRequest{CredentialId: cred, Commands: text, AcceptedHostKeyFingerprints: accept, ExcludedDeviceIds: exclude}
	for _, d := range devs {
		t, err := target(d)
		if err != nil {
			return err
		}
		req.Targets = append(req.Targets, t)
	}
	cl := v1.NewAdhocServiceClient(c.Conn)
	st, err := cl.StartAdhoc(context.Background(), req)
	if err != nil {
		return err
	}
	if !st.Armed {
		fmt.Fprintln(c.Out, cli.T("mctl.adhoc.unarmed", "job", st.JobId, "detail", st.Detail))
		return cli.Err("mctl.adhoc.unarmed_err")
	}
	for deadline := time.Now().Add(timeout); ; time.Sleep(300 * time.Millisecond) {
		r, err := cl.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: st.JobId})
		if err != nil {
			return err
		}
		switch {
		case r.Done && r.Report == nil:
			return cli.Err("mctl.adhoc.no_results", "job", st.JobId, "state", r.State)
		case r.Done && csv:
			fmt.Fprint(c.Out, r.Csv)
		case r.Done && md:
			fmt.Fprint(c.Out, r.Markdown)
		case r.Done:
			c.PrintReport(r.Report, asJSON)
		case time.Now().After(deadline):
			return cli.Err("mctl.adhoc.timeout", "timeout", timeout, "job", st.JobId)
		default:
			continue
		}
		return nil
	}
}

// Area registra run.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "run", Run: runBatch}}}
}

const help = `  run -d EQUIPO... -c "show ..." | -f ARCHIVO --cred ID [--accept HUELLA] [--csv|--md|--json]
        (lote de solo lectura: un trabajo de Patrol de una ronda; todo comando pasa por CheckDenied)`
