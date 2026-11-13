package backup

import (
	"context"
	"encoding/json"
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

const runUsage = "backup run -d EQUIPO[:PUERTO]... --cred ID [--startup] [--keep N] [--every 24h --rounds N] [--secrets] [--accept HUELLA] [--exclude EQUIPO] [--timeout 10m] [--json]"

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

// runFlags son las opciones de backup run, compartidas con backup diff --now.
type runFlags struct {
	devs, accept, exclude cli.List
	cred                  string
	startup, secrets      bool
	keep, rounds          int
	every, timeout        time.Duration
}

func (f *runFlags) set(fs *flag.FlagSet) {
	fs.Var(&f.devs, "d", "equipo (repetible)")
	fs.StringVar(&f.cred, "cred", "", "ID de la credencial de la bóveda")
	fs.BoolVar(&f.startup, "startup", false, "además del running-config, el startup-config")
	fs.BoolVar(&f.secrets, "secrets", false, "sin enmascarar secretos (el archivo queda 0600)")
	fs.IntVar(&f.keep, "keep", 0, "respaldos a conservar por equipo y tipo (0 = 30)")
	fs.DurationVar(&f.every, "every", 0, "programado: cada cuánto (con --rounds)")
	fs.IntVar(&f.rounds, "rounds", 0, "programado: cuántas veces")
	fs.Var(&f.accept, "accept", "huella SHA256 confirmada (repetible)")
	fs.Var(&f.exclude, "exclude", "equipo a excluir (repetible)")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Minute, "espera máxima del respaldo de una sola vez")
}

// start crea el trabajo y espera a que termine si es de una sola vez. Devuelve el informe de lo guardado.
func (f *runFlags) start(c *cli.Env) (job string, scheduled bool, rep *v1.ToolReport, err error) {
	if len(f.devs) == 0 || f.cred == "" || f.keep < 0 || f.rounds < 0 || f.every < 0 {
		return "", false, nil, errors.New("uso: mctl " + runUsage)
	}
	req := &v1.StartBackupRequest{CredentialId: f.cred, Startup: f.startup, Keep: uint32(f.keep), IncludeSecrets: f.secrets,
		IntervalSeconds: uint32(f.every / time.Second), Rounds: uint32(f.rounds), AcceptedHostKeyFingerprints: f.accept, ExcludedDeviceIds: f.exclude}
	for _, d := range f.devs {
		t, err := target(d)
		if err != nil {
			return "", false, nil, err
		}
		req.Targets = append(req.Targets, t)
	}
	cl := v1.NewBackupServiceClient(c.Conn)
	st, err := cl.StartBackup(context.Background(), req)
	if err != nil {
		return "", false, nil, err
	}
	if !st.Armed {
		fmt.Fprintln(c.Out, cli.T("mctl.backup.unarmed", "job", st.JobId, "detail", st.Detail))
		return st.JobId, false, nil, cli.Err("mctl.backup.unarmed_err")
	}
	if req.IntervalSeconds > 0 {
		return st.JobId, true, nil, nil
	}
	for deadline := time.Now().Add(f.timeout); ; time.Sleep(300 * time.Millisecond) {
		r, err := cl.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: st.JobId, Keep: req.Keep})
		if err != nil {
			return st.JobId, false, nil, err
		}
		switch {
		case r.Done && r.Error != "":
			return st.JobId, false, nil, cli.Err("mctl.backup.job_error", "job", st.JobId, "error", r.Error)
		case r.Done:
			return st.JobId, false, r.Report, nil
		case time.Now().After(deadline):
			return st.JobId, false, nil, cli.Err("mctl.backup.timeout", "timeout", f.timeout, "job", st.JobId)
		}
	}
}

func runBackup(c *cli.Env, args []string) error {
	var f runFlags
	var asJSON bool
	if _, err := cli.Flags("backup run", args, func(fs *flag.FlagSet) { f.set(fs); fs.BoolVar(&asJSON, "json", false, "salida JSON") }); err != nil {
		return errors.New("uso: mctl " + runUsage)
	}
	job, scheduled, rep, err := f.start(c)
	if err != nil {
		return err
	}
	if scheduled {
		fmt.Fprintln(c.Out, cli.T("mctl.backup.scheduled", "job", job, "rounds", f.rounds, "every", f.every))
		return nil
	}
	c.PrintReport(rep, asJSON)
	return nil
}

func collect(c *cli.Env, args []string) error {
	var keep int
	var asJSON bool
	fs, err := cli.Flags("backup collect", args, func(fs *flag.FlagSet) {
		fs.IntVar(&keep, "keep", 0, "respaldos a conservar por equipo y tipo (0 = lo del trabajo, o 30)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil || fs.NArg() != 1 || keep < 0 {
		return errors.New("uso: mctl backup collect TRABAJO [--keep N] [--json]")
	}
	r, err := v1.NewBackupServiceClient(c.Conn).CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: fs.Arg(0), Keep: uint32(keep)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	if !r.Done {
		fmt.Fprintln(c.Out, cli.T("mctl.backup.still_running", "state", r.State))
	}
	return nil
}

func list(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("backup list", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil || fs.NArg() > 1 {
		return errors.New("uso: mctl backup list [EQUIPO] [--json]")
	}
	r, err := v1.NewBackupServiceClient(c.Conn).ListBackups(context.Background(), &v1.ListBackupsRequest{Device: fs.Arg(0)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func diff(c *cli.Env, args []string) error {
	var f runFlags
	var now, asJSON bool
	fs, err := cli.Flags("backup diff", args, func(fs *flag.FlagSet) {
		f.set(fs)
		fs.BoolVar(&now, "now", false, "contra el running actual: toma un respaldo nuevo (necesita -d y --cred)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	const usage = "uso: mctl backup diff ID_A ID_B | ID_A --now -d EQUIPO --cred ID [--accept HUELLA] [--json]"
	if err != nil || now && fs.NArg() != 1 || !now && fs.NArg() != 2 {
		return errors.New(usage)
	}
	cl := v1.NewBackupServiceClient(c.Conn)
	a, b := fs.Arg(0), fs.Arg(1)
	if now {
		dev, rest, ok := strings.Cut(a, "/")
		_, kind, ok2 := strings.Cut(rest, "-")
		if !ok || !ok2 {
			return cli.Err("mctl.backup.bad_id", "id", a)
		}
		f.startup = kind == "startup"
		if len(f.devs) != 1 {
			return errors.New(usage)
		}
		if _, _, _, err := f.start(c); err != nil {
			return err
		}
		l, err := cl.ListBackups(context.Background(), &v1.ListBackupsRequest{Device: dev})
		if err != nil {
			return err
		}
		var js struct{ Backups []struct{ ID, Kind string } }
		if err := json.Unmarshal([]byte(l.Report.Json), &js); err != nil {
			return err
		}
		for _, e := range js.Backups { // más nuevo primero
			if e.Kind == kind {
				b = e.ID
				break
			}
		}
		if b == "" {
			return cli.Err("mctl.backup.new_missing")
		}
	}
	r, err := cl.DiffBackups(context.Background(), &v1.DiffBackupsRequest{From: a, To: b})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func export(c *cli.Env, args []string) error {
	var out string
	fs, err := cli.Flags("backup export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "o", "", "archivo de salida (nuevo, 0600); sin él, a la salida estándar")
	})
	if err != nil || fs.NArg() != 1 {
		return errors.New("uso: mctl backup export ID [-o ARCHIVO]")
	}
	r, err := v1.NewBackupServiceClient(c.Conn).GetBackup(context.Background(), &v1.GetBackupRequest{Id: fs.Arg(0)})
	if err != nil {
		return err
	}
	var meta struct{ Masked bool }
	json.Unmarshal([]byte(r.MetaJson), &meta)
	if meta.Masked {
		fmt.Fprintln(os.Stderr, cli.T("mctl.backup.masked_warning"))
	}
	if out == "" {
		fmt.Fprint(c.Out, r.Text)
		return nil
	}
	// O_EXCL: no pisa un archivo existente ni sigue un enlace simbólico.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return cli.ErrWrap("mctl.backup.write_out", err)
	}
	if _, err := f.WriteString(r.Text); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(c.Out, cli.T("mctl.backup.written", "path", out))
	return nil
}

const help = `  ` + runUsage + `
        (guarda show running-config en outputs/respaldos/EQUIPO/ con 0600; un trabajo de Patrol: solo lectura.
         Con --every y --rounds queda programado y el núcleo guarda cada ronda)
  backup collect TRABAJO [--keep N] [--json]   guarda lo que un trabajo lleva recolectado (idempotente)
  backup list [EQUIPO] [--json]                respaldos guardados (avisa los de secretos enmascarados)
  backup diff ID_A ID_B | ID_A --now -d EQUIPO --cred ID [--json]
        (diferencias entre dos respaldos, o contra el running actual: toma uno nuevo; sin líneas volátiles)
  backup export ID [-o ARCHIVO]                respaldo a la salida estándar o a un archivo nuevo 0600`

// Area registra los comandos de respaldos.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "backup run", Run: runBackup}, {Name: "backup collect", Run: collect}, {Name: "backup list", Run: list},
		{Name: "backup diff", Run: diff}, {Name: "backup export", Run: export},
	}}
}
