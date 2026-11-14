package patrol

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func jobCreate(c *cli.Env, args []string) error {
	var file string
	var params cli.List
	if _, err := cli.Flags("job create", args, func(fs *flag.FlagSet) {
		fs.StringVar(&file, "f", "", "archivo YAML")
		fs.Var(&params, "param", "dato de un playbook, nombre=valor (repetible; pisa el del YAML)")
	}); err != nil {
		return err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	j, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var spec v1.JobSpec
	if err := (protojson.UnmarshalOptions{}).Unmarshal(j, &spec); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	if err := applyParams(&spec, params); err != nil {
		return err
	}
	r, err := v1.NewPatrolServiceClient(c.Conn).CreateJob(context.Background(), &v1.CreateJobRequest{Spec: &spec})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.JobId)
	return nil
}

// applyParams suma los --param nombre=valor a spec.Params; uno repetido o sin nombre es error. El núcleo valida el
// resto (faltantes, desconocidos, formato) y responde con su mensaje.
func applyParams(spec *v1.JobSpec, kv []string) error {
	seen := map[string]bool{}
	for _, p := range kv {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return cli.Err("mctl.patrol.param_form", "param", p)
		}
		if seen[k] {
			return cli.Err("mctl.patrol.param_dup", "name", k)
		}
		seen[k] = true
		if spec.Params == nil {
			spec.Params = map[string]string{}
		}
		spec.Params[k] = v
	}
	return nil
}

func jobLoginTest(c *cli.Env, args []string) error {
	id, err := cli.OneArg("job logintest", args)
	if err != nil {
		return err
	}
	st, err := v1.NewPatrolServiceClient(c.Conn).LoginTest(context.Background(), &v1.LoginTestRequest{JobId: id})
	if err != nil {
		return err
	}
	failed := 0
	for {
		r, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if r.Passed {
			fmt.Fprintf(c.Out, "%s  OK  %s\n", r.Target.GetAddress(), r.DetectedPlatform)
			continue
		}
		failed++
		fmt.Fprint(c.Out, cli.T("mctl.patrol.login_fail", "addr", r.Target.GetAddress(), "step", strings.TrimPrefix(r.FailedStep.String(), "LOGIN_TEST_STEP_"), "detail", r.Detail))
		if r.HostKeyFingerprint != "" {
			fmt.Fprint(c.Out, cli.T("mctl.patrol.login_fp", "fp", r.HostKeyFingerprint, "id", id))
		}
		fmt.Fprintln(c.Out)
	}
	if failed > 0 {
		return cli.Err("mctl.patrol.login_failed", "n", failed)
	}
	return nil
}

func jobArm(c *cli.Env, args []string) error {
	var accept, exclude cli.List
	fs, err := cli.Flags("job arm", args, func(fs *flag.FlagSet) {
		fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
		fs.Var(&exclude, "exclude", "equipo a excluir (repetible)")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return cli.Err("mctl.patrol.arm_need_id")
	}
	r, err := v1.NewPatrolServiceClient(c.Conn).ArmJob(context.Background(), &v1.ArmJobRequest{JobId: fs.Arg(0), AcceptedHostKeyFingerprints: accept, ExcludedDeviceIds: exclude})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, cli.T("mctl.patrol.armed", "until", r.WindowEndsAt.AsTime().Local().Format("2006-01-02 15:04")))
	if len(r.MissingInhibitors) > 0 {
		fmt.Fprintln(c.Out, cli.T("mctl.patrol.armed_warn", "list", strings.Join(r.MissingInhibitors, ", ")))
	}
	return nil
}

func jobCancel(c *cli.Env, args []string) error {
	id, err := cli.OneArg("job cancel", args)
	if err != nil {
		return err
	}
	_, err = v1.NewPatrolServiceClient(c.Conn).CancelJob(context.Background(), &v1.CancelJobRequest{JobId: id})
	return err
}

func jobList(c *cli.Env, args []string) error {
	if _, err := cli.Flags("job list", args, nil); err != nil {
		return err
	}
	r, err := v1.NewPatrolServiceClient(c.Conn).ListJobs(context.Background(), &v1.ListJobsRequest{})
	if err != nil {
		return err
	}
	for _, j := range r.Jobs {
		fmt.Fprintf(c.Out, "%s  %s  %s\n", j.JobId, j.Name, j.State)
	}
	return nil
}

// playbooks lista el catálogo: el id es el que va en playbook_ids de job create.
func playbooks(c *cli.Env, args []string) error {
	var platform string
	if _, err := cli.Flags("playbooks", args, func(fs *flag.FlagSet) { fs.StringVar(&platform, "platform", "", "solo esta plataforma") }); err != nil {
		return err
	}
	r, err := v1.NewPatrolServiceClient(c.Conn).ListPlaybooks(context.Background(), &v1.ListPlaybooksRequest{Platform: platform})
	if err != nil {
		return err
	}
	for _, p := range r.Playbooks {
		fmt.Fprintln(c.Out, playbookLine(p))
	}
	return nil
}

// playbookLine es una línea del listado; si el playbook pide datos, los suma al final (nombre:tipo).
func playbookLine(p *v1.PlaybookInfo) string {
	line := cli.T("mctl.patrol.playbook_line", "id", p.Id, "name", p.Name, "n", len(p.Commands))
	if len(p.Params) > 0 {
		var ds []string
		for _, q := range p.Params {
			ds = append(ds, q.Name+":"+q.Kind)
		}
		line += cli.T("mctl.patrol.playbook_data", "list", strings.Join(ds, " "))
	}
	return line
}

func jobWatch(c *cli.Env, args []string) error {
	id, err := cli.OneArg("job watch", args)
	if err != nil {
		return err
	}
	st, err := v1.NewEventServiceClient(c.Conn).Subscribe(context.Background(), &v1.SubscribeRequest{JobIds: []string{id}})
	if err != nil {
		return err
	}
	for {
		e, err := st.Recv()
		if errors.Is(err, io.EOF) { // el núcleo cerró el stream (trabajo ya cerrado): fin normal
			return nil
		}
		if err != nil {
			return err
		}
		t := e.At.AsTime().Local().Format("15:04:05")
		switch ev := e.Event.(type) {
		case *v1.SubscribeResponse_DeviceStateChanged:
			fmt.Fprintf(c.Out, "%s  %s  %s  %s\n", t, ev.DeviceStateChanged.DeviceId, strings.TrimPrefix(ev.DeviceStateChanged.State.String(), "DEVICE_STATE_"), ev.DeviceStateChanged.Detail)
		case *v1.SubscribeResponse_CommandProgress:
			p := ev.CommandProgress
			fmt.Fprintf(c.Out, "%s  %s  %d/%d  %s\n", t, p.DeviceId, p.Index, p.Total, p.Command)
		case *v1.SubscribeResponse_PhaseAdded:
			p := ev.PhaseAdded
			fmt.Fprintln(c.Out, cli.T("mctl.patrol.watch_phase", "t", t, "kind", strings.TrimPrefix(p.Kind.String(), "JOB_PHASE_KIND_"), "round", p.Round, "detail", p.Detail))
		case *v1.SubscribeResponse_Warning:
			fmt.Fprintln(c.Out, cli.T("mctl.patrol.watch_warning", "t", t, "code", ev.Warning.Code))
		case *v1.SubscribeResponse_JobStateChanged:
			fmt.Fprintln(c.Out, cli.T("mctl.patrol.watch_job", "t", t, "state", ev.JobStateChanged.State))
			if ev.JobStateChanged.State == "closed" {
				return nil
			}
		}
	}
}

// help son las líneas de este área en mctl --help.
const help = `  job   create -f job.yaml [--param nombre=valor]... | logintest ID | arm [--accept HUELLA]... [--exclude EQUIPO]... ID
        cancel ID | list | watch ID
  playbooks [--platform P]`

// Area registra los comandos de patrol.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "job create", Run: jobCreate},
		{Name: "job logintest", Run: jobLoginTest},
		{Name: "job arm", Run: jobArm},
		{Name: "job cancel", Run: jobCancel},
		{Name: "job list", Run: jobList},
		{Name: "job watch", Run: jobWatch},
		{Name: "playbooks", Run: playbooks},
	}}
}
