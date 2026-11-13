package change

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Ventana de cambio: PRE/POST con Patrol, verificación de upgrade y cumplimiento.
// Nada de esto aplica configuración; los reportes con fallas terminan con código 1.

func changeCreate(c *cli.Env, args []string) error {
	var file string
	if _, err := cli.Flags("change create", args, func(fs *flag.FlagSet) { fs.StringVar(&file, "f", "", "archivo YAML (mismo formato que job create)") }); err != nil {
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
	r, err := v1.NewChangeServiceClient(c.Conn).CreateChange(context.Background(), &v1.CreateChangeRequest{Spec: &spec})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.ChangeId)
	return nil
}

func changeCapture(phase v1.ChangePhase) func(*cli.Env, []string) error {
	name := map[v1.ChangePhase]string{v1.ChangePhase_CHANGE_PHASE_PRE: "pre", v1.ChangePhase_CHANGE_PHASE_POST: "post"}[phase]
	return func(c *cli.Env, args []string) error {
		var accept, exclude cli.List
		fs, err := cli.Flags("change "+name, args, func(fs *flag.FlagSet) {
			fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
			fs.Var(&exclude, "exclude", "equipo a excluir (repetible)")
		})
		if err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return cli.Err("mctl.change.need_id", "name", name)
		}
		r, err := v1.NewChangeServiceClient(c.Conn).CaptureChange(context.Background(), &v1.CaptureChangeRequest{ChangeId: fs.Arg(0), Phase: phase, AcceptedHostKeyFingerprints: accept, ExcludedDeviceIds: exclude})
		if err != nil {
			return err
		}
		if !r.Armed {
			fmt.Fprintln(c.Out, cli.T("mctl.change.unarmed", "job", r.JobId, "detail", r.Detail, "name", name, "id", fs.Arg(0)))
			return cli.Err("mctl.change.unarmed_er", "name", name)
		}
		fmt.Fprintln(c.Out, cli.T("mctl.change.capturing", "name", name, "job", r.JobId))
		return nil
	}
}

func changeList(c *cli.Env, args []string) error {
	if _, err := cli.Flags("change list", args, nil); err != nil {
		return err
	}
	r, err := v1.NewChangeServiceClient(c.Conn).ListChanges(context.Background(), &v1.ListChangesRequest{})
	if err != nil {
		return err
	}
	for _, ch := range r.Changes {
		fmt.Fprintf(c.Out, "%s  %s  pre=%s %s  post=%s %s\n", ch.ChangeId, ch.Name, or(ch.PreJobId, "-"), ch.PreState, or(ch.PostJobId, "-"), ch.PostState)
	}
	return nil
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func abs(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	return filepath.Abs(p)
}

func changeReport(c *cli.Env, args []string) error {
	var pre, post string
	var asJSON bool
	fs, err := cli.Flags("change report", args, func(fs *flag.FlagSet) {
		fs.StringVar(&pre, "pre", "", "carpeta del trabajo PRE")
		fs.StringVar(&post, "post", "", "carpeta del trabajo POST")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	req := &v1.GetChangeReportRequest{ChangeId: fs.Arg(0)}
	if req.PreDir, err = abs(pre); err != nil {
		return err
	}
	if req.PostDir, err = abs(post); err != nil {
		return err
	}
	if req.ChangeId == "" && (pre == "" || post == "") {
		return errors.New("uso: mctl change report ID | --pre CARPETA --post CARPETA [--json]")
	}
	r, err := v1.NewChangeServiceClient(c.Conn).GetChangeReport(context.Background(), req)
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	var rep struct{ Devices []struct{ Verdict string } }
	json.Unmarshal([]byte(r.Report.Json), &rep)
	n := 0
	for _, d := range rep.Devices {
		if d.Verdict == "regression" {
			n++
		}
	}
	if n > 0 {
		return cli.Err("mctl.change.regression", "n", n)
	}
	return nil
}

func readFile(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	b, err := os.ReadFile(p)
	return string(b), err
}

func upgradeCheck(c *cli.Env, args []string) error {
	var outputs, image, md5, verify string
	var size int64
	var asJSON bool
	if _, err := cli.Flags("upgrade check", args, func(fs *flag.FlagSet) {
		fs.StringVar(&outputs, "outputs", "", "archivo de Patrol (ios-xe/upgrade-check) o sesión pegada")
		fs.StringVar(&image, "image", "", "nombre de la imagen destino")
		fs.Int64Var(&size, "size", 0, "tamaño esperado en bytes")
		fs.StringVar(&md5, "md5", "", "MD5 esperado")
		fs.StringVar(&verify, "verify", "", "archivo con la salida de verify /md5")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	}); err != nil {
		return err
	}
	if outputs == "" || image == "" {
		return errors.New("uso: mctl upgrade check --outputs ARCHIVO --image NOMBRE [--size BYTES] [--md5 HEX] [--verify ARCHIVO] [--json]")
	}
	text, err := readFile(outputs)
	if err != nil {
		return err
	}
	vtext, err := readFile(verify)
	if err != nil {
		return err
	}
	r, err := v1.NewChangeServiceClient(c.Conn).CheckUpgrade(context.Background(), &v1.CheckUpgradeRequest{Outputs: text, ImageFile: image, ImageSize: size, ImageMd5: md5, VerifyOutput: vtext})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	var rep struct{ Items []struct{ Status string } }
	json.Unmarshal([]byte(r.Report.Json), &rep)
	n := 0
	for _, i := range rep.Items {
		if i.Status == "fail" {
			n++
		}
	}
	if n > 0 {
		return fmt.Errorf("%d verificaciones fallaron", n)
	}
	return nil
}

func complianceCheck(c *cli.Env, args []string) error {
	var config, template string
	var asJSON bool
	if _, err := cli.Flags("compliance check", args, func(fs *flag.FlagSet) {
		fs.StringVar(&config, "config", "", "running-config")
		fs.StringVar(&template, "template", "", "plantilla dorada (opcional)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	}); err != nil {
		return err
	}
	if config == "" {
		return errors.New("uso: mctl compliance check --config ARCHIVO [--template ARCHIVO] [--json]")
	}
	cfg, err := readFile(config)
	if err != nil {
		return err
	}
	tpl, err := readFile(template)
	if err != nil {
		return err
	}
	r, err := v1.NewChangeServiceClient(c.Conn).CheckCompliance(context.Background(), &v1.CheckComplianceRequest{Config: cfg, Template: tpl})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	var rep struct{ Fail int }
	json.Unmarshal([]byte(r.Report.Json), &rep)
	if rep.Fail > 0 {
		return fmt.Errorf("%d reglas fallaron", rep.Fail)
	}
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  change create -f cambio.yaml | pre|post [--accept HUELLA]... [--exclude EQUIPO]... ID | list
         report ID | report --pre CARPETA --post CARPETA   [--json]
  upgrade check --outputs ARCHIVO --image NOMBRE [--size BYTES] [--md5 HEX] [--verify ARCHIVO] [--json]
  compliance check --config ARCHIVO [--template ARCHIVO] [--json]`

// Area registra change, upgrade y compliance.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "change create", Run: changeCreate},
		{Name: "change pre", Run: changeCapture(v1.ChangePhase_CHANGE_PHASE_PRE)},
		{Name: "change post", Run: changeCapture(v1.ChangePhase_CHANGE_PHASE_POST)},
		{Name: "change list", Run: changeList},
		{Name: "change report", Run: changeReport},
		{Name: "upgrade check", Run: upgradeCheck},
		{Name: "compliance check", Run: complianceCheck},
	}}
}
