package change

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
		var noWait bool
		fs, err := cli.Flags("change "+name, args, func(fs *flag.FlagSet) {
			fs.Var(&accept, "accept", "huella SHA256 confirmada (repetible)")
			fs.Var(&exclude, "exclude", "equipo a excluir (repetible)")
			fs.BoolVar(&noWait, "no-wait", false, "no esperar a que termine la captura")
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
		if noWait {
			return nil
		}
		// Esperar evita que el ingeniero aplique su cambio mientras la captura PRE sigue corriendo.
		cl := v1.NewChangeServiceClient(c.Conn)
		list := func(ctx context.Context) (*v1.ListChangesResponse, error) {
			return cl.ListChanges(ctx, &v1.ListChangesRequest{})
		}
		if err := waitCapture(context.Background(), list, fs.Arg(0), phase, 300*time.Millisecond); err != nil {
			return err
		}
		// El trabajo puede quedar completed con equipos que fallaron: sin su línea base no hay cambio seguro.
		run, err := v1.NewPatrolServiceClient(c.Conn).GetRun(context.Background(), &v1.GetRunRequest{JobId: r.JobId, Round: 1})
		if err != nil {
			return err
		}
		if err := checkDevices(name, run.Devices); err != nil {
			return err
		}
		if p := partialDevices(run.Devices); p != "" { // la evidencia parcial sirve, pero con huecos
			fmt.Fprintln(c.Out, cli.T("mctl.change.device_partial", "name", name, "list", p))
		}
		fmt.Fprintln(c.Out, cli.T("mctl.change.done_"+name, "id", fs.Arg(0)))
		return nil
	}
}

// waitCapture sondea change list hasta que el trabajo de la fase termina; un trabajo que no queda completed es un error.
// Se sondea (y no job watch) porque una captura de una ronda puede cerrar antes de que la suscripción llegue.
// list es ListChanges ya ligado al cliente (así las pruebas no necesitan un cliente gRPC).
func waitCapture(ctx context.Context, list func(context.Context) (*v1.ListChangesResponse, error), id string, phase v1.ChangePhase, every time.Duration) error {
	name := map[v1.ChangePhase]string{v1.ChangePhase_CHANGE_PHASE_PRE: "pre", v1.ChangePhase_CHANGE_PHASE_POST: "post"}[phase]
	for {
		r, err := list(ctx)
		if err != nil {
			return err
		}
		for _, ch := range r.Changes {
			if ch.ChangeId != id {
				continue
			}
			st := ch.PreState
			if phase == v1.ChangePhase_CHANGE_PHASE_POST {
				st = ch.PostState
			}
			switch st {
			case "completed":
				return nil
			case "arming", "armed", "created":
			default:
				return cli.Err("mctl.change.capture_failed", "name", name, "state", or(st, "?"))
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

// partialDevices nombra por dirección los equipos de la captura que quedaron partial (con comandos cortados).
func partialDevices(devs []*v1.RunDevice) string {
	var out []string
	for _, d := range devs {
		if d.State == v1.DeviceState_DEVICE_STATE_PARTIAL {
			out = append(out, d.Target.GetAddress())
		}
	}
	return strings.Join(out, ", ")
}

// checkDevices falla nombrando los equipos de la captura que no quedaron completed (los excluidos a propósito no cuentan).
// El estado por equipo no trae el hostname: se nombra por dirección.
func checkDevices(name string, devs []*v1.RunDevice) error {
	var bad []string
	for _, d := range devs {
		if d.State == v1.DeviceState_DEVICE_STATE_COMPLETED || d.State == v1.DeviceState_DEVICE_STATE_SKIPPED || d.State == v1.DeviceState_DEVICE_STATE_PARTIAL {
			continue
		}
		who := d.Target.GetAddress()
		if d.Detail != "" {
			who += " (" + d.Detail + ")"
		}
		bad = append(bad, who)
	}
	if len(bad) == 0 {
		return nil
	}
	return cli.Err("mctl.change.device_failed_"+name, "list", strings.Join(bad, ", "))
}

// changeDiff compara la captura PRE con la POST de un cambio: las líneas de configuración que cambiaron, por equipo.
// Reusa el informe del núcleo (el mismo de la app). Las capturas se guardan enmascaradas salvo que el cambio se creó con
// disable_masking: true; shortcut: el informe no trae ese dato, así que en ese caso el diff puede mostrar secretos
// (el aviso queda pendiente hasta que el informe lo exponga).
func changeDiff(c *cli.Env, args []string) error {
	var device string
	var asJSON bool
	fs, err := cli.Flags("change diff", args, func(fs *flag.FlagSet) {
		fs.StringVar(&device, "device", "", "equipo (parte del nombre o la IP)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return cli.Err("mctl.change.need_id", "name", "diff")
	}
	r, err := v1.NewChangeServiceClient(c.Conn).GetChangeReport(context.Background(), &v1.GetChangeReportRequest{ChangeId: fs.Arg(0)})
	if err != nil {
		return err
	}
	return printDiff(c, r.Report.Json, device, asJSON)
}

func printDiff(c *cli.Env, reportJSON, device string, asJSON bool) error {
	type dev struct {
		Address    string   `json:"address"`
		Hostname   string   `json:"hostname"`
		ConfigDiff []string `json:"config_diff"`
		Findings   []struct {
			Facet, Detail string
		} `json:"findings"`
	}
	var rep struct {
		Unmasked bool  `json:"unmasked"` // alguna captura se recogió sin enmascarar
		Devices  []dev `json:"devices"`
	}
	if err := json.Unmarshal([]byte(reportJSON), &rep); err != nil {
		return err
	}
	var sel []dev
	for _, d := range rep.Devices {
		host := hostOnly(d.Address) // la dirección puede traer puerto
		if device == "" || strings.Contains(strings.ToLower(d.Hostname), strings.ToLower(device)) || d.Address == device || host == device {
			sel = append(sel, d)
		}
	}
	if len(sel) == 0 {
		return cli.Err("mctl.change.diff_no_device", "device", device)
	}
	if asJSON {
		for i := range sel {
			if sel[i].ConfigDiff == nil {
				sel[i].ConfigDiff = []string{}
			}
		}
		b, err := json.Marshal(map[string]any{"unmasked": rep.Unmasked, "devices": sel})
		fmt.Fprintln(c.Out, string(b))
		return err
	}
	if rep.Unmasked {
		fmt.Fprintln(c.Out, cli.T("drift.text.warning", "message", cli.T("evidence.unmasked")))
	}
	missing := 0
	for _, d := range sel {
		fmt.Fprintf(c.Out, "%s (%s)\n", or(d.Hostname, "?"), d.Address)
		noCap := false
		for _, f := range d.Findings {
			if f.Facet == "captura" { // falta la PRE o la POST, o falló: «sin diferencias» sería mentira
				fmt.Fprintln(c.Out, "  "+cli.T("mctl.change.diff_nocapture", "detail", f.Detail))
				noCap = true
			}
		}
		if noCap {
			missing++
			continue
		}
		if len(d.ConfigDiff) == 0 {
			fmt.Fprintln(c.Out, "  "+cli.T("mctl.change.diff_none"))
		}
		for _, l := range d.ConfigDiff {
			fmt.Fprintln(c.Out, "  "+l)
		}
	}
	if missing > 0 {
		return cli.Err("mctl.change.diff_incomplete", "n", missing)
	}
	return nil
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
		return cli.Err("mctl.change.checks_failed", "n", n)
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
		return cli.Err("mctl.change.rules_failed", "n", rep.Fail)
	}
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  change create -f cambio.yaml | pre|post [--accept HUELLA]... [--exclude EQUIPO]... [--no-wait] ID | list
         diff ID [--device EQUIPO] [--json]   (líneas de configuración que cambiaron entre PRE y POST)
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
		{Name: "change diff", Run: changeDiff},
		{Name: "change report", Run: changeReport},
		{Name: "upgrade check", Run: upgradeCheck},
		{Name: "compliance check", Run: complianceCheck},
	}}
}

// hostOnly quita el puerto de «host:puerto» o «[ipv6]:puerto» sin importar net (noegress: mctl no toca la red).
// Una IPv6 sin corchetes (varios «:») se deja igual.
func hostOnly(addr string) string {
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i > 0 {
			return addr[1:i]
		}
	}
	if strings.Count(addr, ":") == 1 {
		return addr[:strings.Index(addr, ":")]
	}
	return addr
}
