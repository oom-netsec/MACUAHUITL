package devices

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Libreta de hosts (fase 29b): la fuente «manual» del inventario. Nada de esto toca un equipo, y una
// credencial es siempre la referencia (id) a la bóveda.

func client(c *cli.Env) v1.InventoryServiceClient { return v1.NewInventoryServiceClient(c.Conn) }

// manual son los hosts de la libreta con SUS valores, sin fusionar con lo descubierto y por nombre: es lo que se
// lista y lo que se edita (editar no debe fijar la plataforma que detectó Patrol).
func manual(c *cli.Env, r *v1.ListDevicesRequest) ([]*v1.Device, error) {
	r.ManualOnly = true
	res, err := client(c).ListDevices(context.Background(), r)
	if err != nil {
		return nil, err
	}
	return res.Devices, nil
}

// hosts list [TEXTO] [--folder F] [--tag X] [--json]
func hostsList(c *cli.Env, args []string) error {
	var r v1.ListDevicesRequest
	var asJSON bool
	fs, err := cli.Flags("hosts list", args, func(fs *flag.FlagSet) {
		fs.StringVar(&r.Folder, "folder", "", "carpeta")
		fs.StringVar(&r.Tag, "tag", "", "etiqueta")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("uso: mctl hosts list [TEXTO] [--folder F] [--tag X] [--json]")
	}
	r.Query = fs.Arg(0)
	ds, err := manual(c, &r)
	if err != nil {
		return err
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(&v1.ListDevicesResponse{Devices: ds})
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
		return nil
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNOMBRE\tDIRECCIÓN\tPUERTO\tPLATAFORMA\tCARPETA\tETIQUETAS\tCREDENCIAL")
	for _, d := range ds {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", d.Id, d.Name, d.GetTarget().GetAddress(), d.GetProfile().GetPort(), d.Platform, d.Folder, strings.Join(d.Tags, ","), d.CredentialLabel)
	}
	return tw.Flush()
}

type hostFields struct {
	name, address, platform, folder, cred, notes string
	port                                         int
	tags                                         cli.List
}

func (f *hostFields) flags(fs *flag.FlagSet) {
	fs.StringVar(&f.name, "name", "", "nombre")
	fs.StringVar(&f.address, "address", "", "IP o nombre DNS")
	fs.IntVar(&f.port, "port", 0, "puerto SSH (22 por defecto)")
	fs.StringVar(&f.platform, "platform", "", "plataforma: ios, ios-xe, nx-os, asa, iosxr, wlc")
	fs.StringVar(&f.folder, "folder", "", "carpeta (un solo nivel)")
	fs.Var(&f.tags, "tag", "etiqueta (repetible)")
	fs.StringVar(&f.cred, "cred", "", "id de la credencial en la bóveda")
	fs.StringVar(&f.notes, "notes", "", "notas")
}

func saved(c *cli.Env, verb, id, name string, warnings []string) {
	fmt.Fprintf(c.Out, "%s %s (%s)\n", verb, id, name)
	for _, w := range warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
}

// hosts add NOMBRE --address A [--port N] [--platform P] [--folder F] [--tag X]... [--cred ID] [--notes N]
func hostsAdd(c *cli.Env, args []string) error {
	var f hostFields
	fs, err := cli.Flags("hosts add", args, f.flags)
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || f.name != "" || f.address == "" {
		return errors.New("uso: mctl hosts add NOMBRE --address A [--port N] [--platform P] [--folder F] [--tag X]... [--cred ID] [--notes N]")
	}
	r, err := client(c).PutDevice(context.Background(), &v1.PutDeviceRequest{Device: &v1.Device{Name: fs.Arg(0), Target: &v1.Target{Address: f.address},
		Profile: &v1.DeviceProfile{Port: uint32(f.port)}, Platform: f.platform, Folder: f.folder, Tags: f.tags, CredentialId: f.cred, Notes: f.notes}})
	if err != nil {
		return err
	}
	saved(c, "creado", r.Id, fs.Arg(0), r.Warnings)
	return nil
}

// hosts edit ID [--name N] [--address A] [--port N] [--platform P] [--folder F] [--tag X]... [--cred ID] [--notes N]
// Solo cambia lo que se pasa; --tag reemplaza todas las etiquetas y un valor vacío (--folder "", --cred "") quita el campo.
func hostsEdit(c *cli.Env, args []string) error {
	var f hostFields
	fs, err := cli.Flags("hosts edit", args, f.flags)
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl hosts edit ID [--name N] [--address A] [--port N] [--platform P] [--folder F] [--tag X]... [--cred ID] [--notes N]")
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	ds, err := manual(c, &v1.ListDevicesRequest{})
	if err != nil {
		return err
	}
	var cur *v1.Device
	for _, d := range ds {
		if d.Id == fs.Arg(0) {
			cur = d
		}
	}
	if cur == nil {
		return fmt.Errorf("no hay un host de la libreta con id %q (mctl hosts list)", fs.Arg(0))
	}
	if set["name"] {
		cur.Name = f.name
	}
	if set["address"] {
		cur.Target = &v1.Target{Address: f.address}
	}
	if set["port"] {
		cur.Profile = &v1.DeviceProfile{Port: uint32(f.port)}
	}
	if set["platform"] {
		cur.Platform = f.platform
	}
	if set["folder"] {
		cur.Folder = f.folder
	}
	if set["tag"] {
		cur.Tags = f.tags
	}
	if set["cred"] {
		cur.CredentialId = f.cred
	}
	if set["notes"] {
		cur.Notes = f.notes
	}
	r, err := client(c).PutDevice(context.Background(), &v1.PutDeviceRequest{Device: cur})
	if err != nil {
		return err
	}
	saved(c, "guardado", r.Id, cur.Name, r.Warnings)
	return nil
}

// hosts rm ID
func hostsRm(c *cli.Env, args []string) error {
	id, err := cli.OneArg("hosts rm", args)
	if err != nil {
		return err
	}
	if _, err := client(c).DeleteDevice(context.Background(), &v1.DeleteDeviceRequest{Id: id}); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "borrado %s\n", id)
	return nil
}

// hosts export --out RUTA [--overwrite] [ID...]
func hostsExport(c *cli.Env, args []string) error {
	var out, format string
	var ow bool
	fs, err := cli.Flags("hosts export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "archivo de salida")
		fs.BoolVar(&ow, "overwrite", false, "reemplaza el archivo si existe")
		fs.StringVar(&format, "format", "", "csv o json (por omisión, según la extensión)")
	})
	if err != nil {
		return err
	}
	if out == "" {
		return errors.New("uso: mctl hosts export --out RUTA [--format csv|json] [--overwrite] [ID...]")
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	r, err := client(c).ExportHosts(context.Background(), &v1.ExportHostsRequest{Path: out, Overwrite: ow, Ids: fs.Args(), Format: format})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "exportados %d hosts a %s\n", r.Count, out)
	for _, w := range r.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	return nil
}

var acciones = map[string]bool{"renombrar": true, "reemplazar": true, "omitir": true}

// hosts import RUTA [--decision DIRECCIÓN:PUERTO=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
func hostsImport(c *cli.Env, args []string) error {
	var decs cli.List
	var all, format string
	var onlyPreview bool
	fs, err := cli.Flags("hosts import", args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "", "csv o json (por omisión, según la extensión)")
		fs.Var(&decs, "decision", "DIRECCIÓN:PUERTO=acción para un conflicto (repetible)")
		fs.StringVar(&all, "all", "", "acción para los conflictos sin --decision")
		fs.BoolVar(&onlyPreview, "preview", false, "solo la vista previa")
	})
	if err != nil {
		return err
	}
	const uso = "uso: mctl hosts import RUTA [--format csv|json] [--decision DIRECCIÓN:PUERTO=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]"
	if fs.NArg() != 1 {
		return errors.New(uso)
	}
	if all != "" && !acciones[all] {
		return fmt.Errorf("--all=%q: use renombrar, reemplazar u omitir", all)
	}
	dec := map[string]string{}
	for _, d := range decs {
		k, act, ok := strings.Cut(d, "=")
		if !ok || k == "" || !acciones[act] {
			return fmt.Errorf("--decision %q: use DIRECCIÓN:PUERTO=renombrar|reemplazar|omitir", d)
		}
		dec[k] = act
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	cl := client(c)
	p, err := cl.PreviewImportHosts(context.Background(), &v1.PreviewImportHostsRequest{Path: path, Format: format})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DESTINO\tNOMBRE\tESTADO\tMOTIVO\tCREDENCIAL")
	var req []*v1.ImportHostDecision
	var missing []string
	for _, it := range p.Items {
		cr := it.Host.CredentialLabel
		if it.CredentialMissing {
			cr += " (no está en la bóveda)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", it.Key, it.Host.Name, it.State, it.Reason, cr)
		a, ok := dec[it.Key]
		if !ok && it.State == "conflicto" {
			if a = all; a == "" {
				missing = append(missing, it.Key)
				continue
			}
			ok = true
		}
		if ok {
			req = append(req, &v1.ImportHostDecision{Key: it.Key, Action: a})
		}
	}
	tw.Flush()
	for _, e := range p.Errors {
		campo := ""
		if e.Field != "" {
			campo = e.Field + ": "
		}
		fmt.Fprintf(c.Out, "línea %d: %s%s\n", e.Line, campo, e.Reason)
	}
	if len(p.Errors) > 0 {
		fmt.Fprintf(c.Out, "%d filas inválidas: no se importan y cuentan como omitidas\n", len(p.Errors))
	}
	for _, w := range p.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	if onlyPreview {
		return nil
	}
	if len(missing) > 0 {
		return fmt.Errorf("no se importó nada: falta decidir %d conflicto(s); use --decision DIRECCIÓN:PUERTO=renombrar|reemplazar|omitir o --all=ACCIÓN: %s", len(missing), strings.Join(missing, ", "))
	}
	r, err := cl.ApplyImportHosts(context.Background(), &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: req})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "importados: %d nuevos, %d reemplazados, %d renombrados, %d omitidos", r.Created, r.Replaced, r.Renamed, r.Skipped)
	if r.Invalid > 0 {
		fmt.Fprintf(c.Out, " (%d inválidos)", r.Invalid)
	}
	fmt.Fprintln(c.Out)
	return nil
}

// hosts template --format csv|json  |  hosts template --fields
func hostsTemplate(c *cli.Env, args []string) error {
	var format string
	var fields bool
	fs, err := cli.Flags("hosts template", args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "", "csv o json")
		fs.BoolVar(&fields, "fields", false, "describe los campos en vez de dar la plantilla")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 0 || (!fields && format == "") {
		return errors.New("uso: mctl hosts template --format csv|json  |  mctl hosts template --fields")
	}
	cl := client(c)
	if fields {
		r, err := cl.HostsImportFormat(context.Background(), &v1.HostsImportFormatRequest{})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NOMBRE\tTIPO\tOBLIGATORIO\tEJEMPLO\tDESCRIPCIÓN")
		for _, f := range r.Fields {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Name, f.Type, map[bool]string{true: "sí", false: "no"}[f.Required], f.Example, f.Description)
		}
		tw.Flush()
		fmt.Fprintf(c.Out, "hasta %d hosts y %d MB por archivo\n", r.MaxRows, r.MaxBytes>>20)
		return nil
	}
	r, err := cl.HostsImportTemplate(context.Background(), &v1.HostsImportTemplateRequest{Format: format})
	if err != nil {
		return err
	}
	fmt.Fprint(c.Out, r.Content)
	if !strings.HasSuffix(r.Content, "\n") {
		fmt.Fprintln(c.Out)
	}
	return nil
}

const hostsHelp = `  hosts list [TEXTO] [--folder F] [--tag X] [--json]  |  hosts rm ID
        (libreta de hosts: los equipos que agregas a mano, la fuente «manual» de «devices»; se fusionan por dirección con lo descubierto. rm no borra la evidencia)
  hosts add NOMBRE --address A [--port N] [--platform P] [--folder F] [--tag X]... [--cred ID] [--notes N]
  hosts edit ID [--name N] [--address A] [--port N] [--platform P] [--folder F] [--tag X]... [--cred ID] [--notes N]
        (A: IP o nombre DNS, sin usuario, esquema ni puerto; puerto 22 por defecto; platform: ios, ios-xe, nx-os, asa, iosxr, wlc; carpeta de un solo nivel; hasta 10 etiquetas.
         --cred es el id de una credencial de la bóveda (cred list): nunca un secreto. edit solo cambia lo que se pasa; --tag reemplaza todas y un valor vacío quita el campo)
  hosts export --out RUTA [--format csv|json] [--overwrite] [ID...]
        (archivo 0600; el formato sale de la extensión (.csv / .json) o de --format. JSON versionado con suma SHA-256 (integridad, no autenticidad);
         CSV para Excel (UTF-8, encabezado fijo, etiquetas separadas por «;», celdas que empiezan con = + - @ llevan un apóstrofo delante). La credencial viaja solo como su etiqueta; sin ID exporta todos, hasta 1000)
  hosts template --format csv|json  |  hosts template --fields
        (imprime un archivo de ejemplo con el encabezado y 3 filas válidas, o describe cada campo; ambos salen de la misma tabla que valida el import)
  hosts import RUTA [--format csv|json] [--decision DIRECCIÓN:PUERTO=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
        (una fila inválida sale como «línea N: campo: motivo», no bloquea las demás y cuenta como omitida; el JSON sin suma avisa. Estado de cada host válido: nuevo, igual o conflicto (misma dirección y puerto con otros datos: reemplazar u omitir; mismo nombre: también renombrar); los nuevos entran solos y cada conflicto necesita una decisión, si no, no se importa nada.
         La etiqueta de la credencial se busca en la bóveda abierta; si no está, el host queda sin credencial)`
