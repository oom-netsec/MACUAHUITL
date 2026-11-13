package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

const tokenTTL = 10 * time.Minute

// previa es lo que una vista previa deja listo para aplicar.
type previa struct {
	hosts   []devices.Host // con la credencial ya resuelta por etiqueta en la vista previa: al aplicar no se vuelve a buscar
	path    string
	invalid int // filas inválidas de la vista previa: se cuentan como omitidas
}

// ExportHosts escribe los hosts (todos, o los ids dados) a un JSON versionado. La credencial sale solo como su
// etiqueta; si no se puede resolver (bóveda cerrada, credencial ya borrada) el host sale sin ella y se avisa.
func (s *svc) ExportHosts(ctx context.Context, r *v1.ExportHostsRequest) (*v1.ExportHostsResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(ctx, r.Path)
	if err != nil {
		return nil, err
	}
	format, err := devices.ImportFormat(path, r.Format)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	all, err := loadHosts(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	sel := all
	if len(r.Ids) > 0 {
		byID := map[string]devices.Host{}
		for _, h := range all {
			byID[h.ID] = h
		}
		sel = nil
		seen := map[string]bool{}
		for _, id := range r.Ids {
			h, ok := byID[id]
			if !ok {
				return nil, service.Err(ctx, codes.NotFound, "hosts.err.no_id", i18n.A("id", id))
			}
			if !seen[id] {
				seen[id] = true
				sel = append(sel, h)
			}
		}
	}
	if len(sel) == 0 {
		return nil, service.Err(ctx, codes.InvalidArgument, "hosts.err.nothing_to_export", nil)
	}
	if len(sel) > devices.MaxImportHosts {
		return nil, service.Err(ctx, codes.InvalidArgument, "hosts.err.export_count", i18n.A("max", devices.MaxImportHosts))
	}
	infos, _ := s.creds()
	out := &v1.ExportHostsResponse{Count: int32(len(sel))}
	files := make([]devices.FileHost, len(sel))
	for i, h := range sel {
		label := ""
		if h.CredentialID != "" {
			if label = labelOf(infos, h.CredentialID); label == "" {
				out.Warnings = append(out.Warnings, i18n.T(ctx, "hosts.warn.label_lost", i18n.A("name", h.Name)))
			}
		}
		files[i] = devices.ToFile(h, label)
	}
	var b []byte
	if format == devices.FormatCSV {
		b, err = devices.MarshalHostsCSV(files)
	} else {
		b, err = devices.MarshalHosts(files, s.clock())
	}
	if err != nil {
		return nil, internal(err)
	}
	if len(b) > devices.MaxImportBytes {
		return nil, service.Err(ctx, codes.InvalidArgument, "hosts.err.export_too_big", nil)
	}
	if err := service.WriteExport(ctx, path, b, r.Overwrite); err != nil {
		return nil, err
	}
	s.d.Audit("hosts.exportar", path, fmt.Sprintf("%d hosts (%s)", len(sel), format))
	return out, nil
}

// resolve lleva los hosts del archivo a hosts de la libreta, con la credencial resuelta por etiqueta contra la
// bóveda local: una etiqueta que no está, o que está repetida, deja el host sin credencial (missing[i]).
func (s *svc) resolve(files []devices.FileHost) (hosts []devices.Host, missing []bool, vaultOK bool) {
	infos, vaultOK := s.creds()
	hosts, missing = make([]devices.Host, len(files)), make([]bool, len(files))
	for i, f := range files {
		hosts[i] = f.Host()
		if f.CredentialLabel == "" {
			continue
		}
		var id string
		n := 0
		for _, c := range infos {
			if c.Label == f.CredentialLabel {
				id, n = c.ID, n+1
			}
		}
		if n == 1 {
			hosts[i].CredentialID = id
		} else {
			missing[i] = true
		}
	}
	return
}

// lineReason es el motivo de una fila inválida en el idioma del contexto (con es, el de siempre).
func lineReason(ctx context.Context, e devices.LineError) string {
	if e.Err == nil {
		return e.Reason
	}
	return i18n.In(i18n.Locale(ctx), e.Err)
}

func devicePB(h devices.Host, label string) *v1.Device {
	return &v1.Device{Name: h.Name, Hostname: h.Name, Target: &v1.Target{Address: h.Address}, Profile: portPB(h), Platform: h.Platform,
		Folder: h.Folder, Tags: h.Tags, CredentialLabel: label, Notes: h.Notes}
}

// PreviewImportHosts lee y valida el archivo entero sin tocar la libreta y deja un token de un solo uso.
func (s *svc) PreviewImportHosts(ctx context.Context, r *v1.PreviewImportHostsRequest) (*v1.PreviewImportHostsResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(ctx, r.Path)
	if err != nil {
		return nil, err
	}
	format, err := devices.ImportFormat(path, r.Format)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	b, err := service.ReadImport(ctx, path, devices.MaxImportBytes)
	if err != nil {
		return nil, err
	}
	parsed, err := devices.ParseImport(format, b)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	files := parsed.Hosts
	saved, err := loadHosts(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	hosts, missing, vaultOK := s.resolve(files)
	tok, exp := s.pend.Add(s.clock(), tokenTTL, previa{hosts, path, len(parsed.Errors)})
	out := &v1.PreviewImportHostsResponse{Token: tok, ExpiresMs: exp.UnixMilli(), Format: format}
	for _, e := range parsed.Errors {
		out.Errors = append(out.Errors, &v1.ImportHostError{Line: int32(e.Line), Field: e.Field, Reason: lineReason(ctx, e)})
	}
	if parsed.NoSum {
		out.Warnings = append(out.Warnings, i18n.T(ctx, "hosts.warn.no_sum", nil))
	}
	faltan := 0
	for i, it := range devices.Plan(hosts, saved) {
		if missing[i] {
			faltan++
		}
		out.Items = append(out.Items, &v1.ImportHostItem{Host: devicePB(it.Host, files[i].CredentialLabel), Key: devices.Key(it.Host), State: it.Estado,
			Reason: it.Motivo, ConflictsWith: it.Con, CredentialMissing: missing[i]})
	}
	switch {
	case faltan > 0 && !vaultOK:
		out.Warnings = append(out.Warnings, i18n.T(ctx, "hosts.warn.import_closed", i18n.A("n", faltan)))
	case faltan > 0:
		out.Warnings = append(out.Warnings, i18n.T(ctx, "hosts.warn.import_label", i18n.A("n", faltan)))
	}
	return out, nil
}

// ApplyImportHosts aplica una decisión por conflicto en una sola transacción. El token se saca al tomarlo, así
// dos llamadas a la vez no aplican la misma vista previa; una decisión mala lo devuelve para corregirla.
func (s *svc) ApplyImportHosts(ctx context.Context, r *v1.ApplyImportHostsRequest) (*v1.ApplyImportHostsResponse, error) {
	s.d.MarkActive()
	now := s.clock()
	pv, exp, ok := s.pend.Take(r.Token)
	if !ok {
		return nil, service.Err(ctx, codes.NotFound, "hosts.err.token", nil)
	}
	if now.After(exp) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "hosts.err.expired", nil)
	}
	dec := map[string]string{}
	invalid := false
	var res devices.Resultado
	var err error
	for _, d := range r.Decisions {
		if _, dup := dec[d.Key]; dup {
			invalid, err = true, service.Err(ctx, codes.InvalidArgument, "hostimport.dup_decision", i18n.A("key", d.Key))
			break
		}
		dec[d.Key] = d.Action
	}
	if err == nil {
		err = s.tx(func(tx *sql.Tx) error {
			// Se vuelve a comparar contra lo guardado ahora: entre la vista previa y aquí pudo cambiar.
			saved, err := loadHosts(tx)
			if err != nil {
				return internal(err)
			}
			if res, err = devices.Apply(devices.Plan(pv.hosts, saved), dec, saved, now.UTC().Truncate(time.Second)); err != nil {
				invalid = true
				return service.ErrFrom(ctx, codes.InvalidArgument, err)
			}
			for _, h := range res.Writes {
				if err := putHost(tx, h); err != nil {
					return internal(err)
				}
			}
			return nil
		})
	}
	if err != nil {
		if invalid {
			s.pend.Restore(r.Token, pv, exp)
		}
		return nil, err
	}
	s.d.Audit("hosts.importar", pv.path, fmt.Sprintf("%d new, %d replaced, %d renamed, %d skipped, %d invalid",
		res.Created, res.Replaced, res.Renamed, res.Skipped, pv.invalid))
	return &v1.ApplyImportHostsResponse{Created: int32(res.Created), Replaced: int32(res.Replaced), Renamed: int32(res.Renamed), Skipped: int32(res.Skipped + pv.invalid), Invalid: int32(pv.invalid)}, nil
}

// HostsImportTemplate da el archivo de ejemplo (encabezado y 3 filas válidas) generado de la tabla de campos del import.
func (s *svc) HostsImportTemplate(ctx context.Context, r *v1.HostsImportTemplateRequest) (*v1.HostsImportTemplateResponse, error) {
	s.d.MarkActive()
	format, err := devices.ImportFormat("", r.Format)
	if err != nil {
		return nil, service.Err(ctx, codes.InvalidArgument, "hosts.err.format", nil)
	}
	b, err := devices.Template(format, s.clock())
	if err != nil {
		return nil, internal(err)
	}
	return &v1.HostsImportTemplateResponse{Format: format, Filename: "hosts-plantilla." + format, Content: string(b)}, nil
}

// HostsImportFormat describe los campos del archivo de import, de la misma tabla que lo valida.
func (s *svc) HostsImportFormat(ctx context.Context, _ *v1.HostsImportFormatRequest) (*v1.HostsImportFormatResponse, error) {
	s.d.MarkActive()
	loc := i18n.Locale(ctx)
	out := &v1.HostsImportFormatResponse{MaxRows: devices.MaxImportHosts, MaxBytes: devices.MaxImportBytes}
	for _, f := range devices.HostFields {
		out.Fields = append(out.Fields, &v1.HostField{Name: f.Name, Type: i18n.MsgOr(loc, "hostfield.type."+f.Type, f.Type), Required: f.Required, Example: f.Examples[0],
			Description: i18n.MsgOr(loc, "hostfield.desc."+f.Name, f.Description)})
	}
	return out, nil
}
