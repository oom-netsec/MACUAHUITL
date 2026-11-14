package pack

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	dom "github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

// Paquete personal (fase 32c, ADR 0010): exportar scripts y playbooks del usuario a un .mpack sin firma e importar uno
// de vuelta a «Mis scripts» y <config>/playbooks. Nada de esto escribe en equipos.

// beforePublish es un gancho de pruebas: corre justo antes de publicar los playbooks del import (nil en producción).
var beforePublish func()

func internal(err error) error { return status.Error(codes.Internal, err.Error()) }

func (s *svc) Export(ctx context.Context, r *v1.PackServiceExportRequest) (*v1.PackServiceExportResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(ctx, r.GetPath())
	if err != nil {
		return nil, err
	}
	if len(r.GetScriptIds()) > scripts.MaxImportScripts {
		return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.export.range", i18n.A("max", scripts.MaxImportScripts))
	}
	var sel []scripts.Script
	if len(r.GetScriptIds()) > 0 {
		user, err := scripts.LoadUser(s.d.DB())
		if err != nil {
			return nil, internal(err)
		}
		byID := map[string]scripts.Script{}
		for _, u := range user {
			byID[u.ID] = u
		}
		seen := map[string]bool{}
		for _, id := range r.GetScriptIds() {
			if seen[id] {
				continue
			}
			seen[id] = true
			u, ok := byID[id]
			if !ok { // solo scripts del usuario: los de biblioteca ya viajan en su paquete
				return nil, service.Err(ctx, codes.NotFound, "scripts.svc.not_found", i18n.A("id", id))
			}
			sel = append(sel, u)
		}
	}
	var pbs []playbook.Playbook
	if r.GetIncludePlaybooks() && s.cfg.UserPlaybooks != nil {
		pbs = s.cfg.UserPlaybooks()
	}
	res, err := dom.Export(dom.ExportInput{ID: r.GetEditorName(), Name: r.GetName(), NameEn: r.GetNameEn(), Description: r.GetDescription(),
		DescriptionEn: r.GetDescriptionEn(), Author: r.GetAuthor(), License: r.GetLicense(), Core: s.store.CoreVersion(), TakenNames: s.store.TakenScriptNames(),
		Now: s.d.Now().Local(), Scripts: sel, Playbooks: pbs})
	if err != nil {
		return nil, fail(ctx, err)
	}
	if err := service.WriteExport(ctx, path, res.Data, r.GetOverwrite()); err != nil {
		return nil, err
	}
	sum := dom.SHA256(res.Data)
	s.d.Audit("pack.export", res.Manifest.ID, fmt.Sprintf("id=%s version=%s sha256=%s scripts=%d playbooks=%d omitted=%d path=%q",
		res.Manifest.ID, res.Manifest.Version, sum, res.Scripts, res.Playbooks, len(res.Omitted), path))
	return &v1.PackServiceExportResponse{Id: res.Manifest.ID, Version: res.Manifest.Version, Sha256: sum, Scripts: int32(res.Scripts),
		Playbooks: int32(res.Playbooks), OmittedPlaybooks: res.Omitted}, nil
}

func (s *svc) Import(ctx context.Context, r *v1.PackServiceImportRequest) (*v1.PackServiceImportResponse, error) {
	s.d.MarkActive()
	if r.GetPath() == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.path", nil)
	}
	if s.cfg.ConfigDir == "" {
		return nil, service.Err(ctx, codes.Unavailable, "pack.err.import.unavailable", nil)
	}
	path, err := service.AbsPath(ctx, r.GetPath())
	if err != nil {
		return nil, err
	}
	data, err := dom.ReadArchive(path)
	if err != nil {
		return nil, s.reject(ctx, err, nil, "none", path)
	}
	sum := dom.SHA256(data)
	if r.GetConfirm() && r.GetSha256() == "" {
		return nil, s.reject(ctx, i18n.New("pack.err.import.sha256_missing", nil), nil, sum, path)
	}
	if r.GetConfirm() && !strings.EqualFold(r.GetSha256(), sum) {
		return nil, s.reject(ctx, i18n.New("pack.err.import.changed", nil), nil, sum, path)
	}
	p, err := s.store.VerifyImport(data)
	if err != nil {
		return nil, s.reject(ctx, err, p, sum, path)
	}
	library := func() ([]scripts.Script, error) {
		lib, _, err := scripts.LibraryWith(playbooks.FS, s.store.Snapshot().Contenido())
		return lib, err
	}
	dir := filepath.Join(s.cfg.ConfigDir, "playbooks")
	var userIDs map[string]bool
	if s.userIDs != nil {
		userIDs = s.userIDs()
	}
	info, err := s.info(p)
	if err != nil {
		return nil, internal(err)
	}
	out := &v1.PackServiceImportResponse{Pack: info, Sha256: sum}
	if !r.GetConfirm() {
		user, err := scripts.LoadUser(s.d.DB())
		if err != nil {
			return nil, internal(err)
		}
		lib, err := library()
		if err != nil {
			return nil, internal(err)
		}
		for _, it := range scripts.Plan(p.Scripts, user, lib) {
			out.Items = append(out.Items, &v1.PackImportItem{Kind: "script", Id: it.Script.ID, Name: it.Script.Name, State: it.Estado, ConflictsWith: it.Con})
		}
		pn := map[string]string{}
		for _, pb := range p.Playbooks {
			pn[pb.ID] = pb.Name
		}
		for _, it := range s.store.PlanPlaybooks(p, dir, userIDs) {
			out.Items = append(out.Items, &v1.PackImportItem{Kind: "playbook", Id: it.ID, Name: pn[it.ID], State: it.State, ConflictsWith: it.With})
		}
		return out, nil
	}
	// Decisiones: las de playbook llevan «/» en su ID; las demás son de script. Nunca se reemplaza.
	scDec, pbDec := map[string]string{}, map[string]string{}
	for _, d := range r.GetDecisions() {
		m := scDec
		if strings.Contains(d.GetItemId(), "/") {
			m = pbDec
		}
		if _, dup := m[d.GetItemId()]; dup || d.GetAction() == scripts.Reemplazar {
			return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.import.decision", i18n.A("id", d.GetItemId()))
		}
		m[d.GetItemId()] = d.GetAction()
	}
	var pbRes *dom.PlaybookResult
	var sres scripts.Resultado
	// Orden de candados: primero el del almacén, después la base (Install toma el del almacén y luego abre su transacción).
	err = s.store.Locked(func() error {
		tx, err := s.d.DB().Begin()
		if err != nil {
			return internal(err)
		}
		defer tx.Rollback()
		user, err := scripts.LoadUser(tx)
		if err != nil {
			return internal(err)
		}
		lib, err := library() // bajo el candado: un Install que terminó mientras se esperaba ya cuenta
		if err != nil {
			return internal(err)
		}
		if sres, err = scripts.Apply(scripts.Plan(p.Scripts, user, lib), scDec, user, lib, s.d.Now().UTC().Truncate(time.Second)); err != nil {
			return service.ErrFrom(ctx, codes.InvalidArgument, err)
		}
		for _, x := range sres.Writes {
			if err := scripts.Insert(tx, x); err != nil {
				return internal(err)
			}
		}
		// Orden: los playbooks se preparan con nombre temporal (el catálogo no los lee), se confirman los scripts y recién
		// entonces se publican con un enlace atómico. Una caída entre el commit y la publicación deja los scripts confirmados y los
		// playbooks solo como temporales (invisibles): el reimport los ve como scripts iguales y publica los playbooks.
		if pbRes, err = s.store.StagePlaybooksLocked(p, dir, userIDs, pbDec); err != nil {
			tx.Rollback() // la auditoría escribe en la misma base: no puede haber una transacción abierta
			return s.reject(ctx, err, p, sum, path)
		}
		if err := tx.Commit(); err != nil {
			pbRes.Undo(dir)
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if beforePublish != nil {
		beforePublish()
	}
	if err := pbRes.Publish(dir); err != nil { // los scripts ya están confirmados: se retiran para no dejar el import a medias
		var left []string
		for _, x := range sres.Writes {
			if _, derr := s.d.DB().Exec(`DELETE FROM scripts WHERE id = ?`, x.ID); derr != nil {
				left = append(left, x.ID)
				s.d.Audit("pack.import.compensate_failed", p.ID, fmt.Sprintf("script=%s error=%q", x.ID, derr))
			}
		}
		if len(left) > 0 { // quedaron scripts importados sin sus playbooks: que el ingeniero lo sepa
			return nil, service.Err(ctx, codes.Internal, "pack.err.import.compensate", i18n.A("ids", strings.Join(left, ", "), "reason", dom.Reason(err)))
		}
		return nil, s.reject(ctx, err, p, sum, path)
	}
	if s.cfg.Reload != nil {
		if err := s.cfg.Reload(); err != nil { // los archivos ya están: el catálogo los toma en el próximo arranque
			s.d.Audit("pack.import.reload_failed", p.ID, "reason="+dom.Reason(err))
		}
	}
	s.d.Audit("pack.import", p.ID, fmt.Sprintf("id=%s version=%s sha256=%s origin=%s scripts_created=%d scripts_renamed=%d scripts_skipped=%d playbooks_created=%d playbooks_renamed=%d playbooks_skipped=%d path=%q",
		p.ID, p.Version, sum, p.Origin(), sres.Created, sres.Renamed, sres.Skipped, pbRes.Created, pbRes.Renamed, pbRes.Skipped, path))
	out.Applied = true
	out.ScriptsCreated, out.ScriptsRenamed, out.ScriptsSkipped = int32(sres.Created), int32(sres.Renamed), int32(sres.Skipped)
	out.PlaybooksCreated, out.PlaybooksRenamed, out.PlaybooksSkipped = int32(pbRes.Created), int32(pbRes.Renamed), int32(pbRes.Skipped)
	out.PlaybookIds = slices.Clone(pbRes.Written)
	return out, nil
}
