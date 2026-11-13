package pack

import (
	"context"
	"database/sql"
	"encoding/json"
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

// Estas consultas repiten las de internal/service/scripts (un servicio no importa a otro): la tabla scripts es la misma.
const columns = `id, name, tech, platform, description, commands_json, tags_json, created_at, updated_at`

func scan(r interface{ Scan(...any) error }) (scripts.Script, error) {
	var s scripts.Script
	var cmds, tags, created, updated string
	if err := r.Scan(&s.ID, &s.Name, &s.Tech, &s.Platform, &s.Description, &cmds, &tags, &created, &updated); err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(cmds), &s.Commands); err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(tags), &s.Tags); err != nil {
		return s, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, created)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	s.Origin = scripts.OrigenUsuario
	return s, nil
}

type querier interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	Exec(string, ...any) (sql.Result, error)
}

func loadUser(q querier) ([]scripts.Script, error) {
	rows, err := q.Query(`SELECT ` + columns + ` FROM scripts ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scripts.Script
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// put inserta; el import nunca reemplaza (el plan lo prohíbe), así que no hay ON CONFLICT: un ID repetido falla.
func put(q querier, s scripts.Script) error {
	cmds, _ := json.Marshal(s.Commands)
	tags, _ := json.Marshal(s.Tags)
	_, err := q.Exec(`INSERT INTO scripts(`+columns+`) VALUES(?,?,?,?,?,?,?,?,?)`,
		s.ID, s.Name, s.Tech, s.Platform, s.Description, string(cmds), string(tags),
		s.CreatedAt.UTC().Format(time.RFC3339), s.UpdatedAt.UTC().Format(time.RFC3339))
	return err
}

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
		user, err := loadUser(s.d.DB())
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
	if r.GetConfirm() && r.GetSha256() != "" && !strings.EqualFold(r.GetSha256(), sum) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "pack.err.import.changed", nil)
	}
	p, err := s.store.VerifyImport(data)
	if err != nil {
		return nil, s.reject(ctx, err, p, sum, path)
	}
	lib, _, err := scripts.LibraryWith(playbooks.FS, s.store.Snapshot().Contenido())
	if err != nil {
		return nil, internal(err)
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
		user, err := loadUser(s.d.DB())
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
	tx, err := s.d.DB().Begin()
	if err != nil {
		return nil, internal(err)
	}
	defer tx.Rollback()
	user, err := loadUser(tx)
	if err != nil {
		return nil, internal(err)
	}
	if sres, err = scripts.Apply(scripts.Plan(p.Scripts, user, lib), scDec, user, lib, s.d.Now().UTC().Truncate(time.Second)); err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	for _, x := range sres.Writes {
		if err := put(tx, x); err != nil {
			return nil, internal(err)
		}
	}
	// Orden: los playbooks se preparan con nombre temporal (el catálogo no los lee), se confirman los scripts y recién
	// entonces se publican con un enlace atómico. Una caída antes de publicar deja solo temporales; nada visible a medias.
	if pbRes, err = s.store.StagePlaybooks(p, dir, userIDs, pbDec); err != nil {
		tx.Rollback() // la auditoría escribe en la misma base: no puede haber una transacción abierta
		return nil, s.reject(ctx, err, p, sum, path)
	}
	if err := tx.Commit(); err != nil {
		pbRes.Undo(dir)
		return nil, internal(err)
	}
	if beforePublish != nil {
		beforePublish()
	}
	if err := pbRes.Publish(dir); err != nil { // los scripts ya están confirmados: se retiran para no dejar el import a medias
		for _, x := range sres.Writes {
			s.d.DB().Exec(`DELETE FROM scripts WHERE id = ?`, x.ID)
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
