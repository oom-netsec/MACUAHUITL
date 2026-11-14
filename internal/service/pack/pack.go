// Package pack es el servicio gRPC de los paquetes de contenido (.mpack, fase 32, ADR 0010): instala desde una ruta
// local, lista, muestra y quita. Nunca descarga nada; la validación y el almacén viven en internal/pack.
package pack

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	dom "github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// Module registra el servicio. Store es el almacén del núcleo; UserIDs da los IDs de playbook de
// <config>/playbooks (para marcar los tapados); puede ser nil. Para el paquete personal (fase 32c): ConfigDir es la
// carpeta de configuración (los playbooks viven en <ConfigDir>/playbooks), UserPlaybooks los playbooks del usuario
// vigentes y Reload vuelve a leer esa carpeta y recarga el catálogo en caliente; pueden ser nil.
type Module struct {
	Store         *dom.Store
	UserIDs       func() map[string]bool
	ConfigDir     string
	UserPlaybooks func() []playbook.Playbook
	Reload        func() error
}

func (m Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterPackServiceServer(s, &svc{d: d, store: m.Store, userIDs: m.UserIDs, cfg: m})
}

type svc struct {
	v1.UnimplementedPackServiceServer
	d       service.Deps
	store   *dom.Store
	userIDs func() map[string]bool
	cfg     Module
}

// fail traduce un error del paquete a gRPC: el código del catálogo viaja como reason.
func fail(ctx context.Context, err error) error {
	c := codes.InvalidArgument
	switch dom.Reason(err) {
	case "unsigned", "collision", "version", "official_replace", "import.exists", "import.unsupported_fs":
		c = codes.FailedPrecondition
	case "not_found":
		c = codes.NotFound
	}
	return service.ErrFrom(ctx, c, err)
}

func (s *svc) info(p *dom.Pack) (*v1.PackInfo, error) {
	i := &v1.PackInfo{Id: p.ID, Version: p.Version, MinCore: p.MinCore, Name: p.Name, NameEn: p.NameEn, Description: p.Description,
		DescriptionEn: p.DescriptionEn, Platforms: p.Platforms, Author: p.Author, License: p.License, Official: p.Official,
		PlaybookCount: int32(len(p.Playbooks)), ScriptCount: int32(len(p.ScriptIDs()))}
	if s.userIDs != nil {
		u := s.userIDs()
		for _, pb := range p.Playbooks {
			if u[pb.ID] {
				i.Shadowed = append(i.Shadowed, pb.ID)
			}
		}
	}
	h, err := p.Hidden(s.d.DB())
	i.Hidden = h
	return i, err
}

// reject audita el rechazo (en inglés: id, versión, sha256 del archivo, origen, motivo y ruta) y lo traduce a gRPC.
func (s *svc) reject(ctx context.Context, err error, p *dom.Pack, sum, path string) error {
	id, version, origin := "unknown", "unknown", "unknown"
	if p != nil {
		id, version, origin = p.ID, p.Version, p.Origin()
	}
	s.d.Audit("pack.rejected", id, fmt.Sprintf("id=%s version=%s sha256=%s origin=%s reason=%s path=%q", id, version, sum, origin, dom.Reason(err), path))
	return fail(ctx, err)
}

func (s *svc) Install(ctx context.Context, r *v1.PackServiceInstallRequest) (*v1.PackServiceInstallResponse, error) {
	s.d.MarkActive()
	if r.GetPath() == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.path", nil)
	}
	path, err := service.AbsPath(ctx, r.GetPath())
	if err != nil {
		return nil, err
	}
	reject := func(err error, p *dom.Pack, sum string) error { return s.reject(ctx, err, p, sum, path) }
	data, err := dom.ReadArchive(path)
	if err != nil {
		return nil, reject(err, nil, "none")
	}
	sum := dom.SHA256(data)
	// Lo oculto se guarda antes de publicar el paquete (en una sola transacción): si falla, no se instala nada.
	// shortcut: si el disco falla justo después, la elección ya guardada queda aplicada a la versión que seguía instalada.
	hide := []string{}
	var prepErr error
	res, err := s.store.InstallWith(data, r.GetAllowUnsigned(), func(p *dom.Pack, _ string) error {
		items := p.Items()
		for _, id := range r.GetHide() { // los IDs que el paquete no trae se ignoran
			if items[id] {
				hide = append(hide, id)
			}
		}
		prepErr = s.applyInstallHidden(p, hide, r.GetReplaceHidden())
		return prepErr
	})
	if prepErr != nil {
		return nil, status.Error(codes.Internal, "no se instaló nada: no se pudo guardar lo oculto: "+prepErr.Error())
	}
	if err != nil {
		var p *dom.Pack
		if res != nil {
			p = res.Pack
		}
		return nil, reject(err, p, sum)
	}
	p := res.Pack
	detail := installDetail(p, sum, res)
	s.d.Audit("pack.install", p.ID, detail)
	if len(hide) > 0 {
		s.d.Audit("pack.items", p.ID, fmt.Sprintf("id=%s hidden=%d shown=0 at=install", p.ID, len(hide)))
	}
	info, err := s.info(p)
	if err != nil {
		return nil, status.Error(codes.Internal, "el paquete quedó instalado, pero no se pudo leer lo oculto: "+err.Error())
	}
	return &v1.PackServiceInstallResponse{Pack: info, ReplacedVersion: res.Replaced}, nil
}

// Inspect es la vista previa de Install: lee y valida igual, pero no instala ni audita.
func (s *svc) Inspect(ctx context.Context, r *v1.PackServiceInspectRequest) (*v1.PackServiceInspectResponse, error) {
	s.d.MarkActive()
	if r.GetPath() == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.path", nil)
	}
	path, err := service.AbsPath(ctx, r.GetPath())
	if err != nil {
		return nil, err
	}
	data, err := dom.ReadArchive(path)
	if err != nil {
		return nil, fail(ctx, err)
	}
	res, err := s.store.Inspect(data, r.GetAllowUnsigned())
	if err != nil {
		return nil, fail(ctx, err)
	}
	info, err := s.info(res.Pack)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &v1.PackServiceInspectResponse{Pack: info, ScriptIds: res.Pack.ScriptIDs(), ReplacedVersion: res.Replaced}
	for _, pb := range res.Pack.Playbooks {
		out.PlaybookIds = append(out.PlaybookIds, pb.ID)
	}
	return out, nil
}

// applyInstallHidden guarda lo oculto de una instalación: poda los IDs que el paquete ya no trae y, con replace, deja
// hide como el conjunto exacto; sin replace, lo que ya estaba oculto se conserva y hide suma.
func (s *svc) applyInstallHidden(p *dom.Pack, hide []string, replace bool) error {
	tx, err := s.d.DB().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := dom.PruneHidden(tx, p); err != nil {
		return err
	}
	if replace {
		if err := dom.ReplaceHidden(tx, p, hide); err != nil {
			return err
		}
	} else if _, err := dom.SetHidden(tx, p.ID, hide, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *svc) List(ctx context.Context, _ *v1.PackServiceListRequest) (*v1.PackServiceListResponse, error) {
	out := &v1.PackServiceListResponse{}
	for _, p := range s.store.Snapshot().Packs {
		i, err := s.info(p)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		out.Packs = append(out.Packs, i)
	}
	return out, nil
}

func (s *svc) Show(ctx context.Context, r *v1.PackServiceShowRequest) (*v1.PackServiceShowResponse, error) {
	p := s.store.Snapshot().Find(r.GetId())
	if p == nil {
		return nil, fail(ctx, dom.NotFound(r.GetId()))
	}
	i, err := s.info(p)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &v1.PackServiceShowResponse{Pack: i, Readme: p.Readme, ScriptIds: p.ScriptIDs()}
	for _, pb := range p.Playbooks {
		out.PlaybookIds = append(out.PlaybookIds, pb.ID)
	}
	return out, nil
}

func (s *svc) Remove(ctx context.Context, r *v1.PackServiceRemoveRequest) (*v1.PackServiceRemoveResponse, error) {
	s.d.MarkActive()
	// Buscar y quitar es una sola operación bajo el lock del almacén: lo que se limpia después es lo que de verdad se quitó.
	p, err := s.store.Remove(r.GetId())
	if err != nil {
		return nil, fail(ctx, err)
	}
	favs, err := s.cleanup(p)
	s.d.Audit("pack.remove", p.ID, fmt.Sprintf("id=%s version=%s origin=%s playbooks=%d scripts=%d favorites_removed=%d",
		p.ID, p.Version, p.Origin(), len(p.Playbooks), len(p.ScriptIDs()), favs))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.PackServiceRemoveResponse{FavoritesRemoved: int32(favs)}, nil
}

// cleanup borra de colecciones y fijados los scripts del paquete quitado y anota sus IDs de playbook para pack.missing.
func (s *svc) cleanup(p *dom.Pack) (int, error) {
	tx, err := s.d.DB().Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	favs := 0
	for _, id := range p.ScriptIDs() {
		n := int64(0)
		for _, q := range []string{`DELETE FROM script_collection_items WHERE script_id = ?`, `DELETE FROM script_pins WHERE script_id = ?`} {
			res, err := tx.Exec(q, id)
			if err != nil {
				return 0, err
			}
			k, _ := res.RowsAffected()
			n += k
		}
		if n > 0 {
			favs++
		}
	}
	if _, err := tx.Exec(`DELETE FROM pack_hidden WHERE pack = ?`, p.ID); err != nil { // la elección se va con el paquete
		return 0, err
	}
	for _, pb := range p.Playbooks {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO pack_removed(playbook_id, pack) VALUES(?, ?)`, pb.ID, p.ID); err != nil {
			return 0, err
		}
	}
	return favs, tx.Commit()
}

func (s *svc) SetItems(ctx context.Context, r *v1.PackServiceSetItemsRequest) (*v1.PackServiceSetItemsResponse, error) {
	s.d.MarkActive()
	p := s.store.Snapshot().Find(r.GetPackId())
	if p == nil {
		return nil, fail(ctx, dom.NotFound(r.GetPackId()))
	}
	if len(r.GetHide())+len(r.GetShow()) == 0 {
		return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.items_empty", nil)
	}
	for _, id := range append(slices.Clone(r.GetHide()), r.GetShow()...) {
		if !p.HasItem(id) || slices.Contains(r.GetHide(), id) && slices.Contains(r.GetShow(), id) {
			return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.item", i18n.A("id", id, "pack", p.ID))
		}
	}
	tx, err := s.d.DB().Begin()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer tx.Rollback()
	changed, err := dom.SetHidden(tx, p.ID, r.GetHide(), r.GetShow())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := tx.Commit(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if changed > 0 { // solo cambios reales
		s.d.Audit("pack.items", p.ID, fmt.Sprintf("id=%s hidden=%d shown=%d", p.ID, len(r.GetHide()), len(r.GetShow())))
	}
	i, err := s.info(p)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.PackServiceSetItemsResponse{Pack: i}, nil
}

// installDetail es el detalle de la auditoría pack.install (en inglés, como toda la auditoría).
func installDetail(p *dom.Pack, sum string, res *dom.Result) string {
	detail := fmt.Sprintf("id=%s version=%s sha256=%s origin=%s playbooks=%d scripts=%d", p.ID, p.Version, sum, p.Origin(), len(p.Playbooks), len(p.ScriptIDs()))
	if res.Replaced != "" {
		detail += " replaced=" + res.Replaced
	}
	if p.DevCore {
		detail += " min_core_unchecked=true"
	}
	if res.SyncWarning != nil {
		detail += fmt.Sprintf(" fsync_warning=%q", res.SyncWarning.Error())
	}
	return detail
}
