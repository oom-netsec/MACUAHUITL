// Package pack es el servicio gRPC de los paquetes de contenido (.mpack, fase 32, ADR 0010): instala desde una ruta
// local, lista, muestra y quita. Nunca descarga nada; la validación y el almacén viven en internal/pack.
package pack

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	dom "github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// Module registra el servicio. Store es el almacén del núcleo; UserIDs da los IDs de playbook de
// <config>/playbooks (para marcar los tapados); puede ser nil.
type Module struct {
	Store   *dom.Store
	UserIDs func() map[string]bool
}

func (m Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterPackServiceServer(s, &svc{d: d, store: m.Store, userIDs: m.UserIDs})
}

type svc struct {
	v1.UnimplementedPackServiceServer
	d       service.Deps
	store   *dom.Store
	userIDs func() map[string]bool
}

// fail traduce un error del paquete a gRPC: el código del catálogo viaja como reason.
func fail(ctx context.Context, err error) error {
	c := codes.InvalidArgument
	switch dom.Reason(err) {
	case "unsigned", "collision", "version", "official_replace":
		c = codes.FailedPrecondition
	case "not_found":
		c = codes.NotFound
	}
	return service.ErrFrom(ctx, c, err)
}

func (s *svc) info(p *dom.Pack) *v1.PackInfo {
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
	return i
}

func (s *svc) Install(ctx context.Context, r *v1.PackServiceInstallRequest) (*v1.PackServiceInstallResponse, error) {
	s.d.MarkActive()
	if r.GetPath() == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "pack.err.path", nil)
	}
	// Auditoría en inglés: id, versión, sha256 del archivo, origen y, si se rechaza, el motivo.
	reject := func(err error, id, sum, origin string) error {
		s.d.Audit("pack.rejected", id, fmt.Sprintf("id=%s sha256=%s origin=%s reason=%s path=%q", id, sum, origin, dom.Reason(err), r.Path))
		return fail(ctx, err)
	}
	data, err := dom.ReadArchive(r.Path)
	if err != nil {
		return nil, reject(err, "unknown", "none", "unknown")
	}
	sum := dom.SHA256(data)
	res, err := s.store.Install(data, r.GetAllowUnsigned())
	if err != nil {
		if res != nil && res.Pack != nil {
			return nil, reject(err, res.Pack.ID, sum, res.Pack.Origin())
		}
		return nil, reject(err, "unknown", sum, "unknown")
	}
	p := res.Pack
	detail := fmt.Sprintf("id=%s version=%s sha256=%s origin=%s playbooks=%d scripts=%d", p.ID, p.Version, sum, p.Origin(), len(p.Playbooks), len(p.ScriptIDs()))
	if res.Replaced != "" {
		detail += " replaced=" + res.Replaced
	}
	if p.DevCore {
		detail += " min_core_unchecked=true"
	}
	s.d.Audit("pack.install", p.ID, detail)
	return &v1.PackServiceInstallResponse{Pack: s.info(p), ReplacedVersion: res.Replaced}, nil
}

func (s *svc) List(ctx context.Context, _ *v1.PackServiceListRequest) (*v1.PackServiceListResponse, error) {
	out := &v1.PackServiceListResponse{}
	for _, p := range s.store.Snapshot().Packs {
		out.Packs = append(out.Packs, s.info(p))
	}
	return out, nil
}

func (s *svc) Show(ctx context.Context, r *v1.PackServiceShowRequest) (*v1.PackServiceShowResponse, error) {
	p := s.store.Snapshot().Find(r.GetId())
	if p == nil {
		return nil, fail(ctx, dom.NotFound(r.GetId()))
	}
	out := &v1.PackServiceShowResponse{Pack: s.info(p), Readme: p.Readme, ScriptIds: p.ScriptIDs()}
	for _, pb := range p.Playbooks {
		out.PlaybookIds = append(out.PlaybookIds, pb.ID)
	}
	return out, nil
}

func (s *svc) Remove(ctx context.Context, r *v1.PackServiceRemoveRequest) (*v1.PackServiceRemoveResponse, error) {
	s.d.MarkActive()
	p := s.store.Snapshot().Find(r.GetId())
	if p == nil {
		return nil, fail(ctx, dom.NotFound(r.GetId()))
	}
	tx, err := s.d.DB().Begin()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer tx.Rollback()
	favs := 0
	for _, id := range p.ScriptIDs() {
		n := int64(0)
		for _, q := range []string{`DELETE FROM script_collection_items WHERE script_id = ?`, `DELETE FROM script_pins WHERE script_id = ?`} {
			res, err := tx.Exec(q, id)
			if err != nil {
				return nil, status.Error(codes.Internal, err.Error())
			}
			k, _ := res.RowsAffected()
			n += k
		}
		if n > 0 {
			favs++
		}
	}
	for _, pb := range p.Playbooks {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO pack_removed(playbook_id, pack) VALUES(?, ?)`, pb.ID, p.ID); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	if _, err := s.store.Remove(p.ID); err != nil {
		return nil, fail(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.d.Audit("pack.remove", p.ID, fmt.Sprintf("id=%s version=%s origin=%s playbooks=%d scripts=%d favorites_removed=%d",
		p.ID, p.Version, p.Origin(), len(p.Playbooks), len(p.ScriptIDs()), favs))
	return &v1.PackServiceRemoveResponse{FavoritesRemoved: int32(favs)}, nil
}
