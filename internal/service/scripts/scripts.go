// Package scripts es el servicio gRPC de la bóveda de scripts (fase 28c): guarda los del usuario en el store,
// suma la biblioteca embebida y hace el export/import. Un script nunca se aplica a un equipo desde aquí (ADR 0007).
package scripts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/pack"
	dom "github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

const tokenTTL = 10 * time.Minute

// Tipos de vista previa: un token de un tipo no vale para aplicar el otro.
const (
	pendScripts = "scripts"
	pendCols    = "colecciones"
)

type pending struct {
	kind    string
	scripts []dom.Script
	cols    []dom.Coleccion // solo en pendCols
	path    string
	expires time.Time
}

type svc struct {
	v1.UnimplementedScriptsServiceServer
	d      service.Deps
	now    func() time.Time // nil = d.Now; las pruebas lo fijan para vencer tokens
	packs  *pack.Store      // paquetes instalados; nil = solo la biblioteca base
	libMu  sync.Mutex
	libFor *pack.Snapshot // foto de paquetes con la que se armó lib; una foto nueva (instalar o quitar) invalida la caché
	lib    []dom.Script
	libEN  map[string]dom.Texto
	libErr error
	pend   service.Pending[pending]
}

// Module registra el servicio de scripts. Packs es el almacén de paquetes de contenido, de donde salen los scripts
// de la biblioteca que no vienen en el binario; puede ser nil.
type Module struct{ Packs *pack.Store }

func (m Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterScriptsServiceServer(s, &svc{d: d, packs: m.Packs})
}

func (s *svc) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return s.d.Now()
}

func (s *svc) library() ([]dom.Script, error) {
	lib, _, err := s.libraryEN()
	return lib, err
}

// BaseLibrary son los IDs y nombres de los scripts de la biblioteca base (la del binario, sin paquetes): con ellos el
// almacén de paquetes detecta choques. Lo pide el núcleo, que no importa el dominio de scripts (ADR 0008).
func BaseLibrary() (ids, names []string, err error) {
	lib, _, err := dom.LibraryWithEN(playbooks.FS)
	for _, x := range lib {
		ids, names = append(ids, x.ID), append(names, x.Name)
	}
	return ids, names, err
}

// libraryEN arma la biblioteca (base más paquetes instalados) y su texto en inglés; se vuelve a armar cuando cambia
// la foto de paquetes.
func (s *svc) libraryEN() ([]dom.Script, map[string]dom.Texto, error) {
	var snap *pack.Snapshot
	var extra []dom.Contenido
	if s.packs != nil {
		snap = s.packs.Snapshot()
		extra = snap.Contenido()
	}
	s.libMu.Lock()
	defer s.libMu.Unlock()
	if s.lib == nil && s.libErr == nil || s.libFor != snap {
		s.lib, s.libEN, s.libErr = dom.LibraryWith(playbooks.FS, extra)
		s.libFor = snap
	}
	if s.libErr != nil {
		return nil, nil, status.Error(codes.Internal, s.libErr.Error())
	}
	return s.lib, s.libEN, nil
}

// in da el script en el idioma de la llamada: los de fábrica con su nombre y descripción en inglés; los del usuario, tal cual.
func (s *svc) in(ctx context.Context, x dom.Script) dom.Script {
	if x.Origin != dom.OrigenBiblioteca {
		return x
	}
	lib, err := s.library()
	if err != nil {
		return x
	}
	for _, l := range lib { // un script de un archivo de import con el id de uno de fábrica solo se traduce si es idéntico en nombre y descripción
		if l.ID == x.ID {
			if l.Name != x.Name || l.Description != x.Description {
				return x
			}
			break
		}
	}
	_, en, _ := s.libraryEN()
	return en[x.ID].In(i18n.Locale(ctx), x)
}

// avisosIn escribe en el idioma pedido los avisos del lector de archivos (el de siempre es el de es).
func avisosIn(loc string, avisos []string) []string {
	out := make([]string, len(avisos))
	for i, a := range avisos {
		out[i] = a
		if a == dom.AvisoSinSuma {
			out[i] = i18n.Msg(loc, "scripts.imp.no_sum", nil)
		}
	}
	return out
}

// warnsIn da los avisos en el idioma pedido cuando traen su texto de catálogo.
func warnsIn(loc string, es []string, tx []i18n.Text) []string {
	if len(tx) != len(es) {
		return es
	}
	out := make([]string, len(tx))
	for i, t := range tx {
		out[i] = t.In(loc)
	}
	return out
}

func internal(err error) error { return status.Error(codes.Internal, err.Error()) }

func ms(t time.Time) int64 { return t.UnixMilli() }

func toPB(x dom.Script, m meta) *v1.Script {
	return &v1.Script{Id: x.ID, Name: x.Name, Tech: x.Tech, Platform: x.Platform, Description: x.Description,
		Commands: x.Commands, Tags: x.Tags, Origin: x.Origin, CreatedMs: ms(x.CreatedAt), UpdatedMs: ms(x.UpdatedAt),
		ReadOnly: x.ReadOnly(), Favorite: m.fav[x.ID], Pinned: m.pinned[x.ID], Collections: m.cols[x.ID]}
}

func fromPB(p *v1.Script) dom.Script {
	return dom.Script{ID: p.Id, Name: strings.TrimSpace(p.Name), Tech: p.Tech, Platform: p.Platform, Description: p.Description,
		Commands: append([]string{}, p.Commands...), Tags: append([]string{}, p.Tags...), Origin: dom.OrigenUsuario}
}

// find busca un script en la biblioteca y luego en los del usuario.
func (s *svc) find(ctx context.Context, q querier, id string) (dom.Script, error) {
	if dom.IsLib(id) {
		lib, err := s.library()
		if err != nil {
			return dom.Script{}, err
		}
		for _, x := range lib {
			if x.ID == id {
				return x, nil
			}
		}
		return dom.Script{}, service.Err(ctx, codes.NotFound, "scripts.svc.not_found", i18n.A("id", id))
	}
	x, err := getUser(q, id)
	if errors.Is(err, sql.ErrNoRows) {
		return x, service.Err(ctx, codes.NotFound, "scripts.svc.not_found", i18n.A("id", id))
	}
	if err != nil {
		return x, internal(err)
	}
	return x, nil
}

func (s *svc) tx(f func(tx *sql.Tx) error) error {
	tx, err := s.d.DB().Begin()
	if err != nil {
		return internal(err)
	}
	defer tx.Rollback()
	if err := f(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return internal(err)
	}
	return nil
}

// nameTaken dice si name ya lo tiene un script de all (salvo exceptID) o uno de la biblioteca: los nombres de
// la biblioteca están ocupados para que un export de ambos siempre se pueda reimportar.
func (s *svc) nameTaken(ctx context.Context, all []dom.Script, name, exceptID string) (bool, error) {
	lib, libEN, err := s.libraryEN()
	if err != nil {
		return false, err
	}
	for _, x := range append(append([]dom.Script{}, lib...), all...) {
		if dom.NameKey(x.Name) == dom.NameKey(name) && x.ID != exceptID {
			return true, nil
		}
	}
	for id, en := range libEN { // el nombre en inglés de uno de fábrica también está ocupado
		if en.Name != "" && dom.NameKey(en.Name) == dom.NameKey(name) && id != exceptID {
			return true, nil
		}
	}
	return false, nil
}

func (s *svc) ListScripts(ctx context.Context, r *v1.ListScriptsRequest) (*v1.ListScriptsResponse, error) {
	s.d.MarkActive()
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	user, err := loadUser(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	m, err := loadMeta(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	text := strings.ToLower(r.Text)
	var all []dom.Script
	for _, x := range append(append([]dom.Script{}, lib...), user...) {
		switch {
		case r.OnlyFavorites && !m.fav[x.ID]:
		case r.Tech != "" && x.Tech != r.Tech:
		case r.Platform != "" && x.Platform != r.Platform && x.Platform != "cualquiera":
		case r.Tag != "" && !has(x.Tags, r.Tag):
		case text != "" && !strings.Contains(strings.ToLower(strings.Join([]string{x.Name, x.Description, strings.Join(x.Tags, " "), strings.Join(x.Commands, "\n")}, "\n")), text):
		default:
			all = append(all, s.in(ctx, x)) // se traduce antes de ordenar: el orden sigue al idioma
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	out := &v1.ListScriptsResponse{}
	for _, x := range all {
		out.Scripts = append(out.Scripts, toPB(x, m))
	}
	return out, nil
}

func has(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func (s *svc) GetScript(ctx context.Context, r *v1.GetScriptRequest) (*v1.GetScriptResponse, error) {
	s.d.MarkActive()
	x, err := s.find(ctx, s.d.DB(), r.Id)
	if err != nil {
		return nil, err
	}
	m, err := loadMeta(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	return &v1.GetScriptResponse{Script: toPB(s.in(ctx, x), m)}, nil
}

func (s *svc) SaveScript(ctx context.Context, r *v1.SaveScriptRequest) (*v1.SaveScriptResponse, error) {
	s.d.MarkActive()
	if r.Script == nil {
		return nil, service.Err(ctx, codes.InvalidArgument, "scripts.svc.no_script", nil)
	}
	x := fromPB(r.Script)
	if dom.IsLib(x.ID) {
		return nil, service.Err(ctx, codes.InvalidArgument, "scripts.svc.lib_no_edit", nil)
	}
	now := s.clock().UTC().Truncate(time.Second)
	x.CreatedAt, x.UpdatedAt = now, now
	action := "scripts.crear"
	err := s.tx(func(tx *sql.Tx) error {
		if x.ID == "" {
			x.ID = dom.NewID()
		} else {
			old, err := s.find(ctx, tx, x.ID)
			if err != nil {
				return err
			}
			x.CreatedAt, action = old.CreatedAt, "scripts.editar"
		}
		if err := x.Validate(); err != nil {
			return service.ErrFrom(ctx, codes.InvalidArgument, err)
		}
		user, err := loadUser(tx)
		if err != nil {
			return internal(err)
		}
		taken, err := s.nameTaken(ctx, user, x.Name, x.ID)
		if err != nil {
			return err
		}
		if taken {
			return service.Err(ctx, codes.AlreadyExists, "scripts.svc.name_taken", i18n.A("name", x.Name))
		}
		if err := put(tx, x); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit(action, x.ID, x.Name)
	m, _ := loadMeta(s.d.DB())
	return &v1.SaveScriptResponse{Script: toPB(s.in(ctx, x), m)}, nil
}

func (s *svc) DeleteScript(ctx context.Context, r *v1.DeleteScriptRequest) (*v1.DeleteScriptResponse, error) {
	s.d.MarkActive()
	if dom.IsLib(r.Id) {
		return nil, service.Err(ctx, codes.InvalidArgument, "scripts.svc.lib_no_delete", nil)
	}
	var name string
	err := s.tx(func(tx *sql.Tx) error {
		x, err := s.find(ctx, tx, r.Id)
		if err != nil {
			return err
		}
		name = x.Name
		if _, err := tx.Exec(`DELETE FROM scripts WHERE id = ?`, r.Id); err != nil {
			return internal(err)
		}
		// Fuera de todas las colecciones y de los fijados.
		if _, err := tx.Exec(`DELETE FROM script_collection_items WHERE script_id = ?`, r.Id); err != nil {
			return internal(err)
		}
		if _, err := tx.Exec(`DELETE FROM script_pins WHERE script_id = ?`, r.Id); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.borrar", r.Id, name)
	return &v1.DeleteScriptResponse{}, nil
}

func (s *svc) SetFavorite(ctx context.Context, r *v1.SetFavoriteRequest) (*v1.SetFavoriteResponse, error) {
	s.d.MarkActive()
	err := s.tx(func(tx *sql.Tx) error {
		if _, err := s.find(ctx, tx, r.Id); err != nil {
			return err
		}
		fav, err := getCollection(tx, dom.FavoritosID)
		if err != nil {
			return internal(err)
		}
		switch had := slices.Contains(fav.ScriptIDs, r.Id); {
		case had == r.Favorite: // ya estaba como se pide
			return nil
		case r.Favorite:
			if len(fav.ScriptIDs) >= dom.MaxScriptsColeccion {
				return service.Err(ctx, codes.FailedPrecondition, "scripts.svc.fav_max", i18n.A("max", dom.MaxScriptsColeccion))
			}
			fav.ScriptIDs = append(fav.ScriptIDs, r.Id)
		default:
			fav.ScriptIDs = slices.DeleteFunc(fav.ScriptIDs, func(x string) bool { return x == r.Id })
		}
		fav.UpdatedAt = s.clock().UTC().Truncate(time.Second)
		if err := putCollection(tx, fav); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.favorito", r.Id, map[bool]string{true: "marked", false: "unmarked"}[r.Favorite])
	return &v1.SetFavoriteResponse{}, nil
}

func (s *svc) DuplicateScript(ctx context.Context, r *v1.DuplicateScriptRequest) (*v1.DuplicateScriptResponse, error) {
	s.d.MarkActive()
	var c dom.Script
	err := s.tx(func(tx *sql.Tx) error {
		x, err := s.find(ctx, tx, r.Id)
		if err != nil {
			return err
		}
		user, err := loadUser(tx)
		if err != nil {
			return internal(err)
		}
		now := s.clock().UTC().Truncate(time.Second)
		c = x
		c.ID, c.Origin, c.CreatedAt, c.UpdatedAt = dom.NewID(), dom.OrigenUsuario, now, now
		c.Name = dom.NombreLibre(x.Name, "copia", func(n string) bool { t, _ := s.nameTaken(ctx, user, n, ""); return t })
		if err := put(tx, c); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.crear", c.ID, c.Name+" (copy of "+r.Id+")")
	return &v1.DuplicateScriptResponse{Script: toPB(c, meta{})}, nil
}

func (s *svc) ExportScripts(ctx context.Context, r *v1.ExportScriptsRequest) (*v1.ExportScriptsResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(r.Path)
	if err != nil {
		return nil, err
	}
	if len(r.Ids) < 1 || len(r.Ids) > dom.MaxImportScripts {
		return nil, service.Err(ctx, codes.InvalidArgument, "scripts.svc.export_range", i18n.A("max", dom.MaxImportScripts))
	}
	var sel []dom.Script
	seen := map[string]bool{}
	for _, id := range r.Ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		x, err := s.find(ctx, s.d.DB(), id)
		if err != nil {
			return nil, err
		}
		sel = append(sel, x)
	}
	names := map[string]bool{}
	for _, x := range sel {
		if k := dom.NameKey(x.Name); names[k] {
			return nil, service.Err(ctx, codes.InvalidArgument, "scripts.svc.export_dup", i18n.A("name", x.Name))
		} else {
			names[k] = true
		}
	}
	b, err := dom.Marshal(sel, s.clock())
	if err != nil {
		return nil, internal(err)
	}
	if len(b) > dom.MaxImportBytes {
		return nil, service.Err(ctx, codes.InvalidArgument, "scripts.svc.export_big", nil)
	}
	if err := service.WriteExport(ctx, path, b, r.Overwrite); err != nil {
		return nil, err
	}
	s.d.Audit("scripts.exportar", path, fmt.Sprintf("%d scripts", len(sel)))
	return &v1.ExportScriptsResponse{Count: int32(len(sel))}, nil
}

// stash guarda una vista previa y da su token y su vencimiento (ver service.Pending: los vencidos se limpian y, con
// el tope lleno, el más viejo cede su lugar).
func (s *svc) stash(p pending) (string, time.Time) {
	p.expires = s.clock().Add(tokenTTL)
	return s.pend.Add(s.clock(), tokenTTL, p)
}

// take saca el token bajo el lock: dos aplicaciones a la vez no pueden usar la misma vista previa. Un token
// de otro tipo se rechaza sin gastarlo; uno vencido sí se gasta.
func (s *svc) take(ctx context.Context, tok, kind string) (pending, error) {
	p, exp, ok := s.pend.Take(tok)
	if !ok {
		return p, service.Err(ctx, codes.NotFound, "scripts.svc.token_unknown", nil)
	}
	if p.kind != kind {
		s.pend.Restore(tok, p, exp)
		return p, service.Err(ctx, codes.FailedPrecondition, "scripts.svc.token_kind", i18n.A("kind", p.kind, "kind_en", map[string]string{pendScripts: "scripts", pendCols: "collections"}[p.kind]))
	}
	if s.clock().After(exp) {
		return p, service.Err(ctx, codes.FailedPrecondition, "scripts.svc.preview_expired", nil)
	}
	return p, nil
}

// restore devuelve un token cuya aplicación falló por una decisión mala, para que se pueda corregir.
func (s *svc) restore(tok string, p pending) { s.pend.Restore(tok, p, p.expires) }

func (s *svc) PreviewImport(ctx context.Context, r *v1.PreviewImportRequest) (*v1.PreviewImportResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(r.Path)
	if err != nil {
		return nil, err
	}
	b, err := service.ReadImport(path, dom.MaxImportBytes)
	if err != nil {
		return nil, err
	}
	incoming, avisos, err := dom.ParseAvisos(b)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	user, err := loadUser(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	tok, exp := s.stash(pending{kind: pendScripts, scripts: incoming, path: path})
	out := &v1.PreviewImportResponse{Token: tok, ExpiresMs: ms(exp), Warnings: avisosIn(i18n.Locale(ctx), avisos)}
	for _, it := range dom.Plan(incoming, user, lib) {
		out.Items = append(out.Items, &v1.ImportItem{Script: toPB(s.in(ctx, it.Script), meta{}), State: it.Estado, ConflictsWith: it.Con})
	}
	return out, nil
}

func (s *svc) ApplyImport(ctx context.Context, r *v1.ApplyImportRequest) (*v1.ApplyImportResponse, error) {
	s.d.MarkActive()
	now := s.clock()
	p, err := s.take(ctx, r.Token, pendScripts)
	if err != nil {
		return nil, err
	}
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	dec := map[string]string{}
	invalid := false
	// Una decisión mala (repetida, faltante, conflicto con otra) devuelve el token para corregirla; un fallo
	// de la base de datos no.
	err = func() error {
		for _, d := range r.Decisions {
			if _, dup := dec[d.ScriptId]; dup {
				invalid = true
				return service.Err(ctx, codes.InvalidArgument, "scripts.svc.decision_dup", i18n.A("id", d.ScriptId))
			}
			dec[d.ScriptId] = d.Action
		}
		return nil
	}()
	var res dom.Resultado
	if err == nil {
		err = s.tx(func(tx *sql.Tx) error {
			// Se vuelve a comparar contra lo guardado ahora: entre la vista previa y aquí pudo cambiar.
			user, err := loadUser(tx)
			if err != nil {
				return internal(err)
			}
			if res, err = dom.Apply(dom.Plan(p.scripts, user, lib), dec, user, lib, now.UTC().Truncate(time.Second)); err != nil {
				invalid = true
				return service.ErrFrom(ctx, codes.InvalidArgument, err)
			}
			for _, x := range res.Writes {
				if err := put(tx, x); err != nil {
					return internal(err)
				}
			}
			return nil
		})
	}
	if err != nil {
		if invalid {
			s.restore(r.Token, p)
		}
		return nil, err
	}
	s.d.Audit("scripts.importar", p.path, fmt.Sprintf("%d new, %d replaced, %d renamed, %d skipped; decisions: %s",
		res.Created, res.Replaced, res.Renamed, res.Skipped, resumen(dec)))
	return &v1.ApplyImportResponse{Created: int32(res.Created), Replaced: int32(res.Replaced), Renamed: int32(res.Renamed), Skipped: int32(res.Skipped)}, nil
}

// resumen lista las decisiones para la auditoría, con tope para que un archivo grande no infle la entrada.
func resumen(dec map[string]string) string {
	if len(dec) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(dec))
	for id := range dec {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var parts []string
	for i, id := range ids {
		if i == 20 {
			parts = append(parts, fmt.Sprintf("… and %d more", len(ids)-i))
			break
		}
		parts = append(parts, id+"="+service.DecisionEN(dec[id]))
	}
	return strings.Join(parts, ", ")
}
