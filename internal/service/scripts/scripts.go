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
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
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
	libMu  sync.Once
	lib    []dom.Script
	libErr error
	pend   service.Pending[pending]
}

// Module registra el servicio de scripts.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterScriptsServiceServer(s, &svc{d: d})
}

func (s *svc) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return s.d.Now()
}

func (s *svc) library() ([]dom.Script, error) {
	s.libMu.Do(func() { s.lib, s.libErr = dom.Library(playbooks.FS) })
	if s.libErr != nil {
		return nil, status.Error(codes.Internal, s.libErr.Error())
	}
	return s.lib, nil
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
func (s *svc) find(q querier, id string) (dom.Script, error) {
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
		return dom.Script{}, status.Errorf(codes.NotFound, "no hay un script %q", id)
	}
	x, err := getUser(q, id)
	if errors.Is(err, sql.ErrNoRows) {
		return x, status.Errorf(codes.NotFound, "no hay un script %q", id)
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
func (s *svc) nameTaken(all []dom.Script, name, exceptID string) (bool, error) {
	lib, err := s.library()
	if err != nil {
		return false, err
	}
	for _, x := range append(append([]dom.Script{}, lib...), all...) {
		if dom.NameKey(x.Name) == dom.NameKey(name) && x.ID != exceptID {
			return true, nil
		}
	}
	return false, nil
}

func (s *svc) ListScripts(_ context.Context, r *v1.ListScriptsRequest) (*v1.ListScriptsResponse, error) {
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
			all = append(all, x)
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

func (s *svc) GetScript(_ context.Context, r *v1.GetScriptRequest) (*v1.GetScriptResponse, error) {
	s.d.MarkActive()
	x, err := s.find(s.d.DB(), r.Id)
	if err != nil {
		return nil, err
	}
	m, err := loadMeta(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	return &v1.GetScriptResponse{Script: toPB(x, m)}, nil
}

func (s *svc) SaveScript(_ context.Context, r *v1.SaveScriptRequest) (*v1.SaveScriptResponse, error) {
	s.d.MarkActive()
	if r.Script == nil {
		return nil, status.Error(codes.InvalidArgument, "falta el script")
	}
	x := fromPB(r.Script)
	if dom.IsLib(x.ID) {
		return nil, status.Error(codes.InvalidArgument, "los scripts de la biblioteca no se editan; duplícalo para tener una copia propia")
	}
	now := s.clock().UTC().Truncate(time.Second)
	x.CreatedAt, x.UpdatedAt = now, now
	action := "scripts.crear"
	err := s.tx(func(tx *sql.Tx) error {
		if x.ID == "" {
			x.ID = dom.NewID()
		} else {
			old, err := s.find(tx, x.ID)
			if err != nil {
				return err
			}
			x.CreatedAt, action = old.CreatedAt, "scripts.editar"
		}
		if err := x.Validate(); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		user, err := loadUser(tx)
		if err != nil {
			return internal(err)
		}
		taken, err := s.nameTaken(user, x.Name, x.ID)
		if err != nil {
			return err
		}
		if taken {
			return status.Errorf(codes.AlreadyExists, "ya hay un script llamado %q (los nombres de la biblioteca también cuentan)", x.Name)
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
	return &v1.SaveScriptResponse{Script: toPB(x, m)}, nil
}

func (s *svc) DeleteScript(_ context.Context, r *v1.DeleteScriptRequest) (*v1.DeleteScriptResponse, error) {
	s.d.MarkActive()
	if dom.IsLib(r.Id) {
		return nil, status.Error(codes.InvalidArgument, "los scripts de la biblioteca no se borran")
	}
	var name string
	err := s.tx(func(tx *sql.Tx) error {
		x, err := s.find(tx, r.Id)
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

func (s *svc) SetFavorite(_ context.Context, r *v1.SetFavoriteRequest) (*v1.SetFavoriteResponse, error) {
	s.d.MarkActive()
	err := s.tx(func(tx *sql.Tx) error {
		if _, err := s.find(tx, r.Id); err != nil {
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
				return status.Errorf(codes.FailedPrecondition, "favoritos ya lleva %d scripts, el máximo; quita alguno antes", dom.MaxScriptsColeccion)
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
	s.d.Audit("scripts.favorito", r.Id, map[bool]string{true: "marcado", false: "desmarcado"}[r.Favorite])
	return &v1.SetFavoriteResponse{}, nil
}

func (s *svc) DuplicateScript(_ context.Context, r *v1.DuplicateScriptRequest) (*v1.DuplicateScriptResponse, error) {
	s.d.MarkActive()
	var c dom.Script
	err := s.tx(func(tx *sql.Tx) error {
		x, err := s.find(tx, r.Id)
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
		c.Name = dom.NombreLibre(x.Name, "copia", func(n string) bool { t, _ := s.nameTaken(user, n, ""); return t })
		if err := put(tx, c); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.crear", c.ID, c.Name+" (copia de "+r.Id+")")
	return &v1.DuplicateScriptResponse{Script: toPB(c, meta{})}, nil
}

func (s *svc) ExportScripts(_ context.Context, r *v1.ExportScriptsRequest) (*v1.ExportScriptsResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(r.Path)
	if err != nil {
		return nil, err
	}
	if len(r.Ids) < 1 || len(r.Ids) > dom.MaxImportScripts {
		return nil, status.Errorf(codes.InvalidArgument, "se exportan de 1 a %d scripts", dom.MaxImportScripts)
	}
	var sel []dom.Script
	seen := map[string]bool{}
	for _, id := range r.Ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		x, err := s.find(s.d.DB(), id)
		if err != nil {
			return nil, err
		}
		sel = append(sel, x)
	}
	names := map[string]bool{}
	for _, x := range sel {
		if k := dom.NameKey(x.Name); names[k] {
			return nil, status.Errorf(codes.InvalidArgument, "dos scripts seleccionados se llaman %q: el archivo no se podría importar", x.Name)
		} else {
			names[k] = true
		}
	}
	b, err := dom.Marshal(sel, s.clock())
	if err != nil {
		return nil, internal(err)
	}
	if len(b) > dom.MaxImportBytes {
		return nil, status.Error(codes.InvalidArgument, "el archivo pasaría de 5 MB y el import lo rechazaría; exporta menos scripts")
	}
	if err := service.WriteExport(path, b, r.Overwrite); err != nil {
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
func (s *svc) take(tok, kind string) (pending, error) {
	p, exp, ok := s.pend.Take(tok)
	if !ok {
		return p, status.Error(codes.NotFound, "token de importación desconocido; abre el archivo de nuevo")
	}
	if p.kind != kind {
		s.pend.Restore(tok, p, exp)
		return p, status.Errorf(codes.FailedPrecondition, "el token es de una vista previa de %s; usa el otro paso de importación", p.kind)
	}
	if s.clock().After(exp) {
		return p, status.Error(codes.FailedPrecondition, "la vista previa venció; vuelve a abrir el archivo")
	}
	return p, nil
}

// restore devuelve un token cuya aplicación falló por una decisión mala, para que se pueda corregir.
func (s *svc) restore(tok string, p pending) { s.pend.Restore(tok, p, p.expires) }

func (s *svc) PreviewImport(_ context.Context, r *v1.PreviewImportRequest) (*v1.PreviewImportResponse, error) {
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
		return nil, status.Error(codes.InvalidArgument, err.Error())
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
	out := &v1.PreviewImportResponse{Token: tok, ExpiresMs: ms(exp), Warnings: avisos}
	for _, it := range dom.Plan(incoming, user, lib) {
		out.Items = append(out.Items, &v1.ImportItem{Script: toPB(it.Script, meta{}), State: it.Estado, ConflictsWith: it.Con})
	}
	return out, nil
}

func (s *svc) ApplyImport(_ context.Context, r *v1.ApplyImportRequest) (*v1.ApplyImportResponse, error) {
	s.d.MarkActive()
	now := s.clock()
	p, err := s.take(r.Token, pendScripts)
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
				return status.Errorf(codes.InvalidArgument, "decisión repetida para %s", d.ScriptId)
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
				return status.Error(codes.InvalidArgument, err.Error())
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
	s.d.Audit("scripts.importar", p.path, fmt.Sprintf("%d nuevos, %d reemplazados, %d renombrados, %d omitidos; decisiones: %s",
		res.Created, res.Replaced, res.Renamed, res.Skipped, resumen(dec)))
	return &v1.ApplyImportResponse{Created: int32(res.Created), Replaced: int32(res.Replaced), Renamed: int32(res.Renamed), Skipped: int32(res.Skipped)}, nil
}

// resumen lista las decisiones para la auditoría, con tope para que un archivo grande no infle la entrada.
func resumen(dec map[string]string) string {
	if len(dec) == 0 {
		return "ninguna"
	}
	ids := make([]string, 0, len(dec))
	for id := range dec {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var parts []string
	for i, id := range ids {
		if i == 20 {
			parts = append(parts, fmt.Sprintf("… y %d más", len(ids)-i))
			break
		}
		parts = append(parts, id+"="+dec[id])
	}
	return strings.Join(parts, ", ")
}
