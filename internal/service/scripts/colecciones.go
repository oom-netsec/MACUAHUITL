package scripts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	dom "github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// Colecciones y fijados de la bóveda de scripts (fase 29c). Las colecciones guardan IDs, nunca copias.

func (s *svc) libSet() (map[string]bool, error) {
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(lib))
	for _, x := range lib {
		out[x.ID] = true
	}
	return out, nil
}

// cleanCol quita de la colección los «lib-*» que esta biblioteca ya no trae (por ejemplo, tras actualizar la app).
func cleanCol(c dom.Coleccion, lib map[string]bool) dom.Coleccion {
	c.ScriptIDs = slices.DeleteFunc(slices.Clone(c.ScriptIDs), func(id string) bool { return dom.IsLib(id) && !lib[id] })
	return c
}

func colPB(c dom.Coleccion) *v1.Collection {
	return &v1.Collection{Id: c.ID, Name: c.Name, Description: c.Description, Order: int32(c.Order), ScriptIds: nonNil(c.ScriptIDs),
		CreatedMs: ms(c.CreatedAt), UpdatedMs: ms(c.UpdatedAt)}
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// isPerm dice si want trae exactamente los elementos de have, cada uno una vez.
func isPerm(have, want []string) bool {
	if len(have) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range want {
		if seen[id] || !slices.Contains(have, id) {
			return false
		}
		seen[id] = true
	}
	return true
}

// corta junta IDs para la auditoría, con tope para que una lista grande no infle la entrada.
func corta(ids []string) string {
	if len(ids) > 20 {
		return strings.Join(ids[:20], ",") + fmt.Sprintf(",… and %d more", len(ids)-20)
	}
	return strings.Join(ids, ",")
}

func (s *svc) ListCollections(_ context.Context, _ *v1.ListCollectionsRequest) (*v1.ListCollectionsResponse, error) {
	s.d.MarkActive()
	lib, err := s.libSet()
	if err != nil {
		return nil, err
	}
	cols, err := loadCollections(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	out := &v1.ListCollectionsResponse{}
	for _, c := range cols {
		out.Collections = append(out.Collections, colPB(cleanCol(c, lib)))
	}
	return out, nil
}

func (s *svc) GetCollection(_ context.Context, r *v1.GetCollectionRequest) (*v1.GetCollectionResponse, error) {
	s.d.MarkActive()
	lib, err := s.libSet()
	if err != nil {
		return nil, err
	}
	c, err := getCollection(s.d.DB(), r.Id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Errorf(codes.NotFound, "no hay una colección %q", r.Id)
	}
	if err != nil {
		return nil, internal(err)
	}
	return &v1.GetCollectionResponse{Collection: colPB(cleanCol(c, lib))}, nil
}

// colNameTaken dice si otra colección (no exceptID) ya usa name, sin importar mayúsculas.
func colNameTaken(cols []dom.Coleccion, name, exceptID string) bool {
	for _, c := range cols {
		if c.ID != exceptID && dom.NameKey(c.Name) == dom.NameKey(name) {
			return true
		}
	}
	return false
}

func (s *svc) SaveCollection(_ context.Context, r *v1.SaveCollectionRequest) (*v1.SaveCollectionResponse, error) {
	s.d.MarkActive()
	if r.Collection == nil {
		return nil, status.Error(codes.InvalidArgument, "falta la colección")
	}
	in := r.Collection
	now := s.clock().UTC().Truncate(time.Second)
	action := "scripts.coleccion.crear"
	var out dom.Coleccion
	err := s.tx(func(tx *sql.Tx) error {
		cols, err := loadCollections(tx)
		if err != nil {
			return internal(err)
		}
		c := dom.Coleccion{ID: dom.NewID(), CreatedAt: now, ScriptIDs: []string{}}
		if in.Id == "" {
			if len(cols) >= dom.MaxColecciones {
				return status.Errorf(codes.FailedPrecondition, "ya hay %d colecciones, el tope", dom.MaxColecciones)
			}
		} else {
			i := slices.IndexFunc(cols, func(x dom.Coleccion) bool { return x.ID == in.Id })
			if i < 0 {
				return status.Errorf(codes.NotFound, "no hay una colección %q", in.Id)
			}
			c, action = cols[i], "scripts.coleccion.editar"
		}
		c.Name, c.Description, c.UpdatedAt = strings.TrimSpace(in.Name), in.Description, now
		if err := c.Validate(); err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if colNameTaken(cols, c.Name, c.ID) {
			return status.Errorf(codes.AlreadyExists, "ya hay una colección llamada %q", c.Name)
		}
		if err := putCollection(tx, c); err != nil {
			return internal(err)
		}
		if out, err = getCollection(tx, c.ID); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit(action, out.ID, out.Name)
	return &v1.SaveCollectionResponse{Collection: colPB(out)}, nil
}

func (s *svc) DeleteCollection(_ context.Context, r *v1.DeleteCollectionRequest) (*v1.DeleteCollectionResponse, error) {
	s.d.MarkActive()
	if r.Id == dom.FavoritosID {
		return nil, status.Errorf(codes.FailedPrecondition, "la colección %s no se borra", dom.FavoritosID)
	}
	var name string
	err := s.tx(func(tx *sql.Tx) error {
		c, err := getCollection(tx, r.Id)
		if errors.Is(err, sql.ErrNoRows) {
			return status.Errorf(codes.NotFound, "no hay una colección %q", r.Id)
		}
		if err != nil {
			return internal(err)
		}
		name = c.Name
		// Los scripts no se tocan: la colección solo los referencia.
		if _, err := tx.Exec(`DELETE FROM script_collection_items WHERE collection_id = ?`, r.Id); err != nil {
			return internal(err)
		}
		if _, err := tx.Exec(`DELETE FROM script_collections WHERE id = ?`, r.Id); err != nil {
			return internal(err)
		}
		// Orden contiguo desde 0, como dice el proto.
		if _, err := tx.Exec(`UPDATE script_collections SET position = (SELECT count(*) FROM script_collections o WHERE o.position < script_collections.position OR (o.position = script_collections.position AND o.id < script_collections.id))`); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.coleccion.borrar", r.Id, name)
	return &v1.DeleteCollectionResponse{}, nil
}

func (s *svc) ReorderCollections(_ context.Context, r *v1.ReorderCollectionsRequest) (*v1.ReorderCollectionsResponse, error) {
	s.d.MarkActive()
	err := s.tx(func(tx *sql.Tx) error {
		cols, err := loadCollections(tx)
		if err != nil {
			return internal(err)
		}
		have := make([]string, len(cols))
		for i, c := range cols {
			have[i] = c.ID
		}
		if !isPerm(have, r.Ids) {
			return status.Error(codes.InvalidArgument, "el orden debe traer cada colección existente (también favoritos) una sola vez")
		}
		for i, id := range r.Ids {
			if _, err := tx.Exec(`UPDATE script_collections SET position = ? WHERE id = ?`, i, id); err != nil {
				return internal(err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.coleccion.reordenar", "colecciones", corta(r.Ids))
	return &v1.ReorderCollectionsResponse{}, nil
}

func (s *svc) SetCollectionScripts(_ context.Context, r *v1.SetCollectionScriptsRequest) (*v1.SetCollectionScriptsResponse, error) {
	s.d.MarkActive()
	if len(r.ScriptIds) > dom.MaxScriptsColeccion {
		return nil, status.Errorf(codes.InvalidArgument, "una colección lleva hasta %d scripts", dom.MaxScriptsColeccion)
	}
	var c dom.Coleccion
	var added, removed []string
	err := s.tx(func(tx *sql.Tx) error {
		old, err := getCollection(tx, r.Id)
		if errors.Is(err, sql.ErrNoRows) {
			return status.Errorf(codes.NotFound, "no hay una colección %q", r.Id)
		}
		if err != nil {
			return internal(err)
		}
		seen := map[string]bool{}
		for _, id := range r.ScriptIds {
			if seen[id] {
				return status.Errorf(codes.InvalidArgument, "el script %s está repetido", id)
			}
			seen[id] = true
			if _, err := s.find(tx, id); err != nil {
				return err
			}
		}
		for _, id := range r.ScriptIds {
			if !slices.Contains(old.ScriptIDs, id) {
				added = append(added, id)
			}
		}
		for _, id := range old.ScriptIDs {
			if !seen[id] {
				removed = append(removed, id)
			}
		}
		c = old
		c.ScriptIDs, c.UpdatedAt = slices.Clone(r.ScriptIds), s.clock().UTC().Truncate(time.Second)
		if err := putCollection(tx, c); err != nil {
			return internal(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.coleccion.scripts", c.ID, fmt.Sprintf("%s: added [%s], removed [%s], %d in total", c.Name, corta(added), corta(removed), len(c.ScriptIDs)))
	return &v1.SetCollectionScriptsResponse{Collection: colPB(c)}, nil
}

// prunePins quita de los fijados los «lib-*» que esta biblioteca ya no trae: no se ven, pero contarían para el tope
// y harían fallar el reorden.
func (s *svc) prunePins(tx *sql.Tx) error {
	lib, err := s.libSet()
	if err != nil {
		return err
	}
	pins, err := loadPins(tx)
	if err != nil {
		return internal(err)
	}
	for _, id := range pins {
		if dom.IsLib(id) && !lib[id] {
			if _, err := tx.Exec(`DELETE FROM script_pins WHERE script_id = ?`, id); err != nil {
				return internal(err)
			}
		}
	}
	return nil
}

func (s *svc) SetPinned(_ context.Context, r *v1.SetPinnedRequest) (*v1.SetPinnedResponse, error) {
	s.d.MarkActive()
	changed := false
	err := s.tx(func(tx *sql.Tx) error {
		if err := s.prunePins(tx); err != nil {
			return err
		}
		if r.Pinned { // desfijar no exige que el script exista
			if _, err := s.find(tx, r.Id); err != nil {
				return err
			}
		}
		pins, err := loadPins(tx)
		if err != nil {
			return internal(err)
		}
		had := slices.Contains(pins, r.Id)
		switch {
		case had == r.Pinned:
			return nil
		case r.Pinned && len(pins) >= dom.MaxFijados:
			return status.Errorf(codes.FailedPrecondition, "ya hay %d scripts fijados, el máximo; desfija uno antes", dom.MaxFijados)
		case r.Pinned:
			_, err = tx.Exec(`INSERT INTO script_pins(script_id, position) VALUES(?, (SELECT COALESCE(MAX(position)+1, 0) FROM script_pins))`, r.Id)
		default:
			_, err = tx.Exec(`DELETE FROM script_pins WHERE script_id = ?`, r.Id)
		}
		if err != nil {
			return internal(err)
		}
		changed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.d.Audit("scripts.fijar", r.Id, map[bool]string{true: "pinned", false: "unpinned"}[r.Pinned])
	}
	return &v1.SetPinnedResponse{}, nil
}

func (s *svc) ListPinned(_ context.Context, _ *v1.ListPinnedRequest) (*v1.ListPinnedResponse, error) {
	s.d.MarkActive()
	m, err := loadMeta(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	pins, err := loadPins(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	out := &v1.ListPinnedResponse{}
	for _, id := range pins {
		x, err := s.find(s.d.DB(), id)
		if status.Code(err) == codes.NotFound { // un «lib-*» que esta biblioteca ya no trae
			continue
		}
		if err != nil {
			return nil, err
		}
		out.Scripts = append(out.Scripts, toPB(x, m))
	}
	return out, nil
}

func (s *svc) ReorderPinned(_ context.Context, r *v1.ReorderPinnedRequest) (*v1.ReorderPinnedResponse, error) {
	s.d.MarkActive()
	err := s.tx(func(tx *sql.Tx) error {
		if err := s.prunePins(tx); err != nil {
			return err
		}
		pins, err := loadPins(tx)
		if err != nil {
			return internal(err)
		}
		if !isPerm(pins, r.Ids) {
			return status.Error(codes.InvalidArgument, "el orden debe traer cada script fijado una sola vez")
		}
		for i, id := range r.Ids {
			if _, err := tx.Exec(`UPDATE script_pins SET position = ? WHERE script_id = ?`, i, id); err != nil {
				return internal(err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.d.Audit("scripts.fijados.reordenar", "fijados", corta(r.Ids))
	return &v1.ReorderPinnedResponse{}, nil
}

// ---- export / import ----

func (s *svc) ExportCollections(ctx context.Context, r *v1.ExportCollectionsRequest) (*v1.ExportCollectionsResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(r.Path)
	if err != nil {
		return nil, err
	}
	if len(r.Ids) < 1 || len(r.Ids) > dom.MaxColecciones {
		return nil, status.Errorf(codes.InvalidArgument, "se exportan de 1 a %d colecciones", dom.MaxColecciones)
	}
	lib, err := s.libSet()
	if err != nil {
		return nil, err
	}
	all, err := loadCollections(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	var sel []dom.Coleccion
	var scripts []dom.Script
	seenCol, seenScript := map[string]bool{}, map[string]bool{}
	for _, id := range r.Ids {
		if seenCol[id] {
			continue
		}
		seenCol[id] = true
		i := slices.IndexFunc(all, func(c dom.Coleccion) bool { return c.ID == id })
		if i < 0 {
			return nil, status.Errorf(codes.NotFound, "no hay una colección %q", id)
		}
		c := cleanCol(all[i], lib)
		c.Order = len(sel)
		sel = append(sel, c)
		for _, sid := range c.ScriptIDs { // los de biblioteca viajan solo por ID
			if dom.IsLib(sid) || seenScript[sid] {
				continue
			}
			seenScript[sid] = true
			x, err := getUser(s.d.DB(), sid)
			if err != nil {
				return nil, internal(err)
			}
			scripts = append(scripts, x)
		}
	}
	b, err := dom.MarshalColecciones(sel, scripts, s.clock())
	if err != nil {
		return nil, internal(err)
	}
	if len(b) > dom.MaxImportBytes {
		return nil, status.Error(codes.InvalidArgument, "el archivo pasaría de 5 MB y el import lo rechazaría; exporta menos colecciones")
	}
	if err := service.WriteExport(ctx, path, b, r.Overwrite); err != nil {
		return nil, err
	}
	s.d.Audit("scripts.coleccion.exportar", path, fmt.Sprintf("%d collections, %d scripts", len(sel), len(scripts)))
	return &v1.ExportCollectionsResponse{Collections: int32(len(sel)), Scripts: int32(len(scripts))}, nil
}

// libAvisos avisa de cada «lib-*» que las colecciones del archivo referencian y esta biblioteca no trae.
func libAvisos(cols []dom.Coleccion, lib map[string]bool) []string {
	var out []string
	for _, c := range cols {
		for _, id := range c.ScriptIDs {
			if dom.IsLib(id) && !lib[id] {
				out = append(out, fmt.Sprintf("colección %q: el script %s no está en la biblioteca local; se omitirá", c.Name, id))
			}
		}
	}
	return out
}

func (s *svc) PreviewImportCollections(_ context.Context, r *v1.PreviewImportCollectionsRequest) (*v1.PreviewImportCollectionsResponse, error) {
	s.d.MarkActive()
	path, err := service.AbsPath(r.Path)
	if err != nil {
		return nil, err
	}
	b, err := service.ReadImport(path, dom.MaxImportBytes)
	if err != nil {
		return nil, err
	}
	cols, scripts, avisos, err := dom.ParseColeccionesAvisos(b)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	user, err := loadUser(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	local, err := loadCollections(s.d.DB())
	if err != nil {
		return nil, internal(err)
	}
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	libIDs, err := s.libSet()
	if err != nil {
		return nil, err
	}
	tok, exp := s.stash(pending{kind: pendCols, scripts: scripts, cols: cols, path: path})
	out := &v1.PreviewImportCollectionsResponse{Token: tok, ExpiresMs: ms(exp), Warnings: append(avisos, libAvisos(cols, libIDs)...)}
	for _, it := range dom.PlanColecciones(cols, local) {
		out.Collections = append(out.Collections, &v1.CollectionImportItem{Collection: colPB(it.Col), State: it.Estado, ConflictsWith: it.Con})
	}
	for _, it := range dom.Plan(scripts, user, lib) {
		out.Scripts = append(out.Scripts, &v1.ImportItem{Script: toPB(it.Script, meta{}), State: it.Estado, ConflictsWith: it.Con})
	}
	return out, nil
}

func decisionMap(ds []*v1.ImportDecision, que string) (map[string]string, error) {
	out := map[string]string{}
	for _, d := range ds {
		if _, dup := out[d.ScriptId]; dup {
			return nil, status.Errorf(codes.InvalidArgument, "decisión repetida para %s (%s)", d.ScriptId, que)
		}
		out[d.ScriptId] = d.Action
	}
	return out, nil
}

func (s *svc) ApplyImportCollections(_ context.Context, r *v1.ApplyImportCollectionsRequest) (*v1.ApplyImportCollectionsResponse, error) {
	s.d.MarkActive()
	now := s.clock()
	p, err := s.take(r.Token, pendCols)
	if err != nil {
		return nil, err
	}
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	libIDs, err := s.libSet()
	if err != nil {
		return nil, err
	}
	// Una decisión mala (repetida, faltante, que choca con otra) devuelve el token para corregirla; un fallo de la
	// base de datos no.
	invalid := false
	var sres dom.Resultado
	var cres dom.ResultadoCol
	var sdec, cdec map[string]string
	if sdec, err = decisionMap(r.ScriptDecisions, "script"); err == nil {
		cdec, err = decisionMap(r.CollectionDecisions, "colección")
	}
	if err != nil {
		invalid = true
	} else {
		err = s.tx(func(tx *sql.Tx) error {
			// Se vuelve a comparar contra lo guardado ahora: entre la vista previa y aquí pudo cambiar.
			user, err := loadUser(tx)
			if err != nil {
				return internal(err)
			}
			local, err := loadCollections(tx)
			if err != nil {
				return internal(err)
			}
			ahora := now.UTC().Truncate(time.Second)
			if sres, err = dom.Apply(dom.Plan(p.scripts, user, lib), sdec, user, lib, ahora); err != nil {
				invalid = true
				return status.Error(codes.InvalidArgument, err.Error())
			}
			if cres, err = dom.ApplyColecciones(dom.PlanColecciones(p.cols, local), cdec, local, sres.IDs, libIDs, ahora); err != nil {
				invalid = true
				return status.Error(codes.InvalidArgument, err.Error())
			}
			total := len(local)
			for _, w := range cres.Writes {
				if !slices.ContainsFunc(local, func(c dom.Coleccion) bool { return c.ID == w.ID }) {
					total++
				}
			}
			if total > dom.MaxColecciones {
				invalid = true
				return status.Errorf(codes.InvalidArgument, "quedarían %d colecciones; el tope es %d", total, dom.MaxColecciones)
			}
			for _, x := range sres.Writes {
				if err := put(tx, x); err != nil {
					return internal(err)
				}
			}
			for _, w := range cres.Writes {
				if err := putCollection(tx, w); err != nil {
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
	s.d.Audit("scripts.coleccion.importar", p.path, fmt.Sprintf("collections: %d new, %d replaced, %d renamed, %d merged, %d skipped; scripts: %d new, %d replaced, %d renamed, %d skipped; collection decisions: %s; script decisions: %s",
		cres.Created, cres.Replaced, cres.Renamed, cres.Merged, cres.Skipped, sres.Created, sres.Replaced, sres.Renamed, sres.Skipped, resumen(cdec), resumen(sdec)))
	return &v1.ApplyImportCollectionsResponse{
		ScriptsCreated: int32(sres.Created), ScriptsReplaced: int32(sres.Replaced), ScriptsRenamed: int32(sres.Renamed), ScriptsSkipped: int32(sres.Skipped),
		CollectionsCreated: int32(cres.Created), CollectionsReplaced: int32(cres.Replaced), CollectionsRenamed: int32(cres.Renamed),
		CollectionsMerged: int32(cres.Merged), CollectionsSkipped: int32(cres.Skipped), Warnings: cres.Warnings,
	}, nil
}

func checkKind(kind string) error {
	if kind != dom.KindScripts && kind != dom.KindColecciones {
		return status.Errorf(codes.InvalidArgument, "tipo %q desconocido: %s o %s", kind, dom.KindScripts, dom.KindColecciones)
	}
	return nil
}

func (s *svc) ImportTemplate(_ context.Context, r *v1.ImportTemplateRequest) (*v1.ImportTemplateResponse, error) {
	s.d.MarkActive()
	if err := checkKind(r.Kind); err != nil {
		return nil, err
	}
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	b, err := dom.Plantilla(r.Kind, lib, s.clock())
	if err != nil {
		return nil, internal(err)
	}
	return &v1.ImportTemplateResponse{Json: string(b)}, nil
}

func (s *svc) ImportFormat(_ context.Context, r *v1.ImportFormatRequest) (*v1.ImportFormatResponse, error) {
	s.d.MarkActive()
	if err := checkKind(r.Kind); err != nil {
		return nil, err
	}
	lib, err := s.library()
	if err != nil {
		return nil, err
	}
	cs, err := dom.Campos(r.Kind, lib, s.clock())
	if err != nil {
		return nil, internal(err)
	}
	out := &v1.ImportFormatResponse{}
	for _, c := range cs {
		out.Fields = append(out.Fields, &v1.FormatField{Name: c.Nombre, Type: c.Tipo, Required: c.Obligatorio, Example: c.Ejemplo, Description: c.Descripcion})
	}
	return out, nil
}
