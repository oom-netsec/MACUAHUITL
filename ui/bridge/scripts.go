package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Bóveda de scripts (fase 28c): los del usuario, la biblioteca, favoritos y export/import ----
// Las listas siempre son arreglos (nunca null). Ningún método aplica un script a un equipo (ADR 0007).

type ScriptDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tech        string   `json:"tech"`
	Platform    string   `json:"platform"`
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
	Tags        []string `json:"tags"`
	Origin      string   `json:"origin"` // biblioteca | usuario
	CreatedMs   int64    `json:"createdMs"`
	UpdatedMs   int64    `json:"updatedMs"`
	ReadOnly    bool     `json:"readOnly"`    // Patrol puede correrlo
	Favorite    bool     `json:"favorite"`    // está en la colección «favoritos»
	Pinned      bool     `json:"pinned"`      // fijado para la barra corta de la terminal
	Collections []string `json:"collections"` // IDs de las colecciones que lo contienen
}

type ScriptFilterDTO struct {
	Tech          string `json:"tech"`
	Platform      string `json:"platform"`
	Tag           string `json:"tag"`
	Text          string `json:"text"`
	OnlyFavorites bool   `json:"onlyFavorites"`
}

type ImportItemDTO struct {
	Script        ScriptDTO `json:"script"`
	State         string    `json:"state"`         // nuevo | igual | conflicto_id | conflicto_nombre
	ConflictsWith string    `json:"conflictsWith"` // ID guardado con el que choca; vacío si es nuevo
}

type ImportPreviewDTO struct {
	Token     string          `json:"token"`
	ExpiresMs int64           `json:"expiresMs"`
	Items     []ImportItemDTO `json:"items"`
	Warnings  []string        `json:"warnings"` // por ejemplo «archivo sin suma de verificación»
}

type ImportDecisionDTO struct {
	ScriptID string `json:"scriptId"`
	Action   string `json:"action"` // renombrar | reemplazar | omitir
}

type ImportResultDTO struct {
	Created  int `json:"created"`
	Replaced int `json:"replaced"`
	Renamed  int `json:"renamed"`
	Skipped  int `json:"skipped"`
}

func scriptDTO(s *v1.Script) ScriptDTO {
	return ScriptDTO{ID: s.GetId(), Name: s.GetName(), Tech: s.GetTech(), Platform: s.GetPlatform(), Description: s.GetDescription(),
		Commands: strs(s.GetCommands()), Tags: strs(s.GetTags()), Origin: s.GetOrigin(), CreatedMs: s.GetCreatedMs(), UpdatedMs: s.GetUpdatedMs(),
		ReadOnly: s.GetReadOnly(), Favorite: s.GetFavorite(), Pinned: s.GetPinned(), Collections: strs(s.GetCollections())}
}

func scriptsClient(c *ipc.ClientConn) v1.ScriptsServiceClient { return v1.NewScriptsServiceClient(c) }

// ListScripts devuelve la biblioteca y los scripts del usuario que cumplen el filtro, por nombre.
func (b *Bridge) ListScripts(f ScriptFilterDTO) ([]ScriptDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]ScriptDTO, error) {
		r, err := scriptsClient(c).ListScripts(ctx, &v1.ListScriptsRequest{Tech: f.Tech, Platform: f.Platform, Tag: f.Tag, Text: f.Text, OnlyFavorites: f.OnlyFavorites})
		out := []ScriptDTO{}
		for _, s := range r.GetScripts() {
			out = append(out, scriptDTO(s))
		}
		return out, err
	})
}

func (b *Bridge) GetScript(id string) (ScriptDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ScriptDTO, error) {
		r, err := scriptsClient(c).GetScript(ctx, &v1.GetScriptRequest{Id: id})
		return scriptDTO(r.GetScript()), err
	})
}

// SaveScript crea (id vacío) o edita un script del usuario; rechaza los «lib-*».
func (b *Bridge) SaveScript(s ScriptDTO) (ScriptDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ScriptDTO, error) {
		r, err := scriptsClient(c).SaveScript(ctx, &v1.SaveScriptRequest{Script: &v1.Script{Id: s.ID, Name: s.Name, Tech: s.Tech, Platform: s.Platform,
			Description: s.Description, Commands: s.Commands, Tags: s.Tags}})
		return scriptDTO(r.GetScript()), err
	})
}

func (b *Bridge) DeleteScript(id string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := scriptsClient(c).DeleteScript(ctx, &v1.DeleteScriptRequest{Id: id})
		return struct{}{}, err
	})
	return err
}

func (b *Bridge) SetScriptFavorite(id string, favorite bool) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := scriptsClient(c).SetFavorite(ctx, &v1.SetFavoriteRequest{Id: id, Favorite: favorite})
		return struct{}{}, err
	})
	return err
}

// DuplicateScript copia un script (también de la biblioteca) como script del usuario.
func (b *Bridge) DuplicateScript(id string) (ScriptDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ScriptDTO, error) {
		r, err := scriptsClient(c).DuplicateScript(ctx, &v1.DuplicateScriptRequest{Id: id})
		return scriptDTO(r.GetScript()), err
	})
}

// CopyFromPack copia un script de un paquete instalado (también oculto) a «Mis scripts»: ID nuevo, editable, nombre «<nombre> (copia)».
func (b *Bridge) CopyFromPack(id string) (ScriptDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ScriptDTO, error) {
		r, err := scriptsClient(c).CopyFromPack(ctx, &v1.CopyFromPackRequest{Id: id})
		return scriptDTO(r.GetScript()), err
	})
}

// ExportScripts escribe los scripts elegidos en path (absoluta; el núcleo la crea 0600 y no sobrescribe sin overwrite).
// Devuelve cuántos exportó.
func (b *Bridge) ExportScripts(ids []string, path string, overwrite bool) (int, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (int, error) {
		r, err := scriptsClient(c).ExportScripts(ctx, &v1.ExportScriptsRequest{Ids: ids, Path: path, Overwrite: overwrite})
		return int(r.GetCount()), err
	})
}

// PreviewScriptsImport valida el archivo y da el estado de cada script; no escribe nada.
func (b *Bridge) PreviewScriptsImport(path string) (ImportPreviewDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ImportPreviewDTO, error) {
		r, err := scriptsClient(c).PreviewImport(ctx, &v1.PreviewImportRequest{Path: path})
		out := ImportPreviewDTO{Token: r.GetToken(), ExpiresMs: r.GetExpiresMs(), Items: []ImportItemDTO{}, Warnings: strs(r.GetWarnings())}
		for _, it := range r.GetItems() {
			out.Items = append(out.Items, ImportItemDTO{Script: scriptDTO(it.GetScript()), State: it.GetState(), ConflictsWith: it.GetConflictsWith()})
		}
		return out, err
	})
}

// ApplyScriptsImport aplica la vista previa con las decisiones de cada conflicto.
func (b *Bridge) ApplyScriptsImport(token string, decisions []ImportDecisionDTO) (ImportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ImportResultDTO, error) {
		ds := []*v1.ImportDecision{}
		for _, d := range decisions {
			ds = append(ds, &v1.ImportDecision{ScriptId: d.ScriptID, Action: d.Action})
		}
		r, err := scriptsClient(c).ApplyImport(ctx, &v1.ApplyImportRequest{Token: token, Decisions: ds})
		return ImportResultDTO{Created: int(r.GetCreated()), Replaced: int(r.GetReplaced()), Renamed: int(r.GetRenamed()), Skipped: int(r.GetSkipped())}, err
	})
}

// ---- Colecciones y fijados (fase 29c) ----

type CollectionDTO struct {
	ID              string   `json:"id"` // 32 hex, o «favoritos» (no se borra ni se renombra)
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Order           int      `json:"order"` // desde 0, entre todas las colecciones
	ScriptIDs       []string `json:"scriptIds"`
	CreatedMs       int64    `json:"createdMs"`
	UpdatedMs       int64    `json:"updatedMs"`
	HiddenScriptIDs []string `json:"hiddenScriptIds"` // fase 32b: subconjunto de scriptIds que un paquete tiene oculto; siguen en scriptIds
}

type CollectionImportItemDTO struct {
	Collection    CollectionDTO `json:"collection"`
	State         string        `json:"state"`         // nueva | igual | fusionar | conflicto_id | conflicto_nombre
	ConflictsWith string        `json:"conflictsWith"` // ID local con el que choca o coincide; vacío si es nueva
}

type CollectionsImportPreviewDTO struct {
	Token       string                    `json:"token"`
	ExpiresMs   int64                     `json:"expiresMs"`
	Collections []CollectionImportItemDTO `json:"collections"`
	Scripts     []ImportItemDTO           `json:"scripts"`
	Warnings    []string                  `json:"warnings"`
}

type CollectionsImportResultDTO struct {
	ScriptsCreated      int      `json:"scriptsCreated"`
	ScriptsReplaced     int      `json:"scriptsReplaced"`
	ScriptsRenamed      int      `json:"scriptsRenamed"`
	ScriptsSkipped      int      `json:"scriptsSkipped"`
	CollectionsCreated  int      `json:"collectionsCreated"`
	CollectionsReplaced int      `json:"collectionsReplaced"`
	CollectionsRenamed  int      `json:"collectionsRenamed"`
	CollectionsMerged   int      `json:"collectionsMerged"`
	CollectionsSkipped  int      `json:"collectionsSkipped"`
	Warnings            []string `json:"warnings"`
}

type CollectionsExportResultDTO struct {
	Collections int `json:"collections"`
	Scripts     int `json:"scripts"` // scripts de usuario que viajan dentro del archivo
}

func collectionDTO(c *v1.Collection) CollectionDTO {
	return CollectionDTO{ID: c.GetId(), Name: c.GetName(), Description: c.GetDescription(), Order: int(c.GetOrder()), ScriptIDs: strs(c.GetScriptIds()),
		CreatedMs: c.GetCreatedMs(), UpdatedMs: c.GetUpdatedMs(), HiddenScriptIDs: strs(c.GetHiddenScriptIds())}
}

func importItemsDTO(items []*v1.ImportItem) []ImportItemDTO {
	out := []ImportItemDTO{}
	for _, it := range items {
		out = append(out, ImportItemDTO{Script: scriptDTO(it.GetScript()), State: it.GetState(), ConflictsWith: it.GetConflictsWith()})
	}
	return out
}

func decisionsPB(decisions []ImportDecisionDTO) []*v1.ImportDecision {
	ds := []*v1.ImportDecision{}
	for _, d := range decisions {
		ds = append(ds, &v1.ImportDecision{ScriptId: d.ScriptID, Action: d.Action})
	}
	return ds
}

// ListCollections devuelve todas las colecciones por orden; la primera vez solo existe «favoritos».
func (b *Bridge) ListCollections() ([]CollectionDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]CollectionDTO, error) {
		r, err := scriptsClient(c).ListCollections(ctx, &v1.ListCollectionsRequest{})
		out := []CollectionDTO{}
		for _, x := range r.GetCollections() {
			out = append(out, collectionDTO(x))
		}
		return out, err
	})
}

func (b *Bridge) GetCollection(id string) (CollectionDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CollectionDTO, error) {
		r, err := scriptsClient(c).GetCollection(ctx, &v1.GetCollectionRequest{Id: id})
		return collectionDTO(r.GetCollection()), err
	})
}

// SaveCollection crea (id vacío) o edita nombre y descripción; los scripts van por SetCollectionScripts.
func (b *Bridge) SaveCollection(id, name, description string) (CollectionDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CollectionDTO, error) {
		r, err := scriptsClient(c).SaveCollection(ctx, &v1.SaveCollectionRequest{Collection: &v1.Collection{Id: id, Name: name, Description: description}})
		return collectionDTO(r.GetCollection()), err
	})
}

func (b *Bridge) DeleteCollection(id string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := scriptsClient(c).DeleteCollection(ctx, &v1.DeleteCollectionRequest{Id: id})
		return struct{}{}, err
	})
	return err
}

// ReorderCollections recibe todas las colecciones (también «favoritos») una vez cada una.
func (b *Bridge) ReorderCollections(ids []string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := scriptsClient(c).ReorderCollections(ctx, &v1.ReorderCollectionsRequest{Ids: ids})
		return struct{}{}, err
	})
	return err
}

// SetCollectionScripts deja la colección con exactamente esos scripts y en ese orden.
func (b *Bridge) SetCollectionScripts(id string, scriptIDs []string) (CollectionDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CollectionDTO, error) {
		r, err := scriptsClient(c).SetCollectionScripts(ctx, &v1.SetCollectionScriptsRequest{Id: id, ScriptIds: scriptIDs})
		return collectionDTO(r.GetCollection()), err
	})
}

// SetScriptPinned fija o desfija un script (máximo 5; el sexto falla con el motivo).
func (b *Bridge) SetScriptPinned(id string, pinned bool) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := scriptsClient(c).SetPinned(ctx, &v1.SetPinnedRequest{Id: id, Pinned: pinned})
		return struct{}{}, err
	})
	return err
}

// ListPinnedScripts devuelve los fijados en su orden.
func (b *Bridge) ListPinnedScripts() ([]ScriptDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]ScriptDTO, error) {
		r, err := scriptsClient(c).ListPinned(ctx, &v1.ListPinnedRequest{})
		out := []ScriptDTO{}
		for _, s := range r.GetScripts() {
			out = append(out, scriptDTO(s))
		}
		return out, err
	})
}

func (b *Bridge) ReorderPinnedScripts(ids []string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := scriptsClient(c).ReorderPinned(ctx, &v1.ReorderPinnedRequest{Ids: ids})
		return struct{}{}, err
	})
	return err
}

// ExportCollections escribe las colecciones y los scripts de usuario que referencian en path (absoluta; 0600).
func (b *Bridge) ExportCollections(ids []string, path string, overwrite bool) (CollectionsExportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CollectionsExportResultDTO, error) {
		r, err := scriptsClient(c).ExportCollections(ctx, &v1.ExportCollectionsRequest{Ids: ids, Path: path, Overwrite: overwrite})
		return CollectionsExportResultDTO{Collections: int(r.GetCollections()), Scripts: int(r.GetScripts())}, err
	})
}

// PreviewCollectionsImport valida el archivo y da el estado de cada colección y de cada script; no escribe nada.
func (b *Bridge) PreviewCollectionsImport(path string) (CollectionsImportPreviewDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CollectionsImportPreviewDTO, error) {
		r, err := scriptsClient(c).PreviewImportCollections(ctx, &v1.PreviewImportCollectionsRequest{Path: path})
		out := CollectionsImportPreviewDTO{Token: r.GetToken(), ExpiresMs: r.GetExpiresMs(), Collections: []CollectionImportItemDTO{}, Scripts: importItemsDTO(r.GetScripts()), Warnings: strs(r.GetWarnings())}
		for _, it := range r.GetCollections() {
			out.Collections = append(out.Collections, CollectionImportItemDTO{Collection: collectionDTO(it.GetCollection()), State: it.GetState(), ConflictsWith: it.GetConflictsWith()})
		}
		return out, err
	})
}

// ApplyCollectionsImport aplica la vista previa: las decisiones de scripts y de colecciones van aparte (por ID del archivo).
func (b *Bridge) ApplyCollectionsImport(token string, scriptDecisions, collectionDecisions []ImportDecisionDTO) (CollectionsImportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CollectionsImportResultDTO, error) {
		r, err := scriptsClient(c).ApplyImportCollections(ctx, &v1.ApplyImportCollectionsRequest{Token: token, ScriptDecisions: decisionsPB(scriptDecisions), CollectionDecisions: decisionsPB(collectionDecisions)})
		return CollectionsImportResultDTO{ScriptsCreated: int(r.GetScriptsCreated()), ScriptsReplaced: int(r.GetScriptsReplaced()), ScriptsRenamed: int(r.GetScriptsRenamed()), ScriptsSkipped: int(r.GetScriptsSkipped()),
			CollectionsCreated: int(r.GetCollectionsCreated()), CollectionsReplaced: int(r.GetCollectionsReplaced()), CollectionsRenamed: int(r.GetCollectionsRenamed()),
			CollectionsMerged: int(r.GetCollectionsMerged()), CollectionsSkipped: int(r.GetCollectionsSkipped()), Warnings: strs(r.GetWarnings())}, err
	})
}

// FormatFieldDTO describe un campo de los archivos de import.
type FormatFieldDTO struct {
	Name        string `json:"name"` // «formato», «scripts[].name»
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Example     string `json:"example"` // JSON
	Description string `json:"description"`
}

// ImportTemplate devuelve el JSON de ejemplo de un archivo de import («scripts» o «colecciones»), sin sha256.
// Sale de las mismas reglas que validan el import, así que la vista previa lo acepta.
func (b *Bridge) ImportTemplate(kind string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := scriptsClient(c).ImportTemplate(ctx, &v1.ImportTemplateRequest{Kind: kind})
		return r.GetJson(), err
	})
}

// ImportFormat describe los campos del archivo de import (cabecera incluida).
func (b *Bridge) ImportFormat(kind string) ([]FormatFieldDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]FormatFieldDTO, error) {
		r, err := scriptsClient(c).ImportFormat(ctx, &v1.ImportFormatRequest{Kind: kind})
		out := []FormatFieldDTO{}
		for _, f := range r.GetFields() {
			out = append(out, FormatFieldDTO{Name: f.GetName(), Type: f.GetType(), Required: f.GetRequired(), Example: f.GetExample(), Description: f.GetDescription()})
		}
		return out, err
	})
}
