package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Paquetes de contenido (.mpack, fase 32, ADR 0010) ----
// Todo texto del paquete (nombre, descripción, autor, README) viaja como texto plano: la vista no debe interpretarlo como
// HTML ni pedir recursos a la red. Las listas siempre son arreglos (nunca null).

type PackInfoDTO struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	MinCore       string   `json:"minCore"`
	Name          string   `json:"name"`
	NameEn        string   `json:"nameEn"`
	Description   string   `json:"description"`
	DescriptionEn string   `json:"descriptionEn"`
	Platforms     []string `json:"platforms"`
	Author        string   `json:"author"`
	License       string   `json:"license"`
	Official      bool     `json:"official"`
	PlaybookCount int      `json:"playbookCount"`
	ScriptCount   int      `json:"scriptCount"`
	Shadowed      []string `json:"shadowed"`
	Hidden        []string `json:"hidden"` // fase 32b: IDs de playbook o script ocultos por el usuario
}

type PackInstallResultDTO struct {
	Pack            PackInfoDTO `json:"pack"`
	ReplacedVersion string      `json:"replacedVersion"`
}

type PackDetailDTO struct {
	Pack        PackInfoDTO `json:"pack"`
	Readme      string      `json:"readme"`
	PlaybookIDs []string    `json:"playbookIds"`
	ScriptIDs   []string    `json:"scriptIds"`
}

func packInfoDTO(p *v1.PackInfo) PackInfoDTO {
	return PackInfoDTO{ID: p.GetId(), Version: p.GetVersion(), MinCore: p.GetMinCore(), Name: p.GetName(), NameEn: p.GetNameEn(),
		Description: p.GetDescription(), DescriptionEn: p.GetDescriptionEn(), Platforms: strs(p.GetPlatforms()), Author: p.GetAuthor(),
		License: p.GetLicense(), Official: p.GetOfficial(), PlaybookCount: int(p.GetPlaybookCount()), ScriptCount: int(p.GetScriptCount()),
		Shadowed: strs(p.GetShadowed()), Hidden: strs(p.GetHidden())}
}

// PackInstall instala el .mpack de path (ruta absoluta que el usuario eligió). allowUnsigned es la confirmación del
// diálogo con aviso para un paquete de terceros; sin ella se rechaza con pack.err.unsigned.
func (b *Bridge) PackInstall(path string, allowUnsigned bool, sha256 string) (PackInstallResultDTO, error) {
	return b.PackInstallHiding(path, allowUnsigned, nil, false, sha256)
}

// PackInstallHiding es PackInstall con los IDs de playbook o script que quedan ocultos al instalar (la selección del
// diálogo). Con replaceHidden, hide es el conjunto exacto de ocultos tras instalar (el diálogo manda true); sin él se
// conserva lo que ya estaba oculto y hide suma. sha256 es el de PackInspect (obligatorio: ata lo revisado a lo instalado).
func (b *Bridge) PackInstallHiding(path string, allowUnsigned bool, hide []string, replaceHidden bool, sha256 string) (PackInstallResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackInstallResultDTO, error) {
		r, err := v1.NewPackServiceClient(c).Install(ctx, &v1.PackServiceInstallRequest{Path: path, AllowUnsigned: allowUnsigned, Hide: hide, ReplaceHidden: replaceHidden, Sha256: sha256})
		return PackInstallResultDTO{Pack: packInfoDTO(r.GetPack()), ReplacedVersion: r.GetReplacedVersion()}, err
	})
}

func (b *Bridge) PackList() ([]PackInfoDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]PackInfoDTO, error) {
		r, err := v1.NewPackServiceClient(c).List(ctx, &v1.PackServiceListRequest{})
		out := []PackInfoDTO{}
		for _, p := range r.GetPacks() {
			out = append(out, packInfoDTO(p))
		}
		return out, err
	})
}

func (b *Bridge) PackShow(id string) (PackDetailDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackDetailDTO, error) {
		r, err := v1.NewPackServiceClient(c).Show(ctx, &v1.PackServiceShowRequest{Id: id})
		return PackDetailDTO{Pack: packInfoDTO(r.GetPack()), Readme: r.GetReadme(), PlaybookIDs: strs(r.GetPlaybookIds()), ScriptIDs: strs(r.GetScriptIds())}, err
	})
}

// PackRemove quita el paquete id y devuelve cuántos favoritos de sus scripts se quitaron.
func (b *Bridge) PackRemove(id string) (int, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (int, error) {
		r, err := v1.NewPackServiceClient(c).Remove(ctx, &v1.PackServiceRemoveRequest{Id: id})
		return int(r.GetFavoritesRemoved()), err
	})
}

// PackSetItems oculta (hide) o vuelve a mostrar (show) playbooks y scripts de un paquete; devuelve el paquete con hidden al día.
func (b *Bridge) PackSetItems(packID string, hide, show []string) (PackInfoDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackInfoDTO, error) {
		r, err := v1.NewPackServiceClient(c).SetItems(ctx, &v1.PackServiceSetItemsRequest{PackId: packID, Hide: hide, Show: show})
		return packInfoDTO(r.GetPack()), err
	})
}

type PackInspectDTO struct {
	Pack            PackInfoDTO `json:"pack"`
	PlaybookIDs     []string    `json:"playbookIds"`
	ScriptIDs       []string    `json:"scriptIds"`
	ReplacedVersion string      `json:"replacedVersion"`
	SHA256          string      `json:"sha256"` // del archivo: pásalo a PackInstall
}

// PackInspect es la vista previa de PackInstall para el diálogo con casillas: valida el .mpack igual y no instala nada.
func (b *Bridge) PackInspect(path string, allowUnsigned bool) (PackInspectDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackInspectDTO, error) {
		r, err := v1.NewPackServiceClient(c).Inspect(ctx, &v1.PackServiceInspectRequest{Path: path, AllowUnsigned: allowUnsigned})
		return PackInspectDTO{Pack: packInfoDTO(r.GetPack()), PlaybookIDs: strs(r.GetPlaybookIds()), ScriptIDs: strs(r.GetScriptIds()),
			ReplacedVersion: r.GetReplacedVersion(), SHA256: r.GetSha256()}, err
	})
}

// ---- Paquete personal (fase 32c): exportar scripts y playbooks propios a un .mpack sin firma e importarlo de vuelta ----

type PackExportRequestDTO struct {
	EditorName       string   `json:"editorName"` // "<editor>/<nombre>"
	ScriptIDs        []string `json:"scriptIds"`
	IncludePlaybooks bool     `json:"includePlaybooks"`
	License          string   `json:"license"`
	Path             string   `json:"path"`
	Overwrite        bool     `json:"overwrite"`
	Name             string   `json:"name"`
	NameEn           string   `json:"nameEn"`
	Description      string   `json:"description"`
	DescriptionEn    string   `json:"descriptionEn"`
	Author           string   `json:"author"`
}

type PackExportResultDTO struct {
	ID               string   `json:"id"`
	Version          string   `json:"version"`
	SHA256           string   `json:"sha256"`
	Scripts          int      `json:"scripts"`
	Playbooks        int      `json:"playbooks"`
	OmittedPlaybooks []string `json:"omittedPlaybooks"`
}

type PackImportItemDTO struct {
	Kind          string `json:"kind"` // script | playbook
	ID            string `json:"id"`
	Name          string `json:"name"`
	State         string `json:"state"` // nuevo | igual | conflicto_id | conflicto_nombre
	ConflictsWith string `json:"conflictsWith"`
}

type PackImportDecisionDTO struct {
	ItemID string `json:"itemId"`
	Action string `json:"action"` // renombrar | omitir
}

type PackImportResultDTO struct {
	Pack             PackInfoDTO         `json:"pack"`
	Items            []PackImportItemDTO `json:"items"`
	SHA256           string              `json:"sha256"` // del archivo: pásalo a PackImport para atar la vista previa
	Applied          bool                `json:"applied"`
	ScriptsCreated   int                 `json:"scriptsCreated"`
	ScriptsRenamed   int                 `json:"scriptsRenamed"`
	ScriptsSkipped   int                 `json:"scriptsSkipped"`
	PlaybooksCreated int                 `json:"playbooksCreated"`
	PlaybooksRenamed int                 `json:"playbooksRenamed"`
	PlaybooksSkipped int                 `json:"playbooksSkipped"`
	PlaybookIDs      []string            `json:"playbookIds"`
}

// PackExport arma el paquete personal en req.Path (ruta absoluta que el usuario eligió).
func (b *Bridge) PackExport(req PackExportRequestDTO) (PackExportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackExportResultDTO, error) {
		r, err := v1.NewPackServiceClient(c).Export(ctx, &v1.PackServiceExportRequest{EditorName: req.EditorName, ScriptIds: req.ScriptIDs,
			IncludePlaybooks: req.IncludePlaybooks, License: req.License, Path: req.Path, Overwrite: req.Overwrite, Name: req.Name, NameEn: req.NameEn,
			Description: req.Description, DescriptionEn: req.DescriptionEn, Author: req.Author})
		return PackExportResultDTO{ID: r.GetId(), Version: r.GetVersion(), SHA256: r.GetSha256(), Scripts: int(r.GetScripts()), Playbooks: int(r.GetPlaybooks()),
			OmittedPlaybooks: strs(r.GetOmittedPlaybooks())}, err
	})
}

func packImportDTO(r *v1.PackServiceImportResponse) PackImportResultDTO {
	out := PackImportResultDTO{Pack: packInfoDTO(r.GetPack()), Items: []PackImportItemDTO{}, SHA256: r.GetSha256(), Applied: r.GetApplied(),
		ScriptsCreated: int(r.GetScriptsCreated()), ScriptsRenamed: int(r.GetScriptsRenamed()), ScriptsSkipped: int(r.GetScriptsSkipped()),
		PlaybooksCreated: int(r.GetPlaybooksCreated()), PlaybooksRenamed: int(r.GetPlaybooksRenamed()), PlaybooksSkipped: int(r.GetPlaybooksSkipped()),
		PlaybookIDs: strs(r.GetPlaybookIds())}
	for _, it := range r.GetItems() {
		out.Items = append(out.Items, PackImportItemDTO{Kind: it.GetKind(), ID: it.GetId(), Name: it.GetName(), State: it.GetState(), ConflictsWith: it.GetConflictsWith()})
	}
	return out
}

// PackImportPreview valida el .mpack de path y dice qué traería, sin escribir nada.
func (b *Bridge) PackImportPreview(path string) (PackImportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackImportResultDTO, error) {
		r, err := v1.NewPackServiceClient(c).Import(ctx, &v1.PackServiceImportRequest{Path: path})
		return packImportDTO(r), err
	})
}

// PackImport aplica el import con las decisiones del diálogo (un conflicto sin decisión falla sin escribir nada).
func (b *Bridge) PackImport(path, sha256 string, decisions []PackImportDecisionDTO) (PackImportResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackImportResultDTO, error) {
		req := &v1.PackServiceImportRequest{Path: path, Confirm: true, Sha256: sha256}
		for _, d := range decisions {
			req.Decisions = append(req.Decisions, &v1.PackImportDecision{ItemId: d.ItemID, Action: d.Action})
		}
		r, err := v1.NewPackServiceClient(c).Import(ctx, req)
		return packImportDTO(r), err
	})
}
