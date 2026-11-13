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
		Shadowed: strs(p.GetShadowed())}
}

// PackInstall instala el .mpack de path (ruta absoluta que el usuario eligió). allowUnsigned es la confirmación del
// diálogo con aviso para un paquete de terceros; sin ella se rechaza con pack.err.unsigned.
func (b *Bridge) PackInstall(path string, allowUnsigned bool) (PackInstallResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PackInstallResultDTO, error) {
		r, err := v1.NewPackServiceClient(c).Install(ctx, &v1.PackServiceInstallRequest{Path: path, AllowUnsigned: allowUnsigned})
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
