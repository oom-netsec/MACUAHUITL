package bridge

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Respaldo cifrado de la bóveda (fase 29d). Las frases llegan del webview como string (límite declarado, como las contraseñas de la bóveda).

type VaultBackupItemDTO struct {
	ID       string `json:"id"` // ID dentro del respaldo: las decisiones van por él
	Label    string `json:"label"`
	Username string `json:"username"`
	State    string `json:"state"` // nueva | igual | conflicto_etiqueta | reservada
}

type VaultBackupPreviewDTO struct {
	Token     string               `json:"token"`
	ExpiresMs int64                `json:"expiresMs"`
	Items     []VaultBackupItemDTO `json:"items"`
}

type VaultBackupDecisionDTO struct {
	ID     string `json:"id"`
	Action string `json:"action"` // renombrar | reemplazar | omitir
}

type VaultBackupResultDTO struct {
	Created  int `json:"created"`
	Replaced int `json:"replaced"`
	Renamed  int `json:"renamed"`
	Skipped  int `json:"skipped"`
	Same     int `json:"same"`
}

type VaultBackupExportDTO struct {
	Count         int  `json:"count"`
	NoPermissions bool `json:"noPermissions"` // el sistema de archivos (p. ej. vfat) no admitió los permisos 0600
}

// ExportVaultBackup escribe el respaldo cifrado y devuelve cuántas credenciales guardó; confirm es la confirmación explícita.
func (b *Bridge) ExportVaultBackup(path, passphrase string, overwrite, confirm bool) (VaultBackupExportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (VaultBackupExportDTO, error) {
		r, err := v1.NewVaultServiceClient(c).ExportBackup(ctx, &v1.ExportBackupRequest{Path: path, Passphrase: []byte(passphrase), Overwrite: overwrite, Confirm: confirm})
		return VaultBackupExportDTO{Count: int(r.GetCount()), NoPermissions: r.GetNoPermissions()}, err
	})
}

// RemoveEmptyFile borra el archivo vacío que dejó el diálogo de guardar cuando lo que iba a escribirse falló. Solo borra un archivo
// regular de 0 bytes en esa ruta exacta (sin seguir enlaces); cualquier otra cosa es un error y no se toca. Que ya no exista no es error.
func (b *Bridge) RemoveEmptyFile(path string) error {
	if !filepath.IsAbs(path) {
		return b.bridgeErr(i18n.New("file.err.path_abs", nil))
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return wrapErr(err)
	}
	if !fi.Mode().IsRegular() || fi.Size() != 0 {
		return b.bridgeErr(i18n.New("bridge.err.only_empty", nil))
	}
	return wrapErr(os.Remove(path))
}

// PreviewVaultBackupImport abre el respaldo y da el estado de cada credencial; no escribe nada.
func (b *Bridge) PreviewVaultBackupImport(path, passphrase string) (VaultBackupPreviewDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (VaultBackupPreviewDTO, error) {
		r, err := v1.NewVaultServiceClient(c).PreviewBackupImport(ctx, &v1.PreviewBackupImportRequest{Path: path, Passphrase: []byte(passphrase)})
		out := VaultBackupPreviewDTO{Token: r.GetToken(), ExpiresMs: r.GetExpiresMs(), Items: []VaultBackupItemDTO{}}
		for _, it := range r.GetItems() {
			out.Items = append(out.Items, VaultBackupItemDTO{ID: it.GetId(), Label: it.GetLabel(), Username: it.GetUsername(), State: it.GetState()})
		}
		return out, err
	})
}

// ApplyVaultBackupImport aplica la vista previa con una decisión por credencial en conflicto.
func (b *Bridge) ApplyVaultBackupImport(token string, decisions []VaultBackupDecisionDTO) (VaultBackupResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (VaultBackupResultDTO, error) {
		ds := []*v1.VaultBackupDecision{}
		for _, d := range decisions {
			ds = append(ds, &v1.VaultBackupDecision{Id: d.ID, Action: d.Action})
		}
		r, err := v1.NewVaultServiceClient(c).ApplyBackupImport(ctx, &v1.ApplyBackupImportRequest{Token: token, Decisions: ds})
		return VaultBackupResultDTO{Created: int(r.GetCreated()), Replaced: int(r.GetReplaced()), Renamed: int(r.GetRenamed()), Skipped: int(r.GetSkipped()), Same: int(r.GetSame())}, err
	})
}
