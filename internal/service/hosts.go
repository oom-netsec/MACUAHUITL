package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// Lecturas de solo lectura de la libreta de hosts para los servicios que no la administran (Patrol, cambio asistido,
// terminal). Quien llama no debe tener una transacción ni filas abiertas: el núcleo tiene una sola conexión.

const hostCols = `id, name, address, port, platform, folder, tags_json, credential_id, notes, startup_command, created_at, updated_at, protocol`

// GenericHostAt dice si hay un host guardado linux o windows en esa dirección y puerto (0 = 22). La dirección se
// normaliza igual que la libreta: minúsculas, y en IP netip con Unmap. Un error de la base es err; un host que no
// es genérico, o que no existe, es ok=false.
func GenericHostAt(db *sql.DB, address string, port int) (name, platform string, ok bool, err error) {
	if port == 0 {
		port = devices.DefaultPort
	}
	err = db.QueryRow(`SELECT name, platform FROM hosts WHERE address = ? AND port = ?`, devices.AddrKey(address), port).Scan(&name, &platform)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return name, platform, devices.IsGeneric(platform), nil
}

// SavedHost lee un host de la libreta por id; sql.ErrNoRows si no existe.
func SavedHost(db *sql.DB, id string) (devices.Host, error) {
	var h devices.Host
	var tags, created, updated string
	err := db.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE id = ?`, id).Scan(&h.ID, &h.Name, &h.Address, &h.Port, &h.Platform, &h.Folder, &tags,
		&h.CredentialID, &h.Notes, &h.StartupCommand, &created, &updated, &h.Protocol)
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(tags), &h.Tags); err != nil {
		return h, err
	}
	h.CreatedAt, _ = time.Parse(time.RFC3339, created)
	h.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return h, nil
}

// CheckNotGenericHost rechaza (InvalidArgument) un destino que es un host linux o windows de la libreta: esos solo se
// abren en el terminal SSH. Un error de la base no rechaza: queda la detección de plataforma de siempre.
func CheckNotGenericHost(ctx context.Context, db *sql.DB, address string, port int) error {
	name, platform, ok, err := GenericHostAt(db, address, port)
	if err != nil || !ok {
		return nil
	}
	return Err(ctx, codes.InvalidArgument, "patrol.svc.generic_host", i18n.A("name", name, "platform", platform))
}

// CheckNoKeyCredential rechaza (InvalidArgument) una credencial de solo llave: no sirve fuera del terminal de hosts
// linux y windows (regla 7b). Con la bóveda cerrada o sin la credencial no se sabe el tipo y no rechaza.
func CheckNoKeyCredential(ctx context.Context, v *vault.Vault, ids ...string) error {
	if v == nil {
		return nil
	}
	infos, err := v.List()
	if err != nil {
		return nil
	}
	for _, id := range ids {
		for _, i := range infos {
			if i.ID == id && i.IsKey() {
				return Err(ctx, codes.InvalidArgument, "patrol.svc.key_credential", i18n.A("label", i.Label))
			}
		}
	}
	return nil
}
