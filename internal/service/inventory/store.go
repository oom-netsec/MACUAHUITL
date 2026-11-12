package inventory

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/devices"
)

const fechaFmt = time.RFC3339

// querier es lo que comparten *sql.DB y *sql.Tx.
type querier interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	Exec(string, ...any) (sql.Result, error)
}

const columnas = `id, name, address, port, platform, folder, tags_json, credential_id, notes, created_at, updated_at`

func scan(r interface{ Scan(...any) error }) (devices.Host, error) {
	var h devices.Host
	var tags, created, updated string
	if err := r.Scan(&h.ID, &h.Name, &h.Address, &h.Port, &h.Platform, &h.Folder, &tags, &h.CredentialID, &h.Notes, &created, &updated); err != nil {
		return h, err
	}
	if err := json.Unmarshal([]byte(tags), &h.Tags); err != nil {
		return h, err
	}
	h.CreatedAt, _ = time.Parse(fechaFmt, created)
	h.UpdatedAt, _ = time.Parse(fechaFmt, updated)
	return h, nil
}

func loadHosts(q querier) ([]devices.Host, error) {
	rows, err := q.Query(`SELECT ` + columnas + ` FROM hosts ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []devices.Host
	for rows.Next() {
		h, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func getHost(q querier, id string) (devices.Host, error) {
	return scan(q.QueryRow(`SELECT `+columnas+` FROM hosts WHERE id = ?`, id))
}

// putHost inserta o reemplaza por ID.
func putHost(q querier, h devices.Host) error {
	tags, _ := json.Marshal(append([]string{}, h.Tags...))
	_, err := q.Exec(`INSERT INTO hosts(`+columnas+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, address=excluded.address, port=excluded.port, platform=excluded.platform,
		folder=excluded.folder, tags_json=excluded.tags_json, credential_id=excluded.credential_id, notes=excluded.notes,
		created_at=excluded.created_at, updated_at=excluded.updated_at`,
		h.ID, h.Name, h.Address, h.Port, h.Platform, h.Folder, string(tags), h.CredentialID, h.Notes,
		h.CreatedAt.UTC().Format(fechaFmt), h.UpdatedAt.UTC().Format(fechaFmt))
	return err
}
