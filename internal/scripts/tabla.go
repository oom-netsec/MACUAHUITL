package scripts

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Acceso a la tabla scripts: lo comparten el servicio de scripts y el de paquetes (el import del paquete personal);
// un servicio no importa a otro, así que la única implementación vive aquí.

// Querier es lo que comparten *sql.DB y *sql.Tx.
type Querier interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
	Exec(string, ...any) (sql.Result, error)
}

const columnas = `id, name, tech, platform, description, commands_json, tags_json, created_at, updated_at`

// Scan lee una fila de la tabla scripts (en el orden de columnas) como script del usuario.
func Scan(r interface{ Scan(...any) error }) (Script, error) {
	var s Script
	var cmds, tags, created, updated string
	if err := r.Scan(&s.ID, &s.Name, &s.Tech, &s.Platform, &s.Description, &cmds, &tags, &created, &updated); err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(cmds), &s.Commands); err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(tags), &s.Tags); err != nil {
		return s, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, created)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	s.Origin = OrigenUsuario
	return s, nil
}

// LoadUser lista los scripts del usuario por nombre.
func LoadUser(q Querier) ([]Script, error) {
	rows, err := q.Query(`SELECT ` + columnas + ` FROM scripts ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Script
	for rows.Next() {
		s, err := Scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetUser lee un script por ID (sql.ErrNoRows si no existe).
func GetUser(q Querier, id string) (Script, error) {
	return Scan(q.QueryRow(`SELECT `+columnas+` FROM scripts WHERE id = ?`, id))
}

func args(s Script) []any {
	cmds, _ := json.Marshal(s.Commands)
	tags, _ := json.Marshal(s.Tags)
	return []any{s.ID, s.Name, s.Tech, s.Platform, s.Description, string(cmds), string(tags),
		s.CreatedAt.UTC().Format(time.RFC3339), s.UpdatedAt.UTC().Format(time.RFC3339)}
}

const insertSQL = `INSERT INTO scripts(` + columnas + `) VALUES(?,?,?,?,?,?,?,?,?)`

// Insert agrega un script; un ID repetido falla (el import nunca reemplaza).
func Insert(q Querier, s Script) error {
	_, err := q.Exec(insertSQL, args(s)...)
	return err
}

// Put inserta o reemplaza por ID.
func Put(q Querier, s Script) error {
	_, err := q.Exec(insertSQL+`
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, tech=excluded.tech, platform=excluded.platform,
		description=excluded.description, commands_json=excluded.commands_json, tags_json=excluded.tags_json,
		created_at=excluded.created_at, updated_at=excluded.updated_at`, args(s)...)
	return err
}
