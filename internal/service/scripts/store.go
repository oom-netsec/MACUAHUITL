package scripts

import (
	"database/sql"
	"time"

	dom "github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

const fechaFmt = time.RFC3339

type querier = dom.Querier

func loadUser(q querier) ([]dom.Script, error)         { return dom.LoadUser(q) }
func getUser(q querier, id string) (dom.Script, error) { return dom.GetUser(q, id) }
func put(q querier, s dom.Script) error                { return dom.Put(q, s) }

// loadCollections da las colecciones por orden, cada una con sus scripts en su orden.
func loadCollections(q querier) ([]dom.Coleccion, error) {
	rows, err := q.Query(`SELECT id, name, description, position, created_at, updated_at FROM script_collections ORDER BY position, id`)
	if err != nil {
		return nil, err
	}
	var out []dom.Coleccion
	idx := map[string]int{}
	for rows.Next() {
		var c dom.Coleccion
		var created, updated string
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Order, &created, &updated); err != nil {
			rows.Close()
			return nil, err
		}
		c.CreatedAt, _ = time.Parse(fechaFmt, created)
		c.UpdatedAt, _ = time.Parse(fechaFmt, updated)
		c.ScriptIDs = []string{}
		idx[c.ID] = len(out)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	items, err := q.Query(`SELECT collection_id, script_id FROM script_collection_items ORDER BY position, script_id`)
	if err != nil {
		return nil, err
	}
	defer items.Close()
	for items.Next() {
		var cid, sid string
		if err := items.Scan(&cid, &sid); err != nil {
			return nil, err
		}
		if i, ok := idx[cid]; ok {
			out[i].ScriptIDs = append(out[i].ScriptIDs, sid)
		}
	}
	return out, items.Err()
}

// putCollection inserta o actualiza por ID. Una colección nueva queda al final; una existente conserva su lugar y
// su fecha de creación. Reescribe sus scripts en el orden de c.ScriptIDs.
func putCollection(q querier, c dom.Coleccion) error {
	_, err := q.Exec(`INSERT INTO script_collections(id, name, description, position, created_at, updated_at)
		VALUES(?,?,?,(SELECT COALESCE(MAX(position)+1, 0) FROM script_collections),?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, updated_at=excluded.updated_at`,
		c.ID, c.Name, c.Description, c.CreatedAt.UTC().Format(fechaFmt), c.UpdatedAt.UTC().Format(fechaFmt))
	if err != nil {
		return err
	}
	if _, err := q.Exec(`DELETE FROM script_collection_items WHERE collection_id = ?`, c.ID); err != nil {
		return err
	}
	for i, id := range c.ScriptIDs {
		if _, err := q.Exec(`INSERT INTO script_collection_items(collection_id, script_id, position) VALUES(?,?,?)`, c.ID, id, i); err != nil {
			return err
		}
	}
	return nil
}

// loadPins da los IDs fijados en su orden.
func loadPins(q querier) ([]string, error) {
	rows, err := q.Query(`SELECT script_id FROM script_pins ORDER BY position, script_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// meta es lo que se calcula de cada script a partir de las colecciones y los fijados.
type meta struct {
	fav, pinned map[string]bool
	cols        map[string][]string // ID de script -> IDs de las colecciones que lo contienen, en el orden de las colecciones
}

func loadMeta(q querier) (meta, error) {
	m := meta{fav: map[string]bool{}, pinned: map[string]bool{}, cols: map[string][]string{}}
	cols, err := loadCollections(q)
	if err != nil {
		return m, err
	}
	for _, c := range cols {
		for _, id := range c.ScriptIDs {
			m.cols[id] = append(m.cols[id], c.ID)
			if c.ID == dom.FavoritosID {
				m.fav[id] = true
			}
		}
	}
	pins, err := loadPins(q)
	for _, id := range pins {
		m.pinned[id] = true
	}
	return m, err
}

func getCollection(q querier, id string) (dom.Coleccion, error) {
	cols, err := loadCollections(q)
	if err != nil {
		return dom.Coleccion{}, err
	}
	for _, c := range cols {
		if c.ID == id {
			return c, nil
		}
	}
	return dom.Coleccion{}, sql.ErrNoRows
}
