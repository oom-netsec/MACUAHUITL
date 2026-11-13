package pack

import (
	"database/sql"
	"slices"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

// Querier es lo que comparten *sql.DB y *sql.Tx.
type Querier interface {
	Query(string, ...any) (*sql.Rows, error)
	Exec(string, ...any) (sql.Result, error)
}

// hiddenRows lee la tabla pack_hidden: paquete → IDs ocultos.
func hiddenRows(q Querier) (map[string][]string, error) {
	rows, err := q.Query(`SELECT pack, item_id FROM pack_hidden ORDER BY pack, item_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var pk, id string
		if err := rows.Scan(&pk, &id); err != nil {
			return nil, err
		}
		out[pk] = append(out[pk], id)
	}
	return out, rows.Err()
}

// HasItem dice si id es un playbook o un script (derivado o propio) del paquete.
func (p *Pack) HasItem(id string) bool {
	for _, pb := range p.Playbooks {
		if pb.ID == id {
			return true
		}
	}
	return slices.Contains(p.ScriptIDs(), id)
}

// Hidden son los IDs ocultos de p que el paquete todavía trae (la elección de un ID que una versión nueva quitó no cuenta).
func (p *Pack) Hidden(q Querier) ([]string, error) {
	m, err := hiddenRows(q)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(m[p.ID], func(id string) bool { return !p.HasItem(id) }), nil
}

// HiddenSets son los IDs de playbook y de script que las listas no deben mostrar, de todos los paquetes de sn. Un
// playbook oculto oculta también su script derivado lib-<id>. Se lee de la base en cada llamada: nunca hay copia que se desfase.
func HiddenSets(q Querier, sn *Snapshot) (playbooks, scriptIDs map[string]bool, err error) {
	m, err := hiddenRows(q)
	if err != nil {
		return nil, nil, err
	}
	playbooks, scriptIDs = map[string]bool{}, map[string]bool{}
	for _, p := range sn.Packs {
		for _, id := range m[p.ID] {
			scriptIDs[id] = true
			for _, pb := range p.Playbooks {
				if pb.ID == id {
					playbooks[id] = true
					for _, d := range scripts.Derived([]playbook.Playbook{pb}) {
						scriptIDs[d.ID] = true
					}
				}
			}
		}
	}
	return playbooks, scriptIDs, nil
}

// SetHidden aplica la elección: oculta hide y muestra show. Los IDs ya deben estar validados con HasItem.
func SetHidden(q Querier, packID string, hide, show []string) error {
	for _, id := range hide {
		if _, err := q.Exec(`INSERT OR IGNORE INTO pack_hidden(pack, item_id) VALUES(?, ?)`, packID, id); err != nil {
			return err
		}
	}
	for _, id := range show {
		if _, err := q.Exec(`DELETE FROM pack_hidden WHERE pack = ? AND item_id = ?`, packID, id); err != nil {
			return err
		}
	}
	return nil
}
