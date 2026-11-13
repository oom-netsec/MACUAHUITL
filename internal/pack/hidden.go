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

// Items son los IDs de playbook y de script (derivado o propio) que el paquete trae; se calcula una vez por llamada.
func (p *Pack) Items() map[string]bool {
	m := map[string]bool{}
	for _, pb := range p.Playbooks {
		m[pb.ID] = true
	}
	for _, id := range p.ScriptIDs() {
		m[id] = true
	}
	return m
}

// HasItem dice si id es un playbook o un script (derivado o propio) del paquete.
func (p *Pack) HasItem(id string) bool { return p.Items()[id] }

// Hidden son los IDs ocultos de p que el paquete todavía trae (la elección de un ID que una versión nueva quitó no cuenta).
func (p *Pack) Hidden(q Querier) ([]string, error) {
	m, err := hiddenRows(q)
	if err != nil {
		return nil, err
	}
	items := p.Items()
	return slices.DeleteFunc(m[p.ID], func(id string) bool { return !items[id] }), nil
}

// HiddenSets son los IDs de playbook y de script que las listas no deben mostrar, de todos los paquetes de sn. Un
// playbook oculto oculta también su script derivado lib-<id>. Un playbook que uno de <config>/playbooks tapa (shadowed)
// no se oculta: lo que se vería es el del usuario, no el del paquete. Se lee de la base en cada llamada: nunca hay
// copia que se desfase.
func HiddenSets(q Querier, sn *Snapshot, shadowed map[string]bool) (playbooks, scriptIDs map[string]bool, err error) {
	m, err := hiddenRows(q)
	if err != nil {
		return nil, nil, err
	}
	playbooks, scriptIDs = map[string]bool{}, map[string]bool{}
	for _, p := range sn.Packs {
		if len(m[p.ID]) == 0 {
			continue
		}
		items := p.Items() // una vez por paquete y por llamada
		for _, id := range m[p.ID] {
			if !items[id] {
				continue
			}
			isPB := false
			for _, pb := range p.Playbooks {
				if pb.ID == id {
					isPB = true
				}
			}
			if isPB && shadowed[id] {
				continue
			}
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

// SetHidden aplica la elección: oculta hide y muestra show, y dice cuántas filas cambió de verdad. Los IDs ya deben
// estar validados con HasItem.
func SetHidden(q Querier, packID string, hide, show []string) (changed int, err error) {
	for _, id := range hide {
		r, err := q.Exec(`INSERT OR IGNORE INTO pack_hidden(pack, item_id) VALUES(?, ?)`, packID, id)
		if err != nil {
			return 0, err
		}
		n, _ := r.RowsAffected()
		changed += int(n)
	}
	for _, id := range show {
		r, err := q.Exec(`DELETE FROM pack_hidden WHERE pack = ? AND item_id = ?`, packID, id)
		if err != nil {
			return 0, err
		}
		n, _ := r.RowsAffected()
		changed += int(n)
	}
	return changed, nil
}

// PruneHidden borra las filas de p de IDs que el paquete ya no trae, para que uno que vuelva en una versión
// posterior entre visible. No toca el resto: quitar el paquete (Remove) es quien borra todo.
func PruneHidden(q Querier, p *Pack) error {
	rows, err := hiddenRows(q)
	if err != nil {
		return err
	}
	items := p.Items()
	for _, id := range rows[p.ID] {
		if !items[id] {
			if _, err := q.Exec(`DELETE FROM pack_hidden WHERE pack = ? AND item_id = ?`, p.ID, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReplaceHidden deja exactamente hide como los ocultos de p.
func ReplaceHidden(q Querier, p *Pack, hide []string) error {
	if _, err := q.Exec(`DELETE FROM pack_hidden WHERE pack = ?`, p.ID); err != nil {
		return err
	}
	_, err := SetHidden(q, p.ID, hide, nil)
	return err
}
