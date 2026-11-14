package pack

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// CoreVersion es la versión del núcleo con la que el almacén valida min_core.
func (s *Store) CoreVersion() string { return s.core }

// TakenScriptNames son los nombres de script de la base y de los paquetes instalados: el export no deja que un script derivado
// de un playbook propio los repita, porque Install lo rechazaría por colisión.
func (s *Store) TakenScriptNames() []string {
	names := slices.Clone(s.base.ScriptNames)
	for _, p := range s.snap.Load().Packs {
		for _, sc := range append(scripts.Derived(p.Playbooks), p.Scripts...) {
			names = append(names, sc.Name)
		}
	}
	return names
}

// VerifyImport hace los pasos 2 a 6 del ADR para importar a «Mis scripts» (fase 32b). Solo vale un paquete sin firma:
// uno con firma oficial se instala, no se importa, porque sus IDs van sin prefijo de editor.
func (s *Store) VerifyImport(data []byte) (*Pack, error) {
	p, err := Verify(data, s.core, s.keys)
	if err != nil {
		return nil, err
	}
	if p.Official {
		return p, rej("import.official")
	}
	if err := s.checkReserved(p); err != nil {
		return p, err
	}
	return p, nil
}

// PlaybookPlan es un playbook del paquete frente a lo que ya hay: Estado es scripts.Nuevo o scripts.ConflictoID, y Con dice
// con qué choca («base», «reserved», el ID de un paquete instalado, «user» o «file»).
type PlaybookPlan struct{ ID, File, State, With string }

// clash dice con qué choca un playbook importado (ID o archivo), o vacío. Un paquete importado nunca es oficial, así que
// también cuentan los IDs movidos a oom/ios-xe. Se llama bajo s.mu.
func (s *Store) clash(id, dir string, installed []*Pack, userIDs map[string]bool) string {
	switch {
	case slices.Contains(s.base.PlaybookIDs, id):
		return "base"
	case slices.Contains(s.base.ReservedPlaybooks, id):
		return "reserved"
	case userIDs[id]:
		return "user"
	}
	for _, q := range installed {
		if slices.ContainsFunc(q.Playbooks, func(pb playbook.Playbook) bool { return pb.ID == id }) {
			return q.ID
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, id[slices.Index([]byte(id), '/')+1:]+".yaml")); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return "file"
	}
	return ""
}

// PlanPlaybooks compara los playbooks de p con la base, los instalados, los del usuario (userIDs) y los archivos de dir.
func (s *Store) PlanPlaybooks(p *Pack, dir string, userIDs map[string]bool) []PlaybookPlan {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plan(p, dir, userIDs)
}

func (s *Store) plan(p *Pack, dir string, userIDs map[string]bool) []PlaybookPlan {
	installed := s.snap.Load().Packs
	var out []PlaybookPlan
	for _, pb := range p.Playbooks {
		it := PlaybookPlan{ID: pb.ID, File: pb.ID[slices.Index([]byte(pb.ID), '/')+1:] + ".yaml", State: scripts.Nuevo}
		if with := s.clash(pb.ID, dir, installed, userIDs); with != "" {
			it.State, it.With = scripts.ConflictoID, with
		}
		out = append(out, it)
	}
	return out
}

// PlaybookResult es lo que ImportPlaybooks escribió: Written son los IDs finales.
type PlaybookResult struct {
	Written                   []string
	Created, Renamed, Skipped int
	files                     []string
}

// Undo borra de dir los archivos que ImportPlaybooks creó (para cuando lo que iba junto con ellos falla).
func (r *PlaybookResult) Undo(dir string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer root.Close()
	for _, n := range r.files {
		root.Remove(n)
	}
}

// ImportPlaybooks escribe en dir (<config>/playbooks) los playbooks de p según dec (ID del archivo → renombrar u omitir).
// Un choque sin decisión, una decisión que no cabe (reemplazar, o algo distinto de omitir en un playbook nuevo) o un
// ID que no está en p falla sin escribir nada. Nunca sobrescribe: cada archivo se crea con O_EXCL y sin seguir enlaces,
// y si uno falla se borran los ya escritos.
func (s *Store) ImportPlaybooks(p *Pack, dir string, userIDs map[string]bool, dec map[string]string) (*PlaybookResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan := s.plan(p, dir, userIDs)
	known := map[string]bool{}
	for _, it := range plan {
		known[it.ID] = true
	}
	for id := range dec {
		if !known[id] {
			return nil, rej("import.decision", "id", id)
		}
	}
	res := &PlaybookResult{}
	installed := s.snap.Load().Packs
	files := map[string][]byte{}
	taken := map[string]bool{} // IDs que este mismo import ya usa
	for _, it := range plan {
		taken[it.ID] = true
	}
	for i, it := range plan {
		d, has := dec[it.ID]
		if has && d != scripts.Renombrar && d != scripts.Omitir || has && d == scripts.Renombrar && it.State == scripts.Nuevo {
			return nil, rej("import.decision", "id", it.ID)
		}
		if it.State == scripts.ConflictoID && !has {
			return nil, rej("import.missing", "id", it.ID)
		}
		if d == scripts.Omitir {
			res.Skipped++
			continue
		}
		pb, raw := p.Playbooks[i], p.files[filePlay+it.File]
		if d == scripts.Renombrar {
			base := it.ID
			for n := 2; ; n++ {
				id := base + "-" + strconv.Itoa(n)
				if !taken[id] && s.clash(id, dir, installed, userIDs) == "" {
					pb.ID = id
					break
				}
			}
			taken[pb.ID] = true
			var err error
			if raw, err = playbook.Marshal(pb); err != nil {
				return nil, readErr(err)
			}
			res.Renamed++
		} else {
			res.Created++
		}
		files[pb.ID[slices.Index([]byte(pb.ID), '/')+1:]+".yaml"] = raw
		res.Written = append(res.Written, pb.ID)
	}
	var err error
	if res.files, err = writePlaybooks(dir, files); err != nil {
		return nil, err
	}
	return res, nil
}

// writePlaybooks crea cada archivo nuevo dentro de dir (que se crea si falta) con un os.Root: un nombre o un enlace no
// pueden sacar la escritura de la carpeta, y nada existente se sobrescribe. Si algo falla, borra lo que había escrito.
func writePlaybooks(dir string, files map[string][]byte) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, readErr(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, readErr(err)
	}
	defer root.Close()
	var done []string
	fail := func(err error, name string) ([]string, error) {
		for _, n := range done {
			root.Remove(n)
		}
		if errors.Is(err, fs.ErrExist) {
			return nil, rej("import.exists", "file", name)
		}
		return nil, readErr(err)
	}
	for name, b := range files {
		f, err := sys.OpenNewIn(root, name)
		if err != nil {
			return fail(err, name)
		}
		done = append(done, name)
		if _, err = f.Write(b); err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fail(err, name)
		}
	}
	if d, err := root.Open("."); err == nil { // que los archivos nuevos sobrevivan a una caída
		d.Sync()
		d.Close()
	}
	return done, nil
}
