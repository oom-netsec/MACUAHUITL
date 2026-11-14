package pack

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

const fileIndex = "INDEX" // el índice calculado al instalar; revalida el contenido al arrancar

// Base es el contenido que sigue embebido en el binario; con él se detectan los choques de IDs y nombres.
type Base struct {
	PlaybookIDs []string
	ScriptIDs   []string
	ScriptNames []string // se comparan con scripts.NameKey
	// ReservedPlaybooks y ReservedScripts son IDs que salieron del binario a un paquete oficial (p. ej. los movidos a
	// oom/ios-xe): un paquete que no es oficial nunca los ocupa, esté o no instalado el oficial.
	ReservedPlaybooks []string
	ReservedScripts   []string
}

// checkReserved aplica las reservas a un paquete que no es oficial.
func (s *Store) checkReserved(p *Pack) error {
	if p.Official {
		return nil
	}
	if ed := p.Editor(); reservedSegments[ed] {
		return rej("editor.reserved", "editor", ed)
	}
	return nil
}

// Rejected es un paquete instalado que no pasó la revalidación al arrancar.
type Rejected struct {
	Dir    string // relativa a la carpeta de paquetes
	ID     string // vacío si el manifiesto no se pudo leer
	Reason string
}

// Snapshot es una foto inmutable de los paquetes instalados, ordenados por ID.
type Snapshot struct{ Packs []*Pack }

// Store es la carpeta <datos>/packs con los paquetes instalados y su foto en memoria.
type Store struct {
	dir      string
	core     string
	keys     []ed25519.PublicKey
	base     Base
	mu       sync.Mutex // serializa instalar y quitar
	snap     atomic.Pointer[Snapshot]
	OnChange func() // tras instalar o quitar, ya publicada la foto nueva; corre bajo el lock del almacén (no debe llamarlo de vuelta)
}

// Open abre la carpeta, borra los .tmp-* que hayan quedado (restaurando antes una versión vieja interrumpida) y
// revalida cada paquete: sha256 contra el INDEX, sin archivos de más ni enlaces, firma y los pasos 4 a 7 del ADR
// (manifiesto y min_core, playbooks, scripts y choques), con los oficiales primero y luego por ID, para que el
// resultado no dependa del orden de la carpeta. Uno que no pasa se omite y vuelve en rej; el núcleo sigue funcionando.
func Open(dir, coreVersion string, keys []ed25519.PublicKey, base Base) (*Store, []Rejected, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	s := &Store{dir: dir, core: coreVersion, keys: keys, base: base}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var rej []Rejected
	reject := func(rel string, p *Pack, err error) {
		r := Rejected{Dir: rel, Reason: Reason(err)}
		if p != nil {
			r.ID = p.ID
		}
		if r.Reason == "" {
			r.Reason = "read"
		}
		rej = append(rej, r)
	}
	type cand struct {
		rel string
		p   *Pack
	}
	var cands []cand
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			s.restoreOld(filepath.Join(dir, e.Name()))
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	ents, err = os.ReadDir(dir) // tras restaurar
	if err != nil {
		return nil, nil, err
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil || !e.IsDir() {
			rej = append(rej, Rejected{Dir: e.Name(), Reason: "zip.path"})
			continue
		}
		for _, n := range sub {
			rel := e.Name() + "/" + n.Name()
			p, err := s.revalidate(rel) // sha256/INDEX, firma, manifiesto, min_core, playbooks y scripts
			if err != nil {
				reject(rel, p, err)
				continue
			}
			cands = append(cands, cand{rel, p})
		}
	}
	slices.SortFunc(cands, func(a, b cand) int {
		if a.p.Official != b.p.Official {
			if a.p.Official {
				return -1
			}
			return 1
		}
		return strings.Compare(a.p.ID, b.p.ID)
	})
	var packs []*Pack
	for _, c := range cands { // reservas y choques (paso 7) contra la base y los ya aceptados
		err := s.checkReserved(c.p)
		if err == nil {
			err = s.collides(c.p, packs)
		}
		if err != nil {
			reject(c.rel, c.p, err)
			continue
		}
		packs = append(packs, c.p)
	}
	s.publish(packs)
	return s, rej, nil
}

// restoreOld devuelve a su lugar la versión que una instalación interrumpida dejó en tmp/old, si ese lugar quedó
// vacío (la caída ocurrió entre los dos rename). El contenido se revalida igual que cualquier paquete instalado.
func (s *Store) restoreOld(tmp string) {
	b, err := os.ReadFile(filepath.Join(tmp, "old", fileManifest))
	if err != nil {
		return
	}
	m, err := parseManifest(b)
	if err != nil {
		return
	}
	final := filepath.Join(s.dir, filepath.FromSlash(m.ID))
	if _, err := os.Lstat(final); err == nil {
		return
	}
	if os.MkdirAll(filepath.Dir(final), 0o700) == nil {
		os.Rename(filepath.Join(tmp, "old"), final)
	}
}

func (s *Store) revalidate(rel string) (*Pack, error) {
	d := filepath.Join(s.dir, rel)
	if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
		return nil, rej("zip.path", "name", rel)
	}
	files, err := readDir(d, fileIndex)
	if err != nil {
		return nil, err
	}
	idx, ok := files[fileIndex]
	delete(files, fileIndex)
	if !ok {
		return nil, rej("index.mismatch", "name", fileIndex)
	}
	if string(idx) != string(Index(files)) {
		return nil, rej("index.mismatch", "name", rel)
	}
	p, err := check(files, s.core, s.keys, false)
	if err != nil {
		if m, merr := parseManifest(files[fileManifest]); merr == nil {
			return &Pack{Manifest: m}, err // solo para nombrar el id en el aviso
		}
		return nil, err
	}
	if rel != filepath.ToSlash(p.ID) {
		return p, rej("zip.path", "name", rel)
	}
	return p, nil
}

func (s *Store) publish(packs []*Pack) {
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	s.snap.Store(&Snapshot{Packs: packs})
}

// Snapshot es la foto vigente; nunca cambia una vez devuelta.
func (s *Store) Snapshot() *Snapshot { return s.snap.Load() }

// Contenido es lo que los paquetes suman a la biblioteca de scripts.
func (sn *Snapshot) Contenido() []scripts.Contenido {
	var out []scripts.Contenido
	for _, p := range sn.Packs {
		out = append(out, scripts.Contenido{Playbooks: p.Playbooks, Scripts: p.Scripts})
	}
	return out
}

// Find busca el ID entre los instalados; nunca lo une a una ruta.
func (sn *Snapshot) Find(id string) *Pack {
	for _, p := range sn.Packs {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// ScriptIDs son los IDs de todos los scripts que el paquete aporta: los derivados de sus playbooks y los propios.
func (p *Pack) ScriptIDs() []string {
	d := scripts.Derived(p.Playbooks)
	var ids []string
	for _, s := range append(d, p.Scripts...) {
		ids = append(ids, s.ID)
	}
	return ids
}

// collides aplica el paso 7: ID de playbook o de script, o nombre de script, repetido contra la base, los otros
// paquetes (menos el mismo ID, que se reemplaza) o el propio paquete.
func (s *Store) collides(p *Pack, others []*Pack) error {
	pbs, ids, names := map[string]string{}, map[string]string{}, map[string]string{}
	for _, id := range s.base.PlaybookIDs {
		pbs[id] = "base"
	}
	for _, id := range s.base.ScriptIDs {
		ids[id] = "base"
	}
	if !p.Official {
		for _, id := range s.base.ReservedPlaybooks {
			pbs[id] = "reserved"
		}
		for _, id := range s.base.ReservedScripts {
			ids[id] = "reserved"
		}
	}
	for _, n := range s.base.ScriptNames {
		names[scripts.NameKey(n)] = "base"
	}
	add := func(q *Pack, who string) error {
		for _, pb := range q.Playbooks {
			if w, dup := pbs[pb.ID]; dup {
				return rej("collision", "id", pb.ID, "with", w)
			}
			pbs[pb.ID] = who
		}
		d := scripts.Derived(q.Playbooks)
		for _, sc := range append(d, q.Scripts...) {
			if w, dup := ids[sc.ID]; dup {
				return rej("collision", "id", sc.ID, "with", w)
			}
			ids[sc.ID] = who
			k := scripts.NameKey(sc.Name)
			if w, dup := names[k]; dup {
				return rej("collision", "id", sc.Name, "with", w)
			}
			names[k] = who
		}
		return nil
	}
	for _, o := range others {
		if o.ID == p.ID {
			continue
		}
		if err := add(o, o.ID); err != nil { // dos paquetes ya instalados chocan entre sí: no es culpa de p
			continue
		}
	}
	return add(p, p.ID)
}

// ReadArchive lee el .mpack una sola vez, con tope de 20 MB. Abre sin bloquear y mira el tipo antes de leer: un FIFO
// o un dispositivo no cuelgan al núcleo.
func ReadArchive(path string) ([]byte, error) {
	f, err := sys.OpenRegular(path)
	if errors.Is(err, sys.ErrNotRegular) {
		return nil, rej("zip.invalid")
	}
	if err != nil {
		return nil, readErr(err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxArchive+1))
	if err != nil {
		return nil, readErr(err)
	}
	if len(b) > MaxArchive {
		return nil, rej("zip.too_big", "what", "archive")
	}
	return b, nil
}

// Result es lo que devuelve Install.
type Result struct {
	Pack     *Pack
	Replaced string // versión anterior que reemplazó; vacío si era nuevo
	// SyncWarning: el paquete quedó instalado, pero no se pudo asegurar con fsync la carpeta (una caída podría perderlo).
	SyncWarning error
	// CommitErr: el paquete quedó instalado, pero falló el paso commit de InstallWith (lo oculto no se guardó).
	CommitErr error
}

// check hace los pasos 2 a 7 del ADR sobre bytes ya leídos y devuelve el paquete y el instalado que reemplazaría
// (nil si es nuevo). Con el error, el paquete viaja igual si ya se pudo leer. Install lo llama con s.mu; Inspect sin él.
func (s *Store) check(data []byte, allowUnsigned bool) (p, old *Pack, cur *Snapshot, err error) {
	if p, err = Verify(data, s.core, s.keys); err != nil {
		return nil, nil, nil, err
	}
	if !p.Official && !allowUnsigned {
		return p, nil, nil, rej("unsigned")
	}
	if err = s.checkReserved(p); err != nil {
		return p, nil, nil, err
	}
	cur = s.snap.Load()
	if old = cur.Find(p.ID); old != nil {
		switch {
		case old.Official && !p.Official:
			return p, nil, nil, rej("official_replace", "id", p.ID)
		case CompareVersions(p.Version, old.Version) <= 0:
			return p, nil, nil, rej("version", "id", p.ID, "installed", old.Version, "version", p.Version)
		}
	}
	if err = s.collides(p, cur.Packs); err != nil {
		return p, nil, nil, err
	}
	return p, old, cur, nil
}

// Inspect valida el paquete igual que Install (mismos pasos y mismos errores) sin instalar nada: no toca el disco
// ni la foto vigente. Devuelve el paquete y la versión que reemplazaría.
func (s *Store) Inspect(data []byte, allowUnsigned bool) (*Result, error) { // sin s.mu: la foto es atómica y no escribe
	p, old, _, err := s.check(data, allowUnsigned)
	if err != nil {
		if p == nil {
			return nil, err
		}
		return &Result{Pack: p}, err
	}
	res := &Result{Pack: p}
	if old != nil {
		res.Replaced = old.Version
	}
	return res, nil
}

// Install hace los pasos 2 a 8 del ADR sobre bytes ya leídos. allowUnsigned es la confirmación explícita para un
// paquete de terceros.
func (s *Store) Install(data []byte, allowUnsigned bool) (*Result, error) {
	return s.InstallWith(data, allowUnsigned, nil, nil)
}

// InstallWith es Install con dos pasos, para guardar lo que debe estar listo cuando el paquete se vea (lo oculto) sin
// que quede aplicado a una versión que no cambió y sin retener una transacción durante el extract. prepare corre con
// el paquete ya validado y bajo el lock, antes de tocar el disco: si falla, no se instala nada. commit (puede ser nil)
// corre después del extract y justo antes de publicar la foto; si falla, el paquete ya está en disco y se publica
// igual, y el error va en Result.CommitErr (quien instala debe auditarlo). replaced es la versión que reemplazaría
// ("" si es nuevo).
func (s *Store) InstallWith(data []byte, allowUnsigned bool, prepare func(p *Pack, replaced string) error, commit func(p *Pack) error) (*Result, error) {
	s.mu.Lock()
	p, old, cur, err := s.check(data, allowUnsigned)
	if err != nil {
		s.mu.Unlock()
		if p == nil {
			return nil, err
		}
		return &Result{Pack: p}, err
	}
	if prepare != nil {
		replaced := ""
		if old != nil {
			replaced = old.Version
		}
		if err := prepare(p, replaced); err != nil {
			s.mu.Unlock()
			return &Result{Pack: p}, err
		}
	}
	syncWarn, err := s.extract(p)
	if err != nil {
		s.mu.Unlock()
		return &Result{Pack: p}, err
	}
	var commitErr error
	if commit != nil {
		commitErr = commit(p)
	}
	next := []*Pack{p}
	for _, o := range cur.Packs {
		if o.ID != p.ID {
			next = append(next, o)
		}
	}
	s.publish(next)
	if s.OnChange != nil { // bajo el lock: así no queda publicado un catálogo viejo si otra instalación entra enseguida
		s.OnChange()
	}
	s.mu.Unlock()
	res := &Result{Pack: p, SyncWarning: syncWarn, CommitErr: commitErr}
	if old != nil {
		res.Replaced = old.Version
	}
	return res, nil
}

// syncDir hace fsync de una carpeta para que el rename y los archivos nuevos sobrevivan a una caída.
var syncDir = syncDirOS // variable para que las pruebas simulen un fallo

func syncDirOS(d string) error {
	f, err := os.Open(d)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func writeSync(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// extract escribe el paquete en .tmp-* (con fsync) y lo mete con rename. Lo que hubiera en su lugar (la versión
// anterior, o una carpeta que no pasó la revalidación al arrancar) se aparta a .tmp-*/old y se borra después del
// rename; si el proceso muere entre los dos rename, Open lo restaura.
func (s *Store) extract(p *Pack) (syncWarn, err error) {
	tmp, err := os.MkdirTemp(s.dir, ".tmp-")
	if err != nil {
		return nil, readErr(err)
	}
	defer os.RemoveAll(tmp)
	files := map[string][]byte{fileIndex: Index(p.files)}
	for n, b := range p.files {
		files[n] = b
	}
	dirs := map[string]bool{}
	for n, b := range files {
		dst := filepath.Join(tmp, "x", filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, readErr(err)
		}
		if err := writeSync(dst, b); err != nil {
			return nil, readErr(err)
		}
		dirs[filepath.Dir(dst)] = true
	}
	for d := range dirs {
		if err := syncDir(d); err != nil {
			return nil, readErr(err)
		}
	}
	final := filepath.Join(s.dir, filepath.FromSlash(p.ID))
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return nil, readErr(err)
	}
	aside := filepath.Join(tmp, "old")
	moved := true
	if err := os.Rename(final, aside); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, readErr(err)
		}
		moved = false
	}
	if err := os.Rename(filepath.Join(tmp, "x"), final); err != nil {
		if moved {
			os.Rename(aside, final)
		}
		return nil, readErr(err)
	}
	return syncDir(filepath.Dir(final)), nil // si falla, el paquete ya entró: solo se avisa
}

// Remove quita el paquete id (buscado entre los instalados) y devuelve lo que traía.
func (s *Store) Remove(id string) (*Pack, error) {
	s.mu.Lock()
	cur := s.snap.Load()
	p := cur.Find(id)
	if p == nil {
		s.mu.Unlock()
		return nil, rej("not_found", "id", id)
	}
	// p.ID cumple la gramática del manifiesto, así que la ruta no sale de la carpeta.
	if err := os.RemoveAll(filepath.Join(s.dir, filepath.FromSlash(p.ID))); err != nil {
		s.mu.Unlock()
		return nil, readErr(err)
	}
	var next []*Pack
	for _, o := range cur.Packs {
		if o.ID != id {
			next = append(next, o)
		}
	}
	s.publish(next)
	if s.OnChange != nil {
		s.OnChange()
	}
	s.mu.Unlock()
	return p, nil
}

// SHA256 es el sha256 en hex de los bytes del archivo.
func SHA256(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
