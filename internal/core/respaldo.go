package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

const (
	respaldoTTL     = 10 * time.Minute
	respaldoMaxPend = 4 // cada vista previa retiene el respaldo abierto (una DEK en memoria protegida): pocas y de corta vida
)

// respaldoPend es una vista previa de import: el respaldo abierto (sus entradas siguen cifradas en memoria normal y solo su DEK de 32
// bytes vive en un buffer protegido, así que no cuenta por entrada) y los metadatos no secretos de sus credenciales. Los secretos se
// descifran de a una al comparar y al aplicar, y se destruyen al instante. Dura hasta que se aplique, venza el token o se cierre la bóveda.
type respaldoPend struct {
	b        *vault.Vault
	infos    []vault.Info // credenciales no reservadas del respaldo, con su ID en él
	reserved int          // entradas del sistema del respaldo: se omiten y no se descifran
	path     string
	expires  time.Time
}

func (p respaldoPend) destroy() {
	if p.b != nil {
		p.b.LockAll()
	}
}

// respaldoStore guarda las vistas previas por token. Su valor cero sirve.
type respaldoStore struct {
	mu   sync.Mutex
	pend map[string]respaldoPend
}

func (st *respaldoStore) evictOldestLocked() {
	oldest := ""
	for k, q := range st.pend {
		if oldest == "" || q.expires.Before(st.pend[oldest].expires) {
			oldest = k
		}
	}
	st.pend[oldest].destroy()
	delete(st.pend, oldest)
}

// stash guarda la vista previa y da su token. Con la bóveda ya cerrada la descarta (ok=false): quien la cerró ya pasó por wipeAll. Los
// vencidos se borran y, con el tope lleno, el más viejo cede su lugar.
func (st *respaldoStore) stash(v *vault.Vault, now time.Time, p respaldoPend) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !v.Unlocked() {
		p.destroy()
		return "", false
	}
	p.expires = now.Add(respaldoTTL)
	st.sweepLocked(now)
	for len(st.pend) >= respaldoMaxPend {
		st.evictOldestLocked()
	}
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	if st.pend == nil {
		st.pend = map[string]respaldoPend{}
	}
	st.pend[tok] = p
	// Aunque nadie vuelva a llamar, a los 10 minutos las credenciales descifradas se borran.
	time.AfterFunc(respaldoTTL+time.Second, func() { st.sweep(time.Now()) })
	return tok, true
}

// take saca el token del mapa bajo el lock: dos aplicaciones a la vez no pueden usar la misma vista previa. Uno vencido se gasta y se borra.
func (st *respaldoStore) take(ctx context.Context, tok string, now time.Time) (respaldoPend, error) {
	st.mu.Lock()
	p, ok := st.pend[tok]
	delete(st.pend, tok)
	st.mu.Unlock()
	if !ok {
		return p, service.Err(ctx, codes.NotFound, "respaldo.err.token", nil)
	}
	if now.After(p.expires) {
		p.destroy()
		return p, service.Err(ctx, codes.FailedPrecondition, "respaldo.err.expired", nil)
	}
	return p, nil
}

// restore devuelve un token cuya aplicación falló por una decisión mala, para que se pueda corregir; si la bóveda se cerró entre tanto, borra.
func (st *respaldoStore) restore(v *vault.Vault, tok string, p respaldoPend) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !v.Unlocked() {
		p.destroy()
		return
	}
	if st.pend == nil {
		st.pend = map[string]respaldoPend{}
	}
	st.pend[tok] = p
}

func (st *respaldoStore) sweep(now time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked(now)
}

func (st *respaldoStore) sweepLocked(now time.Time) {
	for k, p := range st.pend {
		if now.After(p.expires) {
			p.destroy()
			delete(st.pend, k)
		}
	}
}

// wipeAll borra todo: la bóveda se cerró o el núcleo se apaga.
func (st *respaldoStore) wipeAll() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for k, p := range st.pend {
		p.destroy()
		delete(st.pend, k)
	}
}

// Estados de una credencial del respaldo frente a la bóveda viva, y decisiones ante un conflicto.
const (
	estNueva     = "nueva"
	estIgual     = "igual"
	estConflicto = "conflicto_etiqueta"
	estReservada = "reservada"

	decRenombrar  = "rename"
	decReemplazar = "replace"
	decOmitir     = "skip"
)

// respaldoErr traduce los errores del respaldo a gRPC sin repetir nunca lo que se escribió (frase, secretos).
func respaldoErr(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, vault.ErrWrongPassword):
		return service.Err(ctx, codes.PermissionDenied, "respaldo.err.wrong_phrase", nil)
	case errors.Is(err, vault.ErrCorrupt):
		return service.Err(ctx, codes.InvalidArgument, "respaldo.err.corrupt", nil)
	case errors.Is(err, fs.ErrNotExist):
		return service.ErrFrom(ctx, codes.NotFound, err)
	}
	return service.VaultErr(ctx, err)
}

// ExportBackup escribe un respaldo cifrado con una frase distinta de la maestra (internal/vault.WriteBackup).
func (s *vaultSvc) ExportBackup(ctx context.Context, r *v1.ExportBackupRequest) (*v1.ExportBackupResponse, error) {
	defer clear(r.Passphrase)
	s.c.markActive()
	if !r.Confirm {
		return nil, service.Err(ctx, codes.FailedPrecondition, "respaldo.err.confirm", nil)
	}
	path, err := service.AbsPathReason(ctx, r.Path, "respaldo.err.path_abs")
	if err != nil {
		return nil, err
	}
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	if s.c.inDataDir(path) {
		return nil, service.Err(ctx, codes.InvalidArgument, "respaldo.err.in_data_dir", nil)
	}
	n, keys, noPerms, err := vault.WriteBackupKeys(v, path, r.Passphrase, r.Overwrite)
	if errors.Is(err, vault.ErrBackupExists) {
		return nil, service.Err(ctx, codes.AlreadyExists, "file.exists.vault", i18n.A("path", path))
	}
	if err != nil {
		return nil, respaldoErr(ctx, err)
	}
	detail := fmt.Sprintf("%d credentials; ssh_keys_included=%d", n, keys)
	if noPerms {
		detail += "; the file system did not support 0600 permissions"
	}
	s.c.audit("vault.respaldo.exportar", path, detail)
	return &v1.ExportBackupResponse{Count: int32(n), NoPermissions: noPerms, SshKeysIncluded: int32(keys)}, nil
}

// inDataDir dice si path cae en la carpeta de datos del núcleo (o es ella), resolviendo enlaces simbólicos del archivo y de su carpeta.
func (c *Core) inDataDir(path string) bool {
	data := filepath.Clean(c.p.Data)
	if d, err := filepath.EvalSymlinks(data); err == nil {
		data = d
	}
	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	} else if d, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		resolved = filepath.Join(d, filepath.Base(path))
	}
	rel, err := filepath.Rel(data, resolved)
	return err == nil && filepath.IsLocal(rel)
}

type planned struct{ state, target string }

// sameCred compara el contenido completo de dos credenciales (la etiqueta ya coincide).
func sameCred(a, b vault.Credential) bool {
	eq := func(x, y []byte) bool { return subtle.ConstantTimeCompare(x, y) == 1 }
	return a.Username == b.Username && eq(a.Password.Bytes(), b.Password.Bytes()) && eq(a.Enable.Bytes(), b.Enable.Bytes()) && eq(a.SSHKey.Bytes(), b.SSHKey.Bytes())
}

// planImport clasifica cada credencial del respaldo (por su ID en él) frente a la bóveda viva y da también las etiquetas ya usadas en ella.
// Descifra de a una (la del respaldo y la viva con la que se compara) y valida su llave SSH: nunca retiene secretos.
func planImport(v, b *vault.Vault, in []vault.Info) (map[string]planned, map[string]bool, error) {
	live, err := v.List()
	if err != nil {
		return nil, nil, err
	}
	byLabel, used := map[string][]string{}, map[string]bool{}
	for _, i := range live {
		byLabel[i.Label] = append(byLabel[i.Label], i.ID)
		used[i.Label] = true
	}
	out := map[string]planned{}
	for _, i := range in {
		c, err := b.Get(i.ID)
		if err != nil {
			return nil, nil, err
		}
		pl, err := classify(v, c, byLabel[c.Label])
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
		if err != nil {
			return nil, nil, err
		}
		out[i.ID] = pl
	}
	return out, used, nil
}

func classify(v *vault.Vault, c vault.Credential, ids []string) (planned, error) {
	if err := vault.ValidateKey(c.Label, c.SSHKey); err != nil {
		return planned{}, err // todo el import falla, con la etiqueta culpable
	}
	if len(ids) == 0 {
		return planned{state: estNueva}, nil
	}
	pl := planned{state: estConflicto, target: ids[0]}
	for _, id := range ids {
		lc, err := v.Get(id)
		if err != nil {
			return planned{}, err
		}
		same := sameCred(lc, c)
		lc.Password.Destroy()
		lc.Enable.Destroy()
		lc.SSHKey.Destroy()
		if same {
			return planned{state: estIgual, target: id}, nil
		}
	}
	return pl, nil
}

// PreviewBackupImport abre el respaldo con su frase y lo compara con la bóveda viva, sin tocarla. Las credenciales descifradas quedan
// en memoria protegida solo hasta que se aplique, venza el token o se cierre la bóveda.
func (s *vaultSvc) PreviewBackupImport(ctx context.Context, r *v1.PreviewBackupImportRequest) (*v1.PreviewBackupImportResponse, error) {
	defer clear(r.Passphrase)
	s.c.markActive()
	path, err := service.AbsPathReason(ctx, r.Path, "respaldo.err.path_abs")
	if err != nil {
		return nil, err
	}
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	if !v.Unlocked() {
		return nil, service.VaultErr(ctx, vault.ErrLocked)
	}
	b, err := vault.OpenBackup(path, r.Passphrase)
	if err != nil {
		return nil, respaldoErr(ctx, err)
	}
	p := respaldoPend{b: b, path: path}
	stored := false
	defer func() {
		if !stored {
			p.destroy()
		}
	}()
	infos, err := b.ListAll()
	if err != nil {
		return nil, respaldoErr(ctx, err)
	}
	items := make([]*v1.VaultBackupItem, 0, len(infos))
	for _, i := range infos {
		it := &v1.VaultBackupItem{Id: i.ID, Label: i.Label, Username: i.Username}
		if vault.Reserved(i.Label) {
			it.State = estReservada
			p.reserved++
		} else {
			p.infos = append(p.infos, i)
		}
		items = append(items, it)
	}
	plan, _, err := planImport(v, b, p.infos)
	if err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	for _, it := range items {
		if it.State == "" {
			it.State = plan[it.Id].state
		}
	}
	now := s.c.o.Now()
	tok, ok := s.c.respaldos.stash(v, now, p)
	stored = true // stash se quedó con ella (o ya la destruyó)
	if !ok {
		return nil, service.VaultErr(ctx, vault.ErrLocked)
	}
	return &v1.PreviewBackupImportResponse{Token: tok, ExpiresMs: now.Add(respaldoTTL).UnixMilli(), Items: items}, nil
}

// uniqueLabel da «<etiqueta> (importada)», o «(importada 2)», … si esa ya existe.
func uniqueLabel(base string, used map[string]bool) string {
	l := base + " (importada)"
	for n := 2; used[l]; n++ {
		l = fmt.Sprintf("%s (importada %d)", base, n)
	}
	return l
}

// ApplyBackupImport aplica las decisiones por credencial en una sola escritura: o entra todo o no entra nada.
func (s *vaultSvc) ApplyBackupImport(ctx context.Context, r *v1.ApplyBackupImportRequest) (*v1.ApplyBackupImportResponse, error) {
	s.c.markActive()
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	// Cerrada la bóveda, cerrar ya borró lo descifrado; no se gasta el token.
	if !v.Unlocked() {
		return nil, service.Err(ctx, codes.FailedPrecondition, "respaldo.err.locked", nil)
	}
	p, err := s.c.respaldos.take(ctx, r.Token, s.c.o.Now())
	if err != nil {
		return nil, err
	}
	restored := false
	defer func() {
		if !restored {
			p.destroy()
		}
	}()
	// Una decisión mala devuelve el token para corregirla; un fallo al escribir no.
	bad := func(code string, kv ...any) error {
		s.c.respaldos.restore(v, r.Token, p)
		restored = true
		return service.Err(ctx, codes.InvalidArgument, code, i18n.A(kv...))
	}
	label := map[string]string{}
	for _, c := range p.infos {
		label[c.ID] = c.Label
	}
	dec := map[string]string{}
	for _, d := range r.Decisions {
		if _, ok := label[d.Id]; !ok {
			return nil, bad("respaldo.err.decision_unknown")
		}
		if _, dup := dec[d.Id]; dup {
			return nil, bad("respaldo.err.decision_dup", "label", label[d.Id])
		}
		act := i18n.Decision(d.Action)
		if act != decRenombrar && act != decReemplazar && act != decOmitir {
			return nil, bad("respaldo.err.action", "action", d.Action)
		}
		dec[d.Id] = act
	}
	// Se vuelve a comparar contra lo guardado ahora: entre la vista previa y aquí pudo cambiar.
	plan, used, err := planImport(v, p.b, p.infos)
	if err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	var batch []vault.Import
	reemplazados := map[string]string{} // ID local -> etiqueta de la credencial del respaldo que ya lo reemplaza
	iguales := map[string]bool{}        // destinos que alguna credencial del respaldo reporta «igual»: reemplazarlos haría mentir al informe
	var res v1.ApplyBackupImportResponse
	for _, c := range p.infos {
		pl, act := plan[c.ID], dec[c.ID]
		switch {
		case pl.state == estIgual:
			if _, dup := reemplazados[pl.target]; dup {
				return nil, bad("respaldo.err.double_replace", "label", c.Label)
			}
			iguales[pl.target] = true
			res.Same++
		case act == decOmitir:
			res.Skipped++
		case pl.state == estConflicto && act == "":
			return nil, bad("respaldo.err.undecided", "label", c.Label)
		case pl.state == estConflicto && act == decReemplazar:
			if _, dup := reemplazados[pl.target]; dup || iguales[pl.target] {
				return nil, bad("respaldo.err.double_replace", "label", c.Label)
			}
			reemplazados[pl.target] = c.Label
			batch = append(batch, vault.Import{SrcID: c.ID, ID: pl.target})
			res.Replaced++
		case pl.state == estConflicto:
			l := uniqueLabel(c.Label, used)
			used[l] = true
			batch = append(batch, vault.Import{SrcID: c.ID, Label: l})
			res.Renamed++
		default:
			used[c.Label] = true
			batch = append(batch, vault.Import{SrcID: c.ID})
			res.Created++
		}
	}
	res.Skipped += int32(p.reserved)
	if len(batch) > 0 {
		if _, err := v.ImportFrom(p.b, batch); err != nil {
			return nil, service.VaultErr(ctx, err)
		}
	}
	s.c.audit("vault.respaldo.importar", p.path, fmt.Sprintf("%d new, %d replaced, %d renamed, %d skipped, %d identical; decisions: %s",
		res.Created, res.Replaced, res.Renamed, res.Skipped, res.Same, resumenDecisiones(dec, label)))
	return &res, nil
}

// resumenDecisiones lista «etiqueta=acción» para la auditoría, con tope para que un respaldo grande no infle la entrada.
func resumenDecisiones(dec, label map[string]string) string {
	if len(dec) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(dec))
	for id, a := range dec {
		parts = append(parts, fmt.Sprintf("%q=%s", label[id], service.DecisionEN(a)))
	}
	sort.Strings(parts)
	if len(parts) > 20 {
		parts = append(parts[:20], fmt.Sprintf("… and %d more", len(parts)-20))
	}
	return strings.Join(parts, ", ")
}
