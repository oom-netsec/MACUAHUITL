// Package vault implementa la bóveda local: formato vault.mcv, Argon2id,
// jerarquía KEK/DEK, AES-256-GCM y ventanas para trabajos programados
// (spec §10, docs/security/CRYPTO.md).
//
// No hace: red ni logs con contenido de secretos.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/sshkey"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

var (
	ErrEmptyPassword = i18n.New("vault.err.empty_password", nil)
	ErrWrongPassword = i18n.New("vault.err.wrong_password", nil)
	ErrLocked        = i18n.New("vault.err.locked", nil)
	ErrNotFound      = i18n.New("vault.err.not_found", nil)
	ErrCorrupt       = i18n.New("vault.err.corrupt", nil)
	ErrFieldTooLong  = i18n.New("vault.err.field_too_long", i18n.A("max", fmt.Sprintf("%d KiB", MaxFieldBytes>>10)))
	ErrKeyInvalid    = i18n.New("vault.err.key_invalid", nil)
	ErrExists        = i18n.New("vault.err.exists", nil)
	ErrWeakParams    = i18n.New("vault.err.weak_params", nil)
	ErrReserved      = i18n.New("vault.err.reserved", nil)
	ErrNoKey         = i18n.New("vault.err.no_key", nil)
	ErrNotKey        = i18n.New("vault.err.not_key_credential", nil)
	ErrKeyCredential = i18n.New("vault.err.key_credential", nil)
)

// ReservedPrefix marca las entradas que guarda el sistema (por ejemplo la llave de las fichas de respaldo): no salen en List, Get las rechaza
// y solo se leen con GetReserved.
const ReservedPrefix = "macuahuitl:"

// Reserved dice si una etiqueta es de una entrada del sistema.
func Reserved(label string) bool { return strings.HasPrefix(label, ReservedPrefix) }

// GetReserved descifra la entrada reservada con esa etiqueta (la bóveda debe estar abierta). Quien llama hace Destroy de sus secretos.
func (v *Vault) GetReserved(label string) (Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return Credential{}, err
	}
	if !Reserved(label) {
		return Credential{}, ErrNotFound
	}
	for _, e := range v.entries {
		c, err := v.decrypt(e)
		if err != nil {
			return Credential{}, err
		}
		if c.Label == label {
			return c, nil
		}
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
	}
	return Credential{}, ErrNotFound
}

// Credential es una credencial descifrada. Quien la recibe hace Destroy de sus secretos.
type Credential struct {
	ID, Label, Username      string
	Password, Enable, SSHKey *secret.Secret
}

// Info es la vista pública de una credencial, sin secretos.
type Info struct {
	ID, Label, Username  string
	HasEnable, HasSSHKey bool
	HasPassword          bool
	Origin               string // fase 47: OriginGenerated u OriginImported en una credencial "key"; "" en las demás
}

// IsKey dice si la credencial es de tipo "key" (como Info.IsKey, pero con los secretos a la vista).
func (c Credential) IsKey() bool { return !c.SSHKey.Empty() && c.Password.Empty() && c.Enable.Empty() }

// IsKey dice si la credencial es de tipo "key": llave sin contraseña ni enable. Se calcula, no se guarda.
func (i Info) IsKey() bool { return i.HasSSHKey && !i.HasPassword && !i.HasEnable }

// Vault es una bóveda abierta desde disco. Es segura para uso concurrente.
type Vault struct {
	mu       sync.Mutex
	kdf      sync.Mutex // Matches: un Argon2 a la vez (no se puede probar la maestra en paralelo ni agotar la memoria)
	path     string
	hdr      header
	entries  []rawEntry
	dek      *secret.Secret
	aead     cipher.AEAD // una expansión de la DEK por vida de la DEK, no una por operación
	unlocked bool
	windows  map[string]Window
	now      func() time.Time
	onLock   []func() // se llaman al cerrarse de forma interactiva, ya sin v.mu
	// Solo los respaldos: toleran un sistema de archivos sin permisos (vfat) y anotan que no se pudo poner 0600.
	lenient, noPerms bool
	fieldMax         uint32 // tope por campo al descifrar; 0 = maxOwnFieldBytes (solo OpenBackup lo baja a MaxFieldBytes)
	bakSynced        bool   // el .bak ya se puso al día en este arranque (syncOldBak)
}

// Create crea una bóveda nueva en path y la deja desbloqueada.
func Create(path string, master []byte, p Params) (*Vault, error) {
	return create(path, master, p, false)
}

func create(path string, master []byte, p Params, lenient bool) (*Vault, error) {
	defer wipe(master)
	if len(master) == 0 {
		return nil, ErrEmptyPassword
	}
	if p.MemoryKiB < MinMemoryKiB {
		return nil, ErrWeakParams
	}
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}
	v := &Vault{path: path, now: time.Now, windows: map[string]Window{}, lenient: lenient}
	v.hdr.Params = p
	dek := make([]byte, 32)
	for _, b := range [][]byte{v.hdr.VaultID[:], v.hdr.Salt[:], dek} {
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, wrap(err)
		}
	}
	if err := v.setDEK(secret.New(dek)); err != nil {
		return nil, err
	}
	if err := v.sealDEK(master); err != nil {
		v.dek.Destroy()
		return nil, err
	}
	if err := v.persist(); err != nil {
		v.dek.Destroy()
		return nil, err
	}
	v.unlocked = true
	return v, nil
}

// Open lee y valida el archivo. La bóveda queda cerrada.
func Open(path string) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, wrap(err)
	}
	h, entries, err := parseFile(b)
	if err != nil {
		return nil, err
	}
	return &Vault{path: path, hdr: h, entries: entries, now: time.Now, windows: map[string]Window{}}, nil
}

// newAEAD es una variable para que las pruebas cuenten cuántas veces se expande una llave.
var newAEAD = newGCM

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// sealDEK genera una sal nueva y cifra la DEK con la KEK derivada de master.
func (v *Vault) sealDEK(master []byte) error {
	if _, err := io.ReadFull(rand.Reader, v.hdr.Salt[:]); err != nil {
		return wrap(err)
	}
	if _, err := io.ReadFull(rand.Reader, v.hdr.DEKNonce[:]); err != nil {
		return wrap(err)
	}
	kek := deriveFn(master, v.hdr.Salt[:], v.hdr.Params)
	defer kek.Destroy()
	g, err := newAEAD(kek.Bytes())
	if err != nil {
		return wrap(err)
	}
	copy(v.hdr.DEKCipher[:], g.Seal(nil, v.hdr.DEKNonce[:], v.dek.Bytes(), v.hdr.aad()))
	return nil
}

func (v *Vault) openDEK(master []byte) (*secret.Secret, error) { return openDEKWith(v.hdr, master) }

// openDEKWith no toca la bóveda: quien quiera no retener v.mu durante el Argon2 copia la cabecera y llama aquí.
func openDEKWith(h header, master []byte) (*secret.Secret, error) {
	kek := deriveFn(master, h.Salt[:], h.Params)
	defer kek.Destroy()
	g, err := newAEAD(kek.Bytes())
	if err != nil {
		return nil, wrap(err)
	}
	dek, err := g.Open(nil, h.DEKNonce[:], h.DEKCipher[:], h.aad())
	if err != nil {
		return nil, ErrWrongPassword
	}
	return secret.New(dek), nil
}

// Unlock descifra la DEK con la contraseña maestra, que se pone en ceros.
func (v *Vault) Unlock(master []byte) error {
	defer wipe(master)
	if len(master) == 0 {
		return ErrEmptyPassword
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek.Empty() {
		dek, err := v.openDEK(master)
		if err != nil {
			return err
		}
		if err := v.setDEK(dek); err != nil {
			return err
		}
	} else if dek, err := v.openDEK(master); err != nil {
		return err
	} else {
		dek.Destroy()
	}
	v.unlocked = true
	v.syncOldBak()
	return nil
}

// syncOldBak migra un .bak dejado por versiones anteriores (puede traer credenciales borradas, secretos viejos o
// la DEK sellada con una contraseña anterior): lo reescribe con el estado vigente, una vez por arranque. Si no
// se puede, sigue sin él (no impide desbloquear) y lo reintenta en el siguiente Unlock. Requiere v.mu.
func (v *Vault) syncOldBak() {
	if v.bakSynced {
		return
	}
	if _, err := os.Stat(v.path + ".bak"); err != nil {
		v.bakSynced = true
		return
	}
	var noPerms *bool
	if v.lenient {
		noPerms = &v.noPerms
	}
	if writeAtomicOpt(v.path+".bak", marshalFile(v.hdr, v.entries), noPerms) == nil {
		v.bakSynced = true
	}
}

func (v *Vault) entryAAD(id [16]byte) []byte {
	b := append(append([]byte(nil), v.hdr.VaultID[:]...), id[:]...)
	return binary.BigEndian.AppendUint16(b, formatVersion)
}

func (v *Vault) find(id string) (int, error) {
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 16 {
		return -1, ErrNotFound
	}
	for i, e := range v.entries {
		if string(e.ID[:]) == string(raw) {
			return i, nil
		}
	}
	return -1, ErrNotFound
}

// setDEK instala la DEK y su única expansión AES. Requiere v.mu (o construcción).
func (v *Vault) setDEK(dek *secret.Secret) error {
	g, err := newAEAD(dek.Bytes())
	if err != nil {
		dek.Destroy()
		return wrap(err)
	}
	v.dek, v.aead = dek, g
	return nil
}

// dropDEK destruye la DEK y suelta su expansión. Requiere v.mu.
func (v *Vault) dropDEK() {
	v.dek.Destroy()
	v.dek, v.aead = nil, nil
}

func (v *Vault) decrypt(e rawEntry) (Credential, error) {
	plain, err := v.aead.Open(nil, e.Nonce[:], e.CT, v.entryAAD(e.ID))
	if err != nil {
		return Credential{}, corrupt("entrada %x no autentica", e.ID)
	}
	max := v.fieldMax
	if max == 0 {
		max = maxOwnFieldBytes
	}
	c, err := decodePlain(plain, max)
	c.ID = hex.EncodeToString(e.ID[:])
	return c, err
}

// requireFull exige la bóveda abierta de forma interactiva.
func (v *Vault) requireFull() error {
	if !v.unlocked || v.dek.Empty() {
		return ErrLocked
	}
	return nil
}

// guardReserved devuelve ErrReserved si la entrada i es del sistema (la llave de las fichas): ni Put ni Delete la tocan por su ID. Requiere v.mu.
func (v *Vault) guardReserved(i int) error {
	c, err := v.decrypt(v.entries[i])
	if err != nil {
		return err
	}
	c.Password.Destroy()
	c.Enable.Destroy()
	c.SSHKey.Destroy()
	if Reserved(c.Label) {
		return ErrReserved
	}
	return nil
}

// Put crea (ID vacío) o reemplaza una credencial y persiste de inmediato.
func (v *Vault) Put(c Credential) (string, error) {
	ids, err := v.PutBatch([]Credential{c})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// PutUnlessKey es Put que no reemplaza una credencial de tipo "key" (ErrKeyCredential: esas cambian con RegenerateKey). La comprobación
// y la escritura van en la misma sección crítica.
func (v *Vault) PutUnlessKey(c Credential) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return "", err
	}
	if c.ID != "" {
		i, err := v.find(c.ID)
		if err != nil {
			return "", err
		}
		old, err := v.decrypt(v.entries[i])
		if err != nil {
			return "", err
		}
		isKey := old.IsKey()
		old.Password.Destroy()
		old.Enable.Destroy()
		old.SSHKey.Destroy()
		if isKey {
			return "", ErrKeyCredential
		}
	}
	ids, err := v.putBatchLocked([]Credential{c}, false, true)
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// PutBatch es Put para varias credenciales con una sola escritura: o quedan todas o no queda ninguna.
func (v *Vault) PutBatch(cs []Credential) ([]string, error) { return v.putBatch(cs, false, true) }

// PutReserved crea o reemplaza (por etiqueta) una entrada reservada del sistema; la etiqueta debe ser reservada. Ignora c.ID: la entrada
// a reemplazar sale solo de la etiqueta, y la búsqueda y la escritura van en la misma sección crítica (dos llamadas no la duplican).
func (v *Vault) PutReserved(c Credential) error {
	if !Reserved(c.Label) {
		return ErrNotFound
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return err
	}
	c.ID = ""
	for _, e := range v.entries {
		old, err := v.decrypt(e)
		if err != nil {
			return err
		}
		old.Password.Destroy()
		old.Enable.Destroy()
		old.SSHKey.Destroy()
		if old.Label == c.Label {
			c.ID = old.ID
			break
		}
	}
	_, err := v.putBatchLocked([]Credential{c}, true, false)
	return err
}

func (v *Vault) putBatch(cs []Credential, reserved, strict bool) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.putBatchLocked(cs, reserved, strict)
}

// putBatchLocked es PutBatch con v.mu ya tomado; reserved deja reemplazar una entrada reservada. strict es la frontera de entrada: tope
// de MaxFieldBytes por campo y llave SSH validada (sin strict, solo el tope de cordura: lo reservado y el export de lo ya guardado).
func (v *Vault) putBatchLocked(cs []Credential, reserved, strict bool) ([]string, error) {
	if err := v.requireFull(); err != nil {
		return nil, err
	}
	max := maxOwnFieldBytes // lo reservado (la reversa pendiente del asistente guarda un running-config entero) no lleva el tope estricto
	if strict {
		max = MaxFieldBytes
	}
	for _, c := range cs {
		if strict {
			if err := checkStrict(c); err != nil {
				return nil, err
			}
		} else if overLen(c, max) {
			return nil, ErrFieldTooLong
		}
	}
	next := append([]rawEntry(nil), v.entries...)
	ids := make([]string, 0, len(cs))
	for _, c := range cs {
		id, err := v.sealInto(&next, c, reserved)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	prev := v.entries
	v.entries = next
	if err := v.persistReplacingBak(); err != nil {
		v.entries = prev
		return nil, err
	}
	return ids, nil
}

// sealInto cifra c y la agrega a next (o reemplaza la entrada de c.ID). No toca v.entries. Requiere v.mu.
func (v *Vault) sealInto(next *[]rawEntry, c Credential, reserved bool) (string, error) {
	idx := -1
	var e rawEntry
	if c.ID != "" {
		i, err := v.find(c.ID)
		if err != nil {
			return "", err
		}
		if err := v.guardReserved(i); err != nil && !reserved {
			return "", err
		}
		idx, e.ID = i, v.entries[i].ID
	} else if _, err := io.ReadFull(rand.Reader, e.ID[:]); err != nil {
		return "", wrap(err)
	}
	if _, err := io.ReadFull(rand.Reader, e.Nonce[:]); err != nil {
		return "", wrap(err)
	}
	plain := encodePlain(c)
	e.CT = v.aead.Seal(nil, e.Nonce[:], plain, v.entryAAD(e.ID))
	wipe(plain)
	if idx >= 0 {
		(*next)[idx] = e
	} else {
		*next = append(*next, e)
	}
	return hex.EncodeToString(e.ID[:]), nil
}

// Import es una credencial de un respaldo abierto que ImportFrom copia: SrcID es su ID en el respaldo; ID, el de la credencial viva que
// reemplaza ("" crea una); Label, la etiqueta nueva ("" conserva la del respaldo).
type Import struct{ SrcID, ID, Label string }

// ImportFrom copia de src las credenciales de items con una sola escritura: o entran todas o no entra ninguna. Descifra y cifra de a
// una (solo una credencial en memoria bloqueada a la vez, sin importar cuántas sean), valida cada una con la frontera estricta de Put
// y no toca v.entries hasta que todas pasaron; si la escritura falla, la bóveda queda como estaba. src es otra bóveda abierta.
func (v *Vault) ImportFrom(src *Vault, items []Import) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return nil, err
	}
	next := append([]rawEntry(nil), v.entries...)
	ids := make([]string, 0, len(items))
	for _, it := range items {
		c, err := src.Get(it.SrcID)
		if err != nil {
			return nil, err
		}
		c.ID = it.ID
		if it.Label != "" {
			c.Label = it.Label
		}
		id, err := v.sealStrict(&next, c)
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	prev := v.entries
	v.entries = next
	if err := v.persistReplacingBak(); err != nil {
		v.entries = prev
		return nil, err
	}
	return ids, nil
}

// overLen dice si algún campo de c pasa de max bytes.
func overLen(c Credential, max int) bool {
	return len(c.Label) > max || len(c.Username) > max || len(c.Password.Bytes()) > max ||
		len(c.Enable.Bytes()) > max || len(c.SSHKey.Bytes()) > max
}

// checkStrict es la frontera de entrada (Put*, import y export): tope de MaxFieldBytes por campo y llave SSH válida. El error nombra
// la credencial para que el usuario sepa cuál editar o borrar.
func checkStrict(c Credential) error {
	if overLen(c, MaxFieldBytes) {
		l := c.Label
		if len(l) > 64 {
			l = l[:64] + "…"
		}
		return i18n.Wrap("vault.err.field_too_long_in", ErrFieldTooLong, i18n.A("label", l, "max", fmt.Sprintf("%d KiB", MaxFieldBytes>>10)))
	}
	return ValidateKey(c.Label, c.SSHKey)
}

// sealStrict es sealInto tras checkStrict.
func (v *Vault) sealStrict(next *[]rawEntry, c Credential) (string, error) {
	if err := checkStrict(c); err != nil {
		return "", err
	}
	return v.sealInto(next, c, false)
}

// Get descifra una credencial. Quien llama hace Destroy de sus secretos.
func (v *Vault) Get(id string) (Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.authorizeGet(id); err != nil {
		return Credential{}, err
	}
	i, err := v.find(id)
	if err != nil {
		return Credential{}, err
	}
	c, err := v.decrypt(v.entries[i])
	if err == nil && Reserved(c.Label) {
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
		return Credential{}, ErrReserved
	}
	return c, err
}

// List devuelve la vista pública de las credenciales (sin las reservadas del sistema).
func (v *Vault) List() ([]Info, error) { return v.list(false) }

// ListAll es List con las entradas reservadas incluidas (solo etiqueta y usuario; Get las sigue rechazando).
func (v *Vault) ListAll() ([]Info, error) { return v.list(true) }

func (v *Vault) list(reserved bool) ([]Info, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(v.entries))
	for _, e := range v.entries {
		c, err := v.decrypt(e)
		if err != nil {
			return nil, err
		}
		if reserved || !Reserved(c.Label) {
			in := Info{ID: c.ID, Label: c.Label, Username: c.Username, HasEnable: !c.Enable.Empty(), HasSSHKey: !c.SSHKey.Empty(), HasPassword: !c.Password.Empty()}
			if in.IsKey() {
				in.Origin = originOf(c.SSHKey.Bytes())
			}
			out = append(out, in)
		}
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
	}
	return out, nil
}

// Delete borra una credencial y persiste.
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return err
	}
	i, err := v.find(id)
	if err != nil {
		return err
	}
	if err := v.guardReserved(i); err != nil {
		return err
	}
	prev := v.entries
	v.entries = append(append([]rawEntry(nil), v.entries[:i]...), v.entries[i+1:]...)
	if err := v.persistReplacingBak(); err != nil {
		v.entries = prev
		return err
	}
	return nil
}

// DeleteReserved borra la entrada reservada con esa etiqueta (Delete por ID las rechaza). ErrNotFound si no existe.
func (v *Vault) DeleteReserved(label string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return err
	}
	if !Reserved(label) {
		return ErrNotFound
	}
	for i, e := range v.entries {
		c, err := v.decrypt(e)
		if err != nil {
			return err
		}
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
		if c.Label != label {
			continue
		}
		prev := v.entries
		v.entries = append(append([]rawEntry(nil), v.entries[:i]...), v.entries[i+1:]...)
		if err := v.persistReplacingBak(); err != nil {
			v.entries = prev
			return err
		}
		return nil
	}
	return ErrNotFound
}

// ChangeMasterPassword vuelve a cifrar la DEK con una KEK nueva (sal nueva).
func (v *Vault) ChangeMasterPassword(old, new []byte) error {
	defer wipe(old)
	defer wipe(new)
	if len(old) == 0 || len(new) == 0 {
		return ErrEmptyPassword
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return err
	}
	check, err := v.openDEK(old)
	if err != nil {
		return err
	}
	check.Destroy()
	prev := v.hdr
	if err := v.sealDEK(new); err != nil {
		v.hdr = prev
		return err
	}
	// El .bak se escribe antes y con la DEK ya sellada con la contraseña nueva: nunca queda uno que abra con la vieja.
	if err := v.persistReplacingBak(); err != nil {
		v.hdr = prev
		return err
	}
	return nil
}

// persist respalda el archivo vigente en .bak y escribe el nuevo, ambos de forma atómica.
func (v *Vault) persist() error {
	var noPerms *bool
	if v.lenient {
		noPerms = &v.noPerms
	}
	if cur, err := os.ReadFile(v.path); err == nil {
		if err := writeAtomicOpt(v.path+".bak", cur, noPerms); err != nil {
			return wrap(fmt.Errorf("respaldo: %w", unprefix(err)))
		}
	}
	return writeAtomicOpt(v.path, marshalFile(v.hdr, v.entries), noPerms)
}

// persistReplacingBak escribe primero el .bak con el estado nuevo y luego la bóveda: el .bak no conserva una
// credencial borrada ni el secreto anterior de una editada, y si falla la segunda escritura la bóveda queda como
// estaba y quien llama recibe el error (nunca «borrada pero con error»; el reintento es posible).
func (v *Vault) persistReplacingBak() error {
	var noPerms *bool
	if v.lenient {
		noPerms = &v.noPerms
	}
	data := marshalFile(v.hdr, v.entries)
	if err := writeAtomicOpt(v.path+".bak", data, noPerms); err != nil {
		return wrap(fmt.Errorf("respaldo: %w", unprefix(err)))
	}
	return writeAtomicOpt(v.path, data, noPerms)
}

// chmod es variable para que las pruebas simulen un sistema de archivos sin permisos.
var chmod = func(f *os.File, m os.FileMode) error { return f.Chmod(m) }

// writeAtomicOpt: temporal 0600 en el mismo directorio, fsync, rename y fsync del directorio; con noPerms distinto de nil tolera que el sistema de archivos no admita chmod (EPERM o no soportado, p. ej. vfat) y lo anota.
func writeAtomicOpt(path string, data []byte, noPerms *bool) error {
	dir := filepath.Dir(path)
	tmp, err := sys.CreateTempPrivate(dir, ".vault-*.tmp")
	if err != nil {
		return wrap(err)
	}
	defer os.Remove(tmp.Name())
	if err := chmod(tmp, 0o600); err != nil {
		if noPerms == nil || !(errors.Is(err, os.ErrPermission) || errors.Is(err, errors.ErrUnsupported)) {
			tmp.Close()
			return wrap(err)
		}
		*noPerms = true
	}
	// En Windows chmod no protege nada, pero el temporal ya nació con la DACL protegida (CreateTempPrivate). Esto solo
	// detecta un sistema de archivos sin ACL (FAT, exFAT) para anotar «sin permisos», con la misma tolerancia que chmod;
	// en Linux no hace nada.
	if err := sys.ProtectNewStrict(tmp.Name()); err != nil {
		if noPerms == nil || !errors.Is(err, errors.ErrUnsupported) {
			tmp.Close()
			return wrap(err)
		}
		*noPerms = true
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return wrap(err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return wrap(err)
	}
	if err := tmp.Close(); err != nil {
		return wrap(err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return wrap(err)
	}
	if err := sys.SyncDir(dir); err != nil { // en Windows no hace nada: ver sys.SyncDir
		return wrap(err)
	}
	return nil
}

// ValidateKey rechaza una llave privada SSH que x/crypto/ssh no parsea (igual que transport.OpenSSH: una con frase tampoco sirve allí).
// Una llave vacía es válida (la credencial no lleva). No hay pública guardada con qué cotejar: la entrada solo guarda la privada.
func ValidateKey(label string, key *secret.Secret) error {
	if key.Empty() {
		return nil
	}
	if err := sshkey.Parse(key.Bytes()); err != nil {
		return i18n.Wrap("vault.err.key_invalid", ErrKeyInvalid, i18n.A("label", label)) // errors.Is(ErrKeyInvalid) por la causa
	}
	return nil
}
