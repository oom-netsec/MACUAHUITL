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
)

var (
	ErrEmptyPassword = i18n.New("vault.err.empty_password", nil)
	ErrWrongPassword = i18n.New("vault.err.wrong_password", nil)
	ErrLocked        = i18n.New("vault.err.locked", nil)
	ErrNotFound      = i18n.New("vault.err.not_found", nil)
	ErrCorrupt       = i18n.New("vault.err.corrupt", nil)
	ErrExists        = i18n.New("vault.err.exists", nil)
	ErrWeakParams    = i18n.New("vault.err.weak_params", nil)
	ErrReserved      = i18n.New("vault.err.reserved", nil)
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
}

// Vault es una bóveda abierta desde disco. Es segura para uso concurrente.
type Vault struct {
	mu       sync.Mutex
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
	bakSynced        bool // el .bak ya se puso al día en este arranque (syncOldBak)
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
			return nil, fmt.Errorf("vault: %w", err)
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
		return nil, fmt.Errorf("vault: %w", err)
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
		return fmt.Errorf("vault: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, v.hdr.DEKNonce[:]); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	kek := deriveFn(master, v.hdr.Salt[:], v.hdr.Params)
	defer kek.Destroy()
	g, err := newAEAD(kek.Bytes())
	if err != nil {
		return fmt.Errorf("vault: %w", err)
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
		return nil, fmt.Errorf("vault: %w", err)
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
		return fmt.Errorf("vault: %w", err)
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
	c, err := decodePlain(plain)
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

// PutBatch es Put para varias credenciales con una sola escritura: o quedan todas o no queda ninguna.
func (v *Vault) PutBatch(cs []Credential) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return nil, err
	}
	next := append([]rawEntry(nil), v.entries...)
	ids := make([]string, 0, len(cs))
	for _, c := range cs {
		idx := -1
		var e rawEntry
		if c.ID != "" {
			i, err := v.find(c.ID)
			if err != nil {
				return nil, err
			}
			if err := v.guardReserved(i); err != nil {
				return nil, err
			}
			idx, e.ID = i, v.entries[i].ID
		} else if _, err := io.ReadFull(rand.Reader, e.ID[:]); err != nil {
			return nil, fmt.Errorf("vault: %w", err)
		}
		if _, err := io.ReadFull(rand.Reader, e.Nonce[:]); err != nil {
			return nil, fmt.Errorf("vault: %w", err)
		}
		plain := encodePlain(c)
		e.CT = v.aead.Seal(nil, e.Nonce[:], plain, v.entryAAD(e.ID))
		wipe(plain)
		if idx >= 0 {
			next[idx] = e
		} else {
			next = append(next, e)
		}
		ids = append(ids, hex.EncodeToString(e.ID[:]))
	}
	prev := v.entries
	v.entries = next
	if err := v.persistReplacingBak(); err != nil {
		v.entries = prev
		return nil, err
	}
	return ids, nil
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
			out = append(out, Info{ID: c.ID, Label: c.Label, Username: c.Username, HasEnable: !c.Enable.Empty(), HasSSHKey: !c.SSHKey.Empty()})
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
			return fmt.Errorf("vault: respaldo: %w", err)
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
		return fmt.Errorf("vault: respaldo: %w", err)
	}
	return writeAtomicOpt(v.path, data, noPerms)
}

// chmod es variable para que las pruebas simulen un sistema de archivos sin permisos.
var chmod = func(f *os.File, m os.FileMode) error { return f.Chmod(m) }

// writeAtomic: temporal 0600 en el mismo directorio, fsync, rename y fsync del directorio.
func writeAtomic(path string, data []byte) error { return writeAtomicOpt(path, data, nil) }

// writeAtomicOpt con noPerms distinto de nil tolera que el sistema de archivos no admita chmod (EPERM o no soportado, p. ej. vfat) y lo anota.
func writeAtomicOpt(path string, data []byte, noPerms *bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := chmod(tmp, 0o600); err != nil {
		if noPerms == nil || !(errors.Is(err, os.ErrPermission) || errors.Is(err, errors.ErrUnsupported)) {
			tmp.Close()
			return fmt.Errorf("vault: %w", err)
		}
		*noPerms = true
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer d.Close()
	return d.Sync()
}
