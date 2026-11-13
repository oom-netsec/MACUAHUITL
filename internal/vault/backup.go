package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Un respaldo es un archivo de bóveda nuevo (mismo formato) con su propio VaultID, su propia sal y una DEK nueva sellada con la frase del respaldo:
// no comparte llaves con la bóveda viva, así que una frase débil en el respaldo no la compromete. No hay criptografía aparte de la de este paquete.
var (
	ErrNotBackup    = i18n.New("vault.err.not_backup", nil)
	ErrShortPhrase  = i18n.New("vault.err.short_phrase", nil)
	ErrSamePhrase   = i18n.New("vault.err.same_phrase", nil)
	ErrBackupExists = i18n.New("vault.err.backup_exists", nil)
	ErrNotRegular   = i18n.New("vault.err.not_regular", nil)
)

var ErrBackupParams = i18n.New("vault.err.backup_params", nil)

// MaxBackupEntries acota las credenciales de un respaldo que se abre.
const MaxBackupEntries = 10000

var ErrTooManyEntries = i18n.New("vault.err.too_many", nil)

// deriveFn es variable para que las pruebas vean cuándo se deriva y desde qué lock.
var deriveFn = deriveKEK

// backupParamsOK dice si un respaldo con esos parámetros se puede abrir después (los mismos topes de OpenBackup).
func backupParamsOK(p Params) bool {
	return p.MemoryKiB <= SealMaxMemoryKiB && p.Threads <= sealMaxThreads
}

// MinBackupPhrase es el largo mínimo (en caracteres) de la frase de un respaldo.
const MinBackupPhrase = 12

// maxBackupBytes acota lo que se lee de un archivo que llega de fuera.
const maxBackupBytes = 64 << 20

// Params devuelve los parámetros de Argon2id de la bóveda.
func (v *Vault) Params() Params {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.hdr.Params
}

// Matches dice si master es la contraseña de esta bóveda, sin cambiar su estado de bloqueo ni dejar la DEK en memoria. No borra master.
// La cabecera se copia bajo el lock y el Argon2 corre fuera de él: un Lock() concurrente no espera.
func (v *Vault) Matches(master []byte) bool {
	if len(master) == 0 {
		return false
	}
	v.mu.Lock()
	h := v.hdr
	v.mu.Unlock()
	dek, err := openDEKWith(h, master)
	if err != nil {
		return false
	}
	dek.Destroy()
	return true
}

// WriteBackup escribe en dst un respaldo cifrado con phrase (que se pone en ceros) con todas las credenciales no reservadas de src,
// que debe estar abierta. Devuelve cuántas guardó. dst queda 0600; sin overwrite no pisa nada y nunca sigue un enlace simbólico;
// se arma en una carpeta temporal contigua y se mueve con rename, así un fallo no deja un respaldo a medias.
func WriteBackup(src *Vault, dst string, phrase []byte, overwrite bool) (int, error) {
	n, _, err := WriteBackupWarn(src, dst, phrase, overwrite)
	return n, err
}

// WriteBackupWarn es WriteBackup que además dice si el sistema de archivos no admitió los permisos 0600 (p. ej. una memoria vfat): el
// respaldo se escribe igual, ya va cifrado, y quien llama debe avisarlo.
func WriteBackupWarn(src *Vault, dst string, phrase []byte, overwrite bool) (int, bool, error) {
	defer wipe(phrase)
	// Primero la bóveda abierta: cerrada, la frase ni se evalúa y no hay forma de probar la maestra sin el registro de un unlock fallido.
	if !src.Unlocked() {
		return 0, false, ErrLocked
	}
	if !backupParamsOK(src.Params()) {
		return 0, false, ErrBackupParams
	}
	if utf8.RuneCount(phrase) < MinBackupPhrase {
		return 0, false, ErrShortPhrase
	}
	if src.Matches(phrase) {
		return 0, false, ErrSamePhrase
	}
	infos, err := src.List()
	if err != nil {
		return 0, false, err
	}
	creds := make([]Credential, 0, len(infos))
	defer func() {
		for _, c := range creds {
			c.Password.Destroy()
			c.Enable.Destroy()
			c.SSHKey.Destroy()
		}
	}()
	for _, i := range infos {
		c, err := src.Get(i.ID)
		if err != nil {
			return 0, false, err
		}
		c.ID = "" // el respaldo asigna IDs propios
		creds = append(creds, c)
	}
	dir, err := os.MkdirTemp(filepath.Dir(dst), ".respaldo-*") // 0700; se lleva también el .bak de la bóveda temporal
	if err != nil {
		return 0, false, fmt.Errorf("vault: %w", err)
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, "respaldo.mcvault")
	b, err := create(tmp, phrase, src.Params(), true) // tolera un sistema de archivos sin permisos
	if err != nil {
		return 0, false, err
	}
	defer b.LockAll()
	if _, err := b.PutBatch(creds); err != nil {
		return 0, false, err
	}
	if err := place(tmp, dst, overwrite); err != nil {
		return 0, false, err
	}
	return len(creds), b.noPerms, nil
}

// place mueve tmp a dst. Sin overwrite reserva dst con O_EXCL|O_NOFOLLOW (no pisa nada ni sigue enlaces) y lo reemplaza con rename; con overwrite solo reemplaza un archivo regular (o un enlace, no su destino).
func place(tmp, dst string, overwrite bool) error {
	reserved := false
	if !overwrite {
		f, err := sys.OpenNew(dst)
		if errors.Is(err, fs.ErrExist) {
			return ErrBackupExists
		}
		if err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		f.Close()
		reserved = true
	} else if fi, err := os.Lstat(dst); err == nil && !fi.Mode().IsRegular() && fi.Mode()&fs.ModeSymlink == 0 {
		return ErrNotRegular
	}
	if err := os.Rename(tmp, dst); err != nil {
		if reserved {
			os.Remove(dst)
		}
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

// OpenBackup abre el respaldo (o bóveda) en path y lo desbloquea con phrase, que se pone en ceros. Un archivo que no tenga el formato da
// ErrNotBackup; una frase incorrecta, ErrWrongPassword. Quien llama hace LockAll al terminar para soltar la DEK.
func OpenBackup(path string, phrase []byte) (*Vault, error) {
	defer wipe(phrase)
	f, err := sys.OpenRegular(path)
	if errors.Is(err, sys.ErrNotRegular) {
		return nil, ErrNotBackup
	}
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBackupBytes+1))
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	if len(raw) > maxBackupBytes {
		return nil, ErrNotBackup
	}
	h, entries, err := parseFile(raw)
	// Los parámetros vienen del archivo: se acotan antes de derivar, como en los sobres sueltos.
	if err != nil || !backupParamsOK(h.Params) {
		return nil, ErrNotBackup
	}
	// Y las entradas, antes de descifrar ninguna: cada una pide memoria bloqueada.
	if len(entries) > MaxBackupEntries {
		return nil, ErrTooManyEntries
	}
	v := &Vault{hdr: h, entries: entries, now: time.Now, windows: map[string]Window{}} // sin path: no se escribe de vuelta
	if err := v.Unlock(phrase); err != nil {
		return nil, err
	}
	return v, nil
}
