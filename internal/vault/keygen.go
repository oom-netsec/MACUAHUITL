package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/sshkey"
)

// ErrKeyUnsupported: la llave guardada no es una ed25519 en formato OpenSSH sin frase, la única de la que se deriva la pública aquí.
var ErrKeyUnsupported = i18n.New("vault.err.key_unsupported", nil)

// afterRekey lo usan las pruebas para ver que la privada vieja quedó destruida.
var afterRekey func(old *secret.Secret)

// PublicKey es una pública SSH ed25519 en formato de cable (RFC 4253: string "ssh-ed25519" ‖ string clave de 32 B).
// Este paquete no importa x/crypto/ssh (noegress); el formato lo valida transport en sus pruebas con ssh.ParsePublicKey.
type PublicKey []byte

const keyType = "ssh-ed25519"

func sshString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func wirePub(pub ed25519.PublicKey) PublicKey {
	return PublicKey(sshString(sshString(nil, []byte(keyType)), pub))
}

// Fingerprint es la huella SHA256:… de la pública, como la de ssh-keygen -lf.
func (p PublicKey) Fingerprint() string {
	h := sha256.Sum256(p)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// AuthorizedKey es la línea de authorized_keys con el comentario macuahuitl@<hostname>. El hostname es el de hoy, no se guarda.
func (p PublicKey) AuthorizedKey() string {
	h, _ := os.Hostname()
	typ := keyType
	if len(p) >= 4 {
		if n := binary.BigEndian.Uint32(p); uint64(n) <= uint64(len(p)-4) {
			typ = string(p[4 : 4+n])
		}
	}
	return typ + " " + base64.StdEncoding.EncodeToString(p) + " macuahuitl@" + cleanHost(h)
}

// newKeyPair genera una ed25519 con crypto/rand y devuelve la privada en formato OpenSSH sin frase (openssh-key-v1, el que lee
// transport con ssh.ParsePrivateKey) ya en memoria bloqueada, más la pública. La privada, el cuerpo, el binario y el PEM se arman
// en búferes de medida exacta (ninguno realoca, así no quedan copias huérfanas) y se ponen en ceros; secret.New pone en ceros el PEM.
func newKeyPair() (*secret.Secret, PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	defer wipe(priv)
	var chk [4]byte
	if _, err := rand.Read(chk[:]); err != nil {
		return nil, nil, err
	}
	w := wirePub(pub)
	// Sección privada: checkint ×2, tipo, pública, privada (semilla ‖ pública), comentario vacío y relleno 1,2,3… a múltiplo de 8.
	n := 8 + 4 + len(keyType) + 4 + len(pub) + 4 + len(priv) + 4
	n += (8 - n%8) % 8
	body := make([]byte, 0, n)
	body = append(append(body, chk[:]...), chk[:]...)
	body = sshString(body, []byte(keyType))
	body = sshString(body, pub)
	body = sshString(body, priv)
	body = sshString(body, nil)
	for i := byte(1); len(body)%8 != 0; i++ {
		body = append(body, i)
	}
	defer wipe(body)
	const magic = "openssh-key-v1\x00"
	out := make([]byte, 0, len(magic)+4+4+4+4+8+4+len(w)+4+len(body))
	out = append(out, magic...)
	out = append(out, 0, 0, 0, 4)
	out = append(out, "none"...)
	out = append(out, 0, 0, 0, 4)
	out = append(out, "none"...)
	out = append(out, 0, 0, 0, 0, 0, 0, 0, 1) // kdfoptions vacío, 1 llave
	out = sshString(out, w)
	out = sshString(out, body)
	defer wipe(out)
	return secret.New(armor(out)), w, nil // secret.New pone en ceros el PEM
}

const (
	pemBegin = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
	pemEnd   = "-----END OPENSSH PRIVATE KEY-----\n"
)

// armor es el PEM de der con líneas de 64 columnas, en un búfer de medida exacta (pem.EncodeToMemory crece un bytes.Buffer y deja copias).
func armor(der []byte) []byte {
	n := base64.StdEncoding.EncodedLen(len(der))
	out := make([]byte, len(pemBegin)+n+(n+63)/64+len(pemEnd))
	o := copy(out, pemBegin)
	for len(der) > 0 {
		c := min(len(der), 48)
		base64.StdEncoding.Encode(out[o:], der[:c])
		o += base64.StdEncoding.EncodedLen(c)
		out[o] = '\n'
		o++
		der = der[c:]
	}
	copy(out[o:], pemEnd)
	return out
}

// unarmor decodifica el PEM de una privada OpenSSH sin pasar por encoding/pem (que deja copias del base64 sin poder borrarlas).
// El resultado lo pone en ceros quien llama; cualquier otra cosa da error.
func unarmor(pemBytes []byte) ([]byte, error) {
	lines := bytes.Split(bytes.TrimSpace(pemBytes), []byte("\n"))
	if len(lines) < 3 || string(bytes.TrimSpace(lines[0])) != strings.TrimSpace(pemBegin) || string(bytes.TrimSpace(lines[len(lines)-1])) != strings.TrimSpace(pemEnd) {
		return nil, ErrKeyUnsupported
	}
	b64 := make([]byte, 0, len(pemBytes))
	defer wipe(b64)
	for _, l := range lines[1 : len(lines)-1] {
		b64 = append(b64, bytes.TrimSpace(l)...)
	}
	der := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(der, b64)
	if err != nil {
		wipe(der)
		return nil, ErrKeyUnsupported
	}
	return der[:n], nil
}

// pubOf deriva la pública de una privada openssh-key-v1 ed25519 sin frase y exige que las tres copias coincidan (la de la cabecera,
// la de la sección privada y la derivada de la semilla, que es la que firma); cualquier otra cosa da ErrKeyUnsupported.
func pubOf(pemBytes []byte) (PublicKey, string, error) {
	b, err := unarmor(pemBytes)
	if err != nil {
		return nil, "", err
	}
	defer wipe(b)
	const magic = "openssh-key-v1\x00"
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return nil, "", ErrKeyUnsupported
	}
	b = b[len(magic):]
	next := func() []byte {
		if len(b) < 4 {
			return nil
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(n) > uint64(len(b)-4) {
			return nil
		}
		s := b[4 : 4+n]
		b = b[4+n:]
		return s
	}
	cipher, kdf := string(next()), string(next())
	if cipher != "none" || kdf != "none" {
		return nil, "", ErrKeyUnsupported
	}
	next() // kdfoptions
	if len(b) < 4 || binary.BigEndian.Uint32(b) != 1 {
		return nil, "", ErrKeyUnsupported
	}
	b = b[4:]
	hdr := next() // pública en el encabezado
	b = next()
	if len(b) < 8 {
		return nil, "", ErrKeyUnsupported
	}
	b = b[8:] // checkints
	if string(next()) != keyType {
		return nil, "", ErrKeyUnsupported
	}
	pub := next()
	priv := next()
	comment := next()
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return nil, "", ErrKeyUnsupported
	}
	derived := ed25519.NewKeyFromSeed(priv[:ed25519.SeedSize])
	defer wipe(derived)
	w := wirePub(pub)
	if !bytes.Equal(hdr, w) || !bytes.Equal(priv[ed25519.SeedSize:], pub) || !bytes.Equal(derived[ed25519.SeedSize:], pub) {
		return nil, "", ErrKeyUnsupported
	}
	return w, string(comment), nil // la copia a string solo después de validar
}

// GenerateKey crea una credencial "key" (solo llave ed25519, sin contraseña ni enable) y devuelve su id y su pública.
// La privada nace aquí y solo sale cifrada dentro del respaldo.
func (v *Vault) GenerateKey(label, user string) (string, PublicKey, error) {
	k, pub, err := newKeyPair()
	if err != nil {
		return "", nil, err
	}
	c := Credential{Label: label, Username: user, SSHKey: k}
	defer c.SSHKey.Destroy()
	id, err := v.Put(c)
	if err != nil {
		return "", nil, err
	}
	return id, pub, nil
}

// withKey corre f con la privada guardada de la credencial "id" (bóveda abierta; una ventana de trabajo no basta). f no la guarda.
func (v *Vault) withKey(id string, f func(key []byte) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return err
	}
	i, err := v.find(id)
	if err != nil {
		return err
	}
	c, err := v.decrypt(v.entries[i])
	if err != nil {
		return err
	}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	defer c.SSHKey.Destroy()
	if Reserved(c.Label) {
		return ErrReserved
	}
	if c.SSHKey.Empty() {
		return ErrNoKey
	}
	return f(c.SSHKey.Bytes())
}

// pubWire deriva la pública de una privada guardada: ed25519 OpenSSH con la comprobación estricta de pubOf; ecdsa, RSA y los demás
// formatos legibles sin frase, por sshkey. Lo ilegible o cifrado da ErrKeyUnsupported.
func pubWire(key []byte) (PublicKey, error) {
	if p, _, err := pubOf(key); err == nil {
		return p, nil
	}
	i, err := sshkey.Inspect(key)
	if err != nil {
		return nil, ErrKeyUnsupported
	}
	return PublicKey(i.Wire), nil
}

// PublicKey deriva la pública de la privada guardada (ed25519, ecdsa o RSA sin frase); lo demás (cifradas, basura) da ErrKeyUnsupported.
func (v *Vault) PublicKey(id string) (PublicKey, error) {
	var out PublicKey
	err := v.withKey(id, func(k []byte) (err error) { out, err = pubWire(k); return })
	return out, err
}

// Orígenes de una credencial "key". Informativos: no son un control de seguridad (un .mcvault armado a mano puede decir cualquiera).
const (
	OriginGenerated = "generated"
	OriginImported  = "imported"
)

// originOf: "generated" si es una ed25519 OpenSSH sin frase con el comentario vacío (lo que escribe newKeyPair); cualquier otra llave
// guardada es "imported" (las importadas llevan sshkey.ImportedTag).
func originOf(key []byte) string {
	if _, c, err := pubOf(key); err == nil && c == "" {
		return OriginGenerated
	}
	return OriginImported
}

// ImportKey guarda como credencial "key" una privada que el usuario ya tiene (OpenSSH, PKCS#1, PKCS#8, SEC1 o PEM legado cifrado; pass es la
// frase si va cifrada). Se guarda en OpenSSH sin frase con el comentario sshkey.ImportedTag. Pone en ceros pem y pass al terminar. El análisis
// (bcrypt puede tardar segundos) va fuera de v.mu; solo guardar entra a la bóveda, con la frontera estricta de Put.
func (v *Vault) ImportKey(label, user string, pem, pass []byte) (string, sshkey.Info, error) {
	defer wipe(pem)
	defer wipe(pass)
	if len(pem) > MaxFieldBytes || len(pass) > MaxFieldBytes {
		return "", sshkey.Info{}, ErrFieldTooLong
	}
	v.mu.Lock()
	err := v.requireFull() // comprobación barata: con la bóveda cerrada no se pide la frase; Put la repite
	v.mu.Unlock()
	if err != nil {
		return "", sshkey.Info{}, err
	}
	out, info, err := sshkey.Import(pem, pass)
	if err != nil {
		return "", sshkey.Info{}, importErr(err)
	}
	k := secret.New(out) // pone en ceros out
	defer k.Destroy()
	id, err := v.Put(Credential{Label: label, Username: user, SSHKey: k})
	if err != nil {
		return "", sshkey.Info{}, err
	}
	return id, info, nil
}

var (
	ErrKeyPassphraseRequired = i18n.New("vault.err.key_passphrase_required", nil)
	ErrKeyPassphraseWrong    = i18n.New("vault.err.key_passphrase_wrong", nil)
	ErrKeyImportInvalid      = i18n.New("vault.err.key_import_invalid", nil)
	ErrKeyImportUnsupported  = i18n.New("vault.err.key_import_unsupported", nil)
)

// importErr traduce el error de sshkey a uno con código del catálogo; la metadata (format, type) sale de listas cerradas.
func importErr(err error) error {
	var ke *sshkey.Error
	if !errors.As(err, &ke) {
		return ErrKeyImportInvalid
	}
	switch {
	case errors.Is(err, sshkey.ErrPassphraseRequired):
		return ErrKeyPassphraseRequired
	case errors.Is(err, sshkey.ErrPassphraseWrong):
		return ErrKeyPassphraseWrong
	case errors.Is(err, sshkey.ErrUnsupported):
		return i18n.Wrap("vault.err.key_import_unsupported", ErrKeyImportUnsupported, i18n.A("format", ke.Format, "type", ke.Type))
	}
	return i18n.Wrap("vault.err.key_import_invalid", ErrKeyImportInvalid, i18n.A("format", ke.Format))
}

// RegenerateKey cambia la llave de una credencial "key" conservando id, etiqueta y usuario, en una sola persistencia, y destruye
// la vieja. Devuelve el origen de la llave reemplazada, la pública vieja (nil si la llave no era una ed25519 OpenSSH sin frase) y la nueva (la auditoría guarda ambas huellas).
func (v *Vault) RegenerateKey(id string) (oldPub, newPub PublicKey, prevOrigin string, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return nil, nil, "", err
	}
	i, err := v.find(id)
	if err != nil {
		return nil, nil, "", err
	}
	c, err := v.decrypt(v.entries[i])
	if err != nil {
		return nil, nil, "", err
	}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	if Reserved(c.Label) {
		c.SSHKey.Destroy()
		return nil, nil, "", ErrReserved
	}
	if c.SSHKey.Empty() || !c.Password.Empty() || !c.Enable.Empty() {
		c.SSHKey.Destroy()
		return nil, nil, "", ErrNotKey
	}
	old, err := pubWire(c.SSHKey.Bytes())
	if err != nil {
		old = nil // llave de antes de la fase 44 (RSA, ECDSA, cifrada…): se reemplaza igual, sin huella vieja
	}
	k, pub, err := newKeyPair()
	if err != nil {
		c.SSHKey.Destroy()
		return nil, nil, "", err
	}
	prevOrigin = originOf(c.SSHKey.Bytes())
	oldKey := c.SSHKey
	c.SSHKey = k
	_, err = v.putBatchLocked([]Credential{c}, false, true)
	k.Destroy()
	oldKey.Destroy()
	if afterRekey != nil {
		afterRekey(oldKey)
	}
	if err != nil {
		return nil, nil, "", err
	}
	return old, pub, prevOrigin, nil
}

// cleanHost deja solo [A-Za-z0-9._-]; si no queda nada, "localhost".
func cleanHost(h string) string {
	var b strings.Builder
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "localhost"
	}
	return b.String()
}
