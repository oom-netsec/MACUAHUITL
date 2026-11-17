// Package sshkey comprueba que una llave privada SSH se puede leer con x/crypto/ssh, igual que transport.OpenSSH al conectar.
//
// Existe aparte para que vault y core la validen sin importar x/crypto/ssh (noegress lo prohíbe fuera de la lista de permitidos):
// este paquete solo analiza llaves (Parse, Check, Import), no abre sockets. No hace: conectar, ni guardar nada.
package sshkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Parse devuelve error si key no es una llave privada que x/crypto/ssh pueda usar sin frase (una con frase tampoco sirve a transport)
// o si Check no la admite (la política única de la frontera de la bóveda y del import).
func Parse(key []byte) error {
	k, err := ssh.ParseRawPrivateKey(key)
	if err != nil {
		return err
	}
	defer wipeKey(k)
	_, err = Check(k)
	return err
}

// ---- Fase 47: importar una llave existente ----

// Errores de Import. Cada uno viaja dentro de *Error, que añade el formato intentado o el tipo rechazado. Ninguno lleva texto de x/crypto
// (podría citar bytes de la llave o de la frase).
var (
	ErrPassphraseRequired = errors.New("sshkey: la llave está cifrada y falta la frase")
	ErrPassphraseWrong    = errors.New("sshkey: la frase no descifra la llave")
	ErrInvalid            = errors.New("sshkey: no es una llave privada legible")
	ErrUnsupported        = errors.New("sshkey: tipo de llave no soportado")
)

// Error es un ErrXxx con el dato que la UI y mctl muestran: Format (formato que se intentó) o Type (tipo rechazado).
type Error struct {
	Err          error
	Format, Type string
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Info describe una llave aceptada. Wire es la pública en formato de cable (RFC 4253).
type Info struct {
	Algorithm   string // ssh-ed25519, ecdsa-sha2-nistp256|384|521, ssh-rsa
	Bits        int
	Weak        bool // RSA de menos de 3072 bits
	Fingerprint string
	Wire        []byte
}

// maxRounds es el tope de rondas de bcrypt que Import acepta (ssh-keygen usa 16 por omisión; más es un archivo hostil o absurdo).
const maxRounds = 2048

// container lee lo que se puede de una llave openssh-key-v1 sin descifrar: el tipo (de la pública del encabezado, que va en claro aun con
// frase), las rondas de bcrypt (0 si el kdf no es bcrypt) y, solo sin cifrar, el comentario. Para otros formatos ok es falso.
func container(b *pem.Block) (typ, comment string, rounds uint32, ok bool) {
	if b == nil || b.Type != "OPENSSH PRIVATE KEY" {
		return
	}
	d := b.Bytes
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(d, []byte(magic)) {
		return
	}
	d = d[len(magic):]
	next := func() []byte {
		if len(d) < 4 {
			return nil
		}
		n := binary.BigEndian.Uint32(d)
		if uint64(n) > uint64(len(d)-4) {
			return nil
		}
		s := d[4 : 4+n]
		d = d[4+n:]
		return s
	}
	cipher := string(next())
	kdf := string(next())
	if o := next(); kdf == "bcrypt" { // kdfoptions: string sal, uint32 rondas
		if len(o) >= 4 {
			if n := binary.BigEndian.Uint32(o); uint64(n) <= uint64(len(o)-4) && len(o)-4-int(n) >= 4 {
				rounds = binary.BigEndian.Uint32(o[4+n:])
			}
		}
	}
	if len(d) < 4 {
		return
	}
	d = d[4:] // número de llaves
	h := next()
	if len(h) < 4 {
		return
	}
	tl := binary.BigEndian.Uint32(h)
	if uint64(tl) > uint64(len(h)-4) {
		return
	}
	typ, ok = string(h[4:4+tl]), true
	if cipher != "none" {
		return typ, "", rounds, true
	}
	priv := next()
	if len(priv) < 8 {
		return
	}
	d = priv[8:]
	next() // tipo
	n := map[string]int{"ssh-ed25519": 2, "ssh-rsa": 6}[typ]
	if strings.HasPrefix(typ, "ecdsa-sha2-") {
		n = 3
	}
	if n == 0 {
		return typ, "", rounds, true
	}
	for i := 0; i < n; i++ {
		next()
	}
	return typ, string(next()), rounds, true
}

func unsupported(typ string) error { return &Error{Err: ErrUnsupported, Type: typ} }

// Check es la política única de llaves: ed25519, ECDSA P-256/384/521 y RSA de 1024 a 16384 bits (weak por debajo de 3072). Vale para
// la importación y para la frontera estricta de la bóveda (ValidateKey), así que también para lo que entra por un .mcvault.
func Check(key any) (Info, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		key = *k
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
		case "P-224":
			return Info{}, unsupported("ecdsa-p224")
		default:
			return Info{}, unsupported("other")
		}
	case *rsa.PrivateKey:
		if b := k.N.BitLen(); b < 1024 {
			return Info{}, unsupported("rsa-small")
		} else if b > 16384 {
			return Info{}, unsupported("rsa-large")
		}
	case ed25519.PrivateKey:
	default:
		return Info{}, unsupported("other")
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return Info{}, unsupported("other")
	}
	pub := s.PublicKey()
	i := Info{Algorithm: pub.Type(), Fingerprint: ssh.FingerprintSHA256(pub), Wire: pub.Marshal(), Bits: 256}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		i.Bits = k.N.BitLen()
		i.Weak = i.Bits < 3072
	case *ecdsa.PrivateKey:
		i.Bits = k.Curve.Params().BitSize
	}
	return i, nil
}

// Inspect describe una llave guardada (OpenSSH sin frase, la forma que deja Import y GenerateKey).
func Inspect(openssh []byte) (Info, error) {
	key, err := ssh.ParseRawPrivateKey(openssh)
	if err != nil {
		return Info{}, &Error{Err: ErrInvalid}
	}
	defer wipeKey(key)
	return Check(key)
}

// ImportedTag es el comentario del contenedor OpenSSH de toda llave importada; origin se deriva de él (una generada lo lleva vacío).
const ImportedTag = "macuahuitl:imported"

func wipe(b []byte) { clear(b) }

// wipeKey pone en ceros lo que se pueda de una privada ya parseada (mejor esfuerzo: x/crypto y x509 dejan otras copias).
func wipeKey(key any) {
	zero := func(b *big.Int) {
		if b != nil {
			clear(b.Bits())
		}
	}
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		wipe(*k)
	case ed25519.PrivateKey:
		wipe(k)
	case *rsa.PrivateKey:
		zero(k.D)
		for _, p := range k.Primes {
			zero(p)
		}
	case *ecdsa.PrivateKey:
		//lint:ignore SA1019 borrado de mejor esfuerzo de una llave que ya no se usa
		zero(k.D)
	}
}

// dekValid: DEK-Info del PEM legado, "CIFRADO,IV-en-hex", con un cifrado de la lista cerrada y el IV del largo del bloque.
func dekValid(v string) bool {
	alg, iv, ok := strings.Cut(v, ",")
	n := map[string]int{"DES-CBC": 8, "DES-EDE3-CBC": 8, "AES-128-CBC": 16, "AES-192-CBC": 16, "AES-256-CBC": 16}[alg]
	b, err := hex.DecodeString(iv)
	return ok && n != 0 && err == nil && len(b) == n
}

// formatOf es el formato de un bloque PEM, de una lista cerrada (va a la metadata del error).
func formatOf(b *pem.Block) string {
	legacy := b.Headers["DEK-Info"] != ""
	switch b.Type {
	case "OPENSSH PRIVATE KEY":
		return "openssh"
	case "ENCRYPTED PRIVATE KEY":
		return "pkcs8-encrypted"
	case "PRIVATE KEY":
		return "pkcs8"
	case "RSA PRIVATE KEY", "EC PRIVATE KEY":
		if legacy {
			return "pem-legacy"
		}
		return map[string]string{"RSA PRIVATE KEY": "pkcs1", "EC PRIVATE KEY": "sec1"}[b.Type]
	}
	return "other"
}

// typeOf es el tipo rechazado a partir del tipo de la pública del encabezado OpenSSH, de una lista cerrada; "" si se acepta.
func typeOf(t string) string {
	switch {
	case t == "ssh-dss":
		return "ssh-dss"
	case strings.HasPrefix(t, "sk-ecdsa"):
		return "sk-ecdsa"
	case strings.HasPrefix(t, "sk-ssh-ed25519"):
		return "sk-ed25519"
	case strings.HasPrefix(t, "sk-"):
		return "other"
	}
	return ""
}

const (
	pemBegin = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
	pemEnd   = "-----END OPENSSH PRIVATE KEY-----\n"
)

// armor es el PEM OpenSSH de der con líneas de 64 columnas, en un búfer de medida exacta (pem.EncodeToMemory deja copias).
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

// Import lee una privada de cualquier formato aceptado (OpenSSH, PKCS#1, PKCS#8, SEC1 y PEM legado cifrado; con frase si va cifrada) y la
// devuelve en OpenSSH sin frase con el comentario ImportedTag. El comentario original no se conserva (x/crypto lo descarta). Orden: tipo
// de PEM, tipo de la pública del encabezado OpenSSH (DSA y sk-* se rechazan antes de pedir la frase), análisis, política Check.
// Una frase de más con una llave sin cifrar se ignora. Los errores nunca citan el texto de x/crypto (trae cadenas del archivo).
func Import(pemBytes, passphrase []byte) ([]byte, Info, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, Info{}, &Error{Err: ErrInvalid, Format: "other"}
	}
	defer wipe(blk.Bytes)
	format := formatOf(blk)
	bad := func(e error) error { return &Error{Err: e, Format: format} }
	switch blk.Type {
	case "DSA PRIVATE KEY":
		return nil, Info{}, &Error{Err: ErrUnsupported, Format: format, Type: "ssh-dss"}
	case "ENCRYPTED PRIVATE KEY": // PKCS#8 cifrada: x/crypto no la lee; el usuario la convierte con ssh-keygen -p
		return nil, Info{}, &Error{Err: ErrUnsupported, Format: format, Type: "other"}
	}
	if typ, _, rounds, ok := container(blk); ok {
		if t := typeOf(typ); t != "" {
			return nil, Info{}, &Error{Err: ErrUnsupported, Format: format, Type: t}
		}
		if rounds > maxRounds { // antes de pedir la frase
			return nil, Info{}, &Error{Err: ErrUnsupported, Format: format, Type: "other"}
		}
	}
	// Proc-Type ENCRYPTED sin un DEK-Info válido sobre RSA o EC: se rechaza antes de pedir la frase.
	if format != "pem-legacy" && strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, Info{}, bad(ErrInvalid)
	}
	if format == "pem-legacy" && !dekValid(blk.Headers["DEK-Info"]) {
		return nil, Info{}, bad(ErrInvalid)
	}
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	var miss *ssh.PassphraseMissingError
	if errors.As(err, &miss) {
		if len(passphrase) == 0 {
			return nil, Info{}, bad(ErrPassphraseRequired)
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
		if err != nil && (errors.Is(err, x509.IncorrectPasswordError) || format == "pem-legacy") {
			return nil, Info{}, bad(ErrPassphraseWrong) // en PEM legado, todo fallo tras descifrar es frase mala
		}
	}
	if err != nil {
		return nil, Info{}, bad(ErrInvalid)
	}
	defer wipeKey(key)
	info, err := Check(key)
	if err != nil {
		var ke *Error
		if errors.As(err, &ke) {
			ke.Format = format
		}
		return nil, Info{}, err
	}
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}
	out, err := ssh.MarshalPrivateKey(key, ImportedTag)
	if err != nil {
		return nil, Info{}, bad(ErrInvalid)
	}
	defer wipe(out.Bytes)
	return armor(out.Bytes), info, nil
}
