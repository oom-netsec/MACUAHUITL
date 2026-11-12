package radiustest

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	//lint:ignore SA1019 MS-CHAPv2 (RFC 2759) exige MD4: compatibilidad con el servidor, no seguridad propia
	"golang.org/x/crypto/md4"
)

// Códigos de paquete (RFC 2865 §3, RFC 2866 §3, RFC 5997).
const (
	AccessRequest      byte = 1
	AccessAccept       byte = 2
	AccessReject       byte = 3
	AccountingRequest  byte = 4
	AccountingResponse byte = 5
	AccessChallenge    byte = 11
	StatusServer       byte = 12
)

// Atributos que el probador escribe.
const (
	AttrUserName             byte = 1
	AttrUserPassword         byte = 2
	AttrCHAPPassword         byte = 3
	AttrNASIPAddress         byte = 4
	AttrServiceType          byte = 6
	AttrReplyMessage         byte = 18
	AttrVendorSpecific       byte = 26
	AttrCalledStationID      byte = 30
	AttrCallingStationID     byte = 31
	AttrNASIdentifier        byte = 32
	AttrAcctStatusType       byte = 40
	AttrAcctSessionID        byte = 44
	AttrAcctSessionTime      byte = 46
	AttrCHAPChallenge        byte = 60
	AttrNASPortType          byte = 61
	AttrMessageAuthenticator byte = 80
)

const (
	headerLen = 20
	maxPacket = 4096 // RFC 2865 §3
)

type Attr struct {
	Type  byte
	Value []byte
}

type Packet struct {
	Code          byte
	ID            byte
	Authenticator [16]byte
	Attrs         []Attr
}

func (p *Packet) Add(t byte, v []byte) { p.Attrs = append(p.Attrs, Attr{t, v}) }

// Get devuelve el primer atributo de tipo t.
func (p *Packet) Get(t byte) ([]byte, bool) {
	for _, a := range p.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// Encode serializa tal cual, sin calcular autenticadores.
func (p *Packet) Encode() []byte {
	b := make([]byte, headerLen, maxPacket)
	b[0], b[1] = p.Code, p.ID
	copy(b[4:20], p.Authenticator[:])
	for _, a := range p.Attrs {
		b = append(b, a.Type, byte(len(a.Value)+2))
		b = append(b, a.Value...)
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

// Decode valida longitudes de paquete y atributos antes de confiar en ellas.
func Decode(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, errors.New("radius: paquete de menos de 20 bytes")
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l < headerLen || l > maxPacket || l > len(b) {
		return nil, fmt.Errorf("radius: longitud %d inválida (recibidos %d bytes)", l, len(b))
	}
	p := &Packet{Code: b[0], ID: b[1]}
	copy(p.Authenticator[:], b[4:20])
	rest := b[headerLen:l] // RFC 2865 §3: los bytes después de Length se ignoran
	for len(rest) > 0 {
		if len(rest) < 2 || rest[1] < 2 || int(rest[1]) > len(rest) {
			return nil, errors.New("radius: atributo con longitud inválida")
		}
		p.Attrs = append(p.Attrs, Attr{rest[0], append([]byte(nil), rest[2:rest[1]]...)})
		rest = rest[rest[1]:]
	}
	return p, nil
}

func md5sum(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// EncodeWithMA agrega Message-Authenticator como primer atributo (RFC 5080 y la
// mitigación de Blast-RADIUS, CVE-2024-3596) y lo calcula sobre el paquete con el
// campo en ceros y el autenticador de petición (RFC 3579 §3.2).
func (p *Packet) EncodeWithMA(secret []byte) []byte {
	q := *p
	q.Attrs = append([]Attr{{AttrMessageAuthenticator, make([]byte, 16)}}, p.Attrs...)
	b := q.Encode()
	m := hmac.New(md5.New, secret)
	m.Write(b)
	copy(b[headerLen+2:headerLen+18], m.Sum(nil))
	return b
}

// maOffset ubica el valor de Message-Authenticator en un paquete ya validado.
func maOffset(b []byte) int {
	for i := headerLen; i+2 <= len(b) && b[i+1] >= 2; i += int(b[i+1]) {
		if b[i] == AttrMessageAuthenticator && b[i+1] == 18 {
			return i + 2
		}
	}
	return -1
}

// checkMA verifica Message-Authenticator calculándolo con auth en el campo
// Authenticator: el de la petición para respuestas (RFC 3579 §3.2).
func checkMA(b, secret []byte, auth [16]byte) bool {
	off := maOffset(b)
	if off < 0 {
		return false
	}
	c := append([]byte(nil), b...)
	copy(c[4:20], auth[:])
	got := append([]byte(nil), c[off:off+16]...)
	clear(c[off : off+16])
	m := hmac.New(md5.New, secret)
	m.Write(c)
	return hmac.Equal(got, m.Sum(nil))
}

// SignResponse arma una respuesta con Response Authenticator (RFC 2865 §3); si
// trae Message-Authenticator, lo calcula antes. Lo usan los servidores de prueba.
func (p *Packet) SignResponse(reqAuth [16]byte, secret []byte) []byte {
	q := *p
	q.Authenticator = reqAuth
	b := q.Encode()
	if off := maOffset(b); off >= 0 {
		clear(b[off : off+16])
		m := hmac.New(md5.New, secret)
		m.Write(b)
		copy(b[off:], m.Sum(nil))
	}
	copy(b[4:20], md5sum(b, secret))
	return b
}

// verifyResponse: MD5(Code‖ID‖Length‖RequestAuth‖Attributes‖Secret).
func verifyResponse(b []byte, reqAuth [16]byte, secret []byte) bool {
	c := append([]byte(nil), b...)
	copy(c[4:20], reqAuth[:])
	return hmac.Equal(b[4:20], md5sum(c, secret))
}

// SignAccounting: Request Authenticator de RFC 2866 §3, sobre 16 ceros.
func (p *Packet) SignAccounting(secret []byte) []byte {
	q := *p
	q.Authenticator = [16]byte{}
	b := q.Encode()
	copy(b[4:20], md5sum(b, secret))
	return b
}

func verifyAccountingRequest(b, secret []byte) bool {
	return verifyResponse(b, [16]byte{}, secret)
}

// papHide cifra User-Password (RFC 2865 §5.2): bloques de 16 con relleno de ceros,
// cada uno XOR MD5(secreto ‖ bloque cifrado anterior), empezando por el autenticador.
func papHide(pw, secret []byte, auth [16]byte) []byte {
	n := (len(pw) + 15) / 16 * 16
	if n == 0 {
		n = 16
	}
	out := make([]byte, n)
	copy(out, pw)
	prev := auth[:]
	for i := 0; i < n; i += 16 {
		k := md5sum(secret, prev)
		for j := range 16 {
			out[i+j] ^= k[j]
		}
		prev = out[i : i+16]
	}
	return out
}

func chapResponse(ident byte, pw, challenge []byte) []byte {
	return append([]byte{ident}, md5sum([]byte{ident}, pw, challenge)...)
}

// ---- MS-CHAPv2 (RFC 2759) ----

func challengeHash(peer, auth []byte, user string) []byte {
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(user))
	return h.Sum(nil)[:8]
}

func ntPasswordHash(pw []byte) []byte {
	u := utf16.Encode([]rune(string(pw)))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	defer clear(b)
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// desKey expande 7 bytes a una llave DES de 8 (la paridad la ignora crypto/des).
func desKey(s []byte) []byte {
	return []byte{
		s[0] &^ 1, s[0]<<7 | s[1]>>1, s[1]<<6 | s[2]>>2, s[2]<<5 | s[3]>>3,
		s[3]<<4 | s[4]>>4, s[4]<<3 | s[5]>>5, s[5]<<2 | s[6]>>6, s[6] << 1,
	}
}

func ntResponse(authCh, peerCh []byte, user string, pw []byte) []byte {
	ch := challengeHash(peerCh, authCh, user)
	z := make([]byte, 21)
	copy(z, ntPasswordHash(pw))
	defer clear(z)
	out := make([]byte, 0, 24)
	for i := 0; i < 21; i += 7 {
		c, _ := des.NewCipher(desKey(z[i : i+7]))
		blk := make([]byte, 8)
		c.Encrypt(blk, ch)
		out = append(out, blk...)
	}
	return out
}

func authenticatorResponse(pw, nt, peerCh, authCh []byte, user string) string {
	const magic1 = "Magic server to client signing constant"
	const magic2 = "Pad to make it do more than one iteration"
	hh := md4.New()
	hh.Write(ntPasswordHash(pw))
	d := sha1.New()
	d.Write(hh.Sum(nil))
	d.Write(nt)
	d.Write([]byte(magic1))
	d2 := sha1.New()
	d2.Write(d.Sum(nil))
	d2.Write(challengeHash(peerCh, authCh, user))
	d2.Write([]byte(magic2))
	return "S=" + strings.ToUpper(fmt.Sprintf("%x", d2.Sum(nil)))
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
