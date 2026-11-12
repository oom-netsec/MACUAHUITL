package radiustest

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 2865 §7.1: Access-Request de "nemo"/"arctangent" con secreto "xyzzy5461".
const (
	rfcSecret  = "xyzzy5461"
	rfcRequest = "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8 01 10 05 06 00 00 00 03"
)

func TestPAPMatchesRFC2865Example(t *testing.T) {
	req := unhex(t, rfcRequest)
	var auth [16]byte
	copy(auth[:], req[4:20])
	got := papHide([]byte("arctangent"), []byte(rfcSecret), auth)
	if want := unhex(t, "0d be 70 8d 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee"); !bytes.Equal(got, want) {
		t.Fatalf("User-Password = %x, want %x", got, want)
	}
	// Contraseñas de más de 16 bytes encadenan el bloque anterior (RFC 2865 §5.2).
	// Vector calculado a mano: c1 = p1 XOR MD5(S‖RA), c2 = p2 XOR MD5(S‖c1).
	pw := []byte("0123456789abcdefWXYZ")
	padded := append(append([]byte(nil), pw...), make([]byte, 12)...)
	b1 := md5.Sum(append([]byte(rfcSecret), auth[:]...))
	want := make([]byte, 32)
	for i := range 16 {
		want[i] = padded[i] ^ b1[i]
	}
	b2 := md5.Sum(append([]byte(rfcSecret), want[:16]...))
	for i := range 16 {
		want[16+i] = padded[16+i] ^ b2[i]
	}
	if long := papHide(pw, []byte(rfcSecret), auth); !bytes.Equal(long, want) {
		t.Fatalf("PAP 20 bytes:\n%x\n%x", long, want)
	}
}

func TestEncodeDecodeRFC2865Example(t *testing.T) {
	req := unhex(t, rfcRequest)
	p, err := Decode(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Code != AccessRequest || p.ID != 0 || len(p.Attrs) != 4 || string(p.Attrs[0].Value) != "nemo" {
		t.Fatalf("decoded = %+v", p)
	}
	if b := p.Encode(); !bytes.Equal(b, req) {
		t.Fatalf("re-encode:\n%x\n%x", b, req)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	req := unhex(t, rfcRequest)
	bad := map[string][]byte{
		"corto":            req[:10],
		"longitud mayor":   append(append([]byte{}, req[:2]...), append([]byte{0x10, 0x00}, req[4:]...)...),
		"atributo largo 1": append(append([]byte{1, 0, 0, 22}, req[4:20]...), 1, 1),
		"atributo excede":  append(append([]byte{1, 0, 0, 23}, req[4:20]...), 1, 9, 0),
	}
	for name, b := range bad {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
}

func TestMessageAuthenticatorRoundTrip(t *testing.T) {
	p := &Packet{Code: AccessRequest, ID: 7}
	p.Add(AttrUserName, []byte("u"))
	secret := []byte("s3cr3t")
	b := p.EncodeWithMA(secret)
	q, _ := Decode(b)
	if q.Attrs[0].Type != AttrMessageAuthenticator {
		t.Fatal("Message-Authenticator debe ir primero (RFC 5080/Blast-RADIUS)")
	}
	if !checkMA(b, secret, q.Authenticator) {
		t.Fatal("MA no verifica")
	}
	b[len(b)-1] ^= 1
	if checkMA(b, secret, q.Authenticator) {
		t.Fatal("MA verifica tras alterar el paquete")
	}
}

func TestResponseAuthenticator(t *testing.T) {
	secret := []byte("s")
	var reqAuth [16]byte
	reqAuth[0] = 9
	resp := &Packet{Code: AccessAccept, ID: 3}
	resp.Add(AttrReplyMessage, []byte("hola"))
	b := resp.SignResponse(reqAuth, secret)
	if !verifyResponse(b, reqAuth, secret) {
		t.Fatal("respuesta firmada no verifica")
	}
	if verifyResponse(b, reqAuth, []byte("otro")) {
		t.Fatal("verifica con otro secreto")
	}
}

func TestAccountingRequestAuthenticator(t *testing.T) {
	p := &Packet{Code: AccountingRequest, ID: 1}
	p.Add(AttrAcctStatusType, u32(1))
	b := p.SignAccounting([]byte("s"))
	if !verifyAccountingRequest(b, []byte("s")) || verifyAccountingRequest(b, []byte("x")) {
		t.Fatal("autenticador de accounting")
	}
}

func TestCHAP(t *testing.T) {
	// CHAP-Password = ident ‖ MD5(ident ‖ password ‖ challenge) (RFC 1994, RFC 2865 §5.3).
	ch := []byte("0123456789abcdef")
	got := chapResponse(5, []byte("pw"), ch)
	if len(got) != 17 || got[0] != 5 {
		t.Fatalf("chap = %x", got)
	}
	if !bytes.Equal(got[1:], md5sum([]byte{5}, []byte("pw"), ch)) {
		t.Fatal("hash")
	}
}

// RFC 2759 §9.2.
func TestMSCHAPv2RFC2759Vectors(t *testing.T) {
	authCh := unhex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peerCh := unhex(t, "21402324255E262A28295F2B3A337C7E")
	if c := challengeHash(peerCh, authCh, "User"); !bytes.Equal(c, unhex(t, "D02E4386BCE91226")) {
		t.Fatalf("ChallengeHash = %X", c)
	}
	if h := ntPasswordHash([]byte("clientPass")); !bytes.Equal(h, unhex(t, "44EBBA8D5312B8D611474411F56989AE")) {
		t.Fatalf("PasswordHash = %X", h)
	}
	nt := ntResponse(authCh, peerCh, "User", []byte("clientPass"))
	if !bytes.Equal(nt, unhex(t, "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")) {
		t.Fatalf("NT-Response = %X", nt)
	}
	if s := authenticatorResponse([]byte("clientPass"), nt, peerCh, authCh, "User"); s != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatalf("AuthenticatorResponse = %s", s)
	}
}
