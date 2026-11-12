package radiustest

import (
	"bytes"
	"net"
	"sync"
)

// FakeConfig arma un servidor RADIUS mínimo en loopback para las pruebas de este
// paquete, del núcleo y de mctl. No es un servidor de producción.
type FakeConfig struct {
	Secret        string
	Users         map[string]string
	Reply         []Attr // atributos del Access-Accept
	ChallengeUser string // a este usuario se le responde Access-Challenge
	IgnoreMA      bool   // no exigir Message-Authenticator en la petición
	NoReplyMA     bool   // responder sin Message-Authenticator (servidor sin parche Blast-RADIUS)
	ReplySecret   string // firmar las respuestas con otro secreto
	PadReply      int    // bytes extra tras Length (RFC 2865 §3: el receptor los ignora)
	BadMSSuccess  bool   // MS-CHAP2-Success que no verifica (servidor que no conoce la contraseña)
	SpoofFirst    bool   // antes de la respuesta real, manda una falsificada (otro secreto)
}

// AuthzReply es una autorización típica de ISE: VLAN 10, ACL y nivel de privilegio.
func AuthzReply() []Attr {
	return []Attr{
		{64, []byte{0, 0, 0, 13}}, {65, []byte{0, 0, 0, 6}}, {81, []byte("10")},
		{AttrVendorSpecific, vsa(9, 1, []byte("shell:priv-lvl=15"))},
		{AttrVendorSpecific, vsa(9, 1, []byte("url-redirect-acl=ACL-REDIR"))},
		{11, []byte("PERMIT-ALL.in")}, {27, u32(3600)}, {25, []byte("CACS:0a0000050001")},
	}
}

type Fake struct {
	cfg  FakeConfig
	conn net.PacketConn
	mu   sync.Mutex
	last *Packet
	from net.Addr // solo lo usa la goroutine de serve
	wg   sync.WaitGroup
}

func StartFake(cfg FakeConfig) (*Fake, error) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Fake{cfg: cfg, conn: c}
	f.wg.Add(1)
	go f.serve()
	return f, nil
}

func (f *Fake) Addr() string { return f.conn.LocalAddr().String() }

func (f *Fake) Close() { f.conn.Close(); f.wg.Wait() }

// Last es la última petición recibida y aceptada.
func (f *Fake) Last() *Packet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *Fake) serve() {
	defer f.wg.Done()
	buf := make([]byte, maxPacket)
	for {
		n, from, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		req, err := Decode(raw)
		if err != nil {
			continue
		}
		f.from = from
		if out := f.handle(raw, req); out != nil {
			f.mu.Lock()
			f.last = req
			f.mu.Unlock()
			f.conn.WriteTo(append(out, make([]byte, f.cfg.PadReply)...), from)
		}
	}
}

func (f *Fake) handle(raw []byte, req *Packet) []byte {
	if f.cfg.SpoofFirst {
		forged := &Packet{Code: AccessAccept, ID: req.ID}
		forged.Add(AttrReplyMessage, []byte("falsificada"))
		f.conn.WriteTo(forged.SignResponse(req.Authenticator, []byte("falso")), f.from)
	}
	secret := []byte(f.cfg.Secret)
	sign := secret
	if f.cfg.ReplySecret != "" {
		sign = []byte(f.cfg.ReplySecret)
	}
	resp := &Packet{ID: req.ID}
	if !f.cfg.NoReplyMA {
		resp.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	switch req.Code {
	case AccountingRequest:
		if !verifyAccountingRequest(raw, secret) {
			return nil
		}
		resp.Code = AccountingResponse
		return resp.SignResponse(req.Authenticator, sign)
	case StatusServer, AccessRequest:
		if !f.cfg.IgnoreMA && !checkMA(raw, secret, req.Authenticator) {
			return nil // RFC 3579 §3.2: se descarta en silencio
		}
	default:
		return nil
	}
	if req.Code == StatusServer {
		resp.Code = AccessAccept
		resp.Add(AttrReplyMessage, []byte("vivo"))
		return resp.SignResponse(req.Authenticator, sign)
	}
	user, _ := req.Get(AttrUserName)
	pw, known := f.cfg.Users[string(user)]
	ok := known && f.checkPassword(req, []byte(pw), resp)
	switch {
	case ok && string(user) == f.cfg.ChallengeUser:
		resp.Code = AccessChallenge
		resp.Add(24, []byte("estado-1"))
		resp.Add(AttrReplyMessage, []byte("Introduce el código OTP"))
	case ok:
		resp.Code = AccessAccept
		resp.Attrs = append(resp.Attrs, f.cfg.Reply...)
	default:
		resp.Code = AccessReject
		resp.Attrs = resp.Attrs[:min(len(resp.Attrs), 1)]
		resp.Add(AttrReplyMessage, []byte("credenciales inválidas"))
	}
	return resp.SignResponse(req.Authenticator, sign)
}

func (f *Fake) checkPassword(req *Packet, pw []byte, resp *Packet) bool {
	secret := []byte(f.cfg.Secret)
	if v, ok := req.Get(AttrUserPassword); ok {
		return bytes.Equal(v, papHide(pw, secret, req.Authenticator))
	}
	if v, ok := req.Get(AttrCHAPPassword); ok && len(v) == 17 {
		ch, ok := req.Get(AttrCHAPChallenge)
		if !ok {
			ch = req.Authenticator[:]
		}
		return bytes.Equal(v, chapResponse(v[0], pw, ch))
	}
	var authCh, msResp []byte
	for _, a := range req.Attrs {
		if a.Type == AttrVendorSpecific && len(a.Value) > 6 && bytes.Equal(a.Value[:4], u32(311)) {
			switch a.Value[4] {
			case 11:
				authCh = a.Value[6:]
			case 25:
				msResp = a.Value[6:]
			}
		}
	}
	if len(authCh) != 16 || len(msResp) != 50 {
		return false
	}
	user, _ := req.Get(AttrUserName)
	peer, nt := msResp[2:18], msResp[26:50]
	if !bytes.Equal(nt, ntResponse(authCh, peer, string(user), pw)) {
		return false
	}
	ar := authenticatorResponse(pw, nt, peer, authCh, string(user))
	if f.cfg.BadMSSuccess {
		ar = ar[:len(ar)-1] + "0" + ar[len(ar)-1:len(ar)] // cambia el valor sin dejar de ser un texto
	}
	resp.Add(AttrVendorSpecific, vsa(311, 26, append([]byte{msResp[0]}, ar...)))
	return true
}
