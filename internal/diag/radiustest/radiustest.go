// Package radiustest prueba un servidor RADIUS (ISE, FreeRADIUS, NPS…) como lo
// haría un NAS: Access-Request PAP, CHAP o MS-CHAPv2 con atributos del NAS,
// Message-Authenticator (RFC 3579, RFC 5080), Status-Server (RFC 5997) y
// Accounting Start/Stop (RFC 2866). Implementación propia de RFC 2865/2866.
//
// No hace: EAP, RadSec ni guardar o mostrar el secreto compartido o la contraseña.
package radiustest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Dialer func(ctx context.Context, network, host string, port uint16) (net.Conn, error)

// Config describe la prueba. Secret y Password son del llamador, que los borra.
type Config struct {
	Host               string
	AuthPort, AcctPort uint16 // 1812 y 1813 por defecto
	Secret             []byte
	Username           string
	Password           []byte
	Method             string // pap (por defecto), chap, mschapv2
	NASIP              string
	NASIdentifier      string
	NASPortType        string // nombre (Ethernet, Wireless-802.11, Virtual…) o número
	ServiceType        string // nombre (Framed, Login, Call-Check…) o número
	CalledStationID    string
	CallingStationID   string
	StatusServer       bool // solo Status-Server, sin credenciales
	Accounting         bool // Start y Stop después del Access-Request
	Timeout            time.Duration
	Retries            int // reintentos además del primer envío
}

type Exchange struct {
	Kind                 string // access-request, status-server, accounting-start, accounting-stop
	Code                 string `json:",omitempty"`
	RTTMillis            float64
	Attempts             int
	MessageAuthenticator string `json:",omitempty"` // válido, ausente, inválido
	Attrs                []Decoded
	Error                string `json:",omitempty"`
}

type Finding struct{ Severity, Code, Detail string }

type Report struct {
	Server    string
	Method    string `json:",omitempty"`
	Exchanges []Exchange
	Findings  []Finding
}

var codeNames = map[byte]string{AccessAccept: "Access-Accept", AccessReject: "Access-Reject", AccessChallenge: "Access-Challenge",
	AccountingResponse: "Accounting-Response", AccessRequest: "Access-Request", AccountingRequest: "Accounting-Request", StatusServer: "Status-Server"}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (c *Config) defaults() {
	if c.AuthPort == 0 {
		c.AuthPort = 1812
	}
	if c.AcctPort == 0 {
		c.AcctPort = 1813
	}
	if c.Method == "" {
		c.Method = "pap"
	}
	if c.Timeout <= 0 {
		c.Timeout = 3 * time.Second
	}
	if c.Retries < 0 {
		c.Retries = 0
	}
	if c.Retries > 5 {
		c.Retries = 5
	}
}

// nasAttrs valida y arma los atributos comunes del NAS.
func (c *Config) nasAttrs() ([]Attr, error) {
	var out []Attr
	if c.NASIP != "" {
		a, err := netip.ParseAddr(c.NASIP)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("NAS-IP-Address %q: debe ser IPv4", c.NASIP)
		}
		b := a.As4()
		out = append(out, Attr{AttrNASIPAddress, b[:]})
	}
	for name, v := range map[string]string{"NAS-Identifier": c.NASIdentifier, "Called-Station-Id": c.CalledStationID, "Calling-Station-Id": c.CallingStationID} {
		if len(v) > 253 { // RFC 2865 §5: el valor de un atributo mide a lo más 253 bytes
			return nil, fmt.Errorf("%s de más de 253 bytes", name)
		}
	}
	if c.NASIdentifier != "" {
		out = append(out, Attr{AttrNASIdentifier, []byte(c.NASIdentifier)})
	}
	if c.NASIP == "" && c.NASIdentifier == "" { // RFC 2865 §4.1 exige uno de los dos
		out = append(out, Attr{AttrNASIdentifier, []byte("macuahuitl")})
	}
	for _, e := range []struct {
		t    byte
		v    string
		m    map[uint32]string
		name string
	}{{AttrNASPortType, c.NASPortType, nasPortTypes, "NAS-Port-Type"}, {AttrServiceType, c.ServiceType, serviceTypes, "Service-Type"}} {
		if e.v == "" {
			continue
		}
		n, err := parseEnum(e.v, e.m)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.name, err)
		}
		out = append(out, Attr{e.t, u32(n)})
	}
	for t, v := range map[byte]string{AttrCalledStationID: c.CalledStationID, AttrCallingStationID: c.CallingStationID} {
		if v != "" {
			out = append(out, Attr{t, []byte(v)})
		}
	}
	return out, nil
}

// Run hace la prueba completa. Solo devuelve error si la configuración es inválida;
// las fallas de red o del servidor quedan en el reporte.
func Run(ctx context.Context, d Dialer, c Config) (Report, error) {
	c.defaults()
	if strings.TrimSpace(c.Host) == "" || strings.HasPrefix(c.Host, "-") {
		return Report{}, errors.New("radius: servidor inválido")
	}
	if len(c.Secret) == 0 {
		return Report{}, errors.New("radius: falta el secreto compartido")
	}
	nas, err := c.nasAttrs()
	if err != nil {
		return Report{}, fmt.Errorf("radius: %w", err)
	}
	r := Report{Server: c.Host}
	if c.StatusServer {
		p := &Packet{Code: StatusServer, ID: randBytes(1)[0], Attrs: nas}
		copy(p.Authenticator[:], randBytes(16))
		r.Exchanges = append(r.Exchanges, exchange(ctx, d, c, c.AuthPort, "status-server", p, p.EncodeWithMA(c.Secret)))
		r.findings()
		return r, nil
	}
	if c.Username == "" || len(c.Username) > 253 {
		return Report{}, errors.New("radius: usuario vacío o de más de 253 bytes")
	}
	if len(c.Password) > 128 { // RFC 2865 §5.2
		return Report{}, errors.New("radius: contraseña de más de 128 bytes")
	}
	r.Method = c.Method
	p := &Packet{Code: AccessRequest, ID: randBytes(1)[0]}
	copy(p.Authenticator[:], randBytes(16))
	p.Add(AttrUserName, []byte(c.Username))
	var verifyMS func(Exchange) Exchange
	switch c.Method {
	case "pap":
		p.Add(AttrUserPassword, papHide(c.Password, c.Secret, p.Authenticator))
	case "chap":
		ch := randBytes(16)
		p.Add(AttrCHAPPassword, chapResponse(randBytes(1)[0], c.Password, ch))
		p.Add(AttrCHAPChallenge, ch)
	case "mschapv2":
		authCh, peerCh := randBytes(16), randBytes(16)
		nt := ntResponse(authCh, peerCh, c.Username, c.Password)
		resp := append([]byte{1, 0}, peerCh...) // Ident, Flags, Peer-Challenge
		resp = append(append(resp, make([]byte, 8)...), nt...)
		p.Add(AttrVendorSpecific, vsa(311, 11, authCh))
		p.Add(AttrVendorSpecific, vsa(311, 25, resp))
		want := authenticatorResponse(c.Password, nt, peerCh, authCh, c.Username)
		verifyMS = func(e Exchange) Exchange {
			for i, a := range e.Attrs {
				if a.Name == "MS-CHAP2-Success" {
					ok := strings.Contains(a.Value, want)
					e.Attrs[i].Value = map[bool]string{true: "respuesta del servidor verificada (autenticación mutua)", false: "NO verifica: el servidor no conoce la contraseña o hay un intermediario"}[ok]
				}
			}
			return e
		}
	default:
		return Report{}, fmt.Errorf("radius: método %q no soportado (pap, chap, mschapv2)", c.Method)
	}
	p.Attrs = append(p.Attrs, nas...)
	e := exchange(ctx, d, c, c.AuthPort, "access-request", p, p.EncodeWithMA(c.Secret))
	if verifyMS != nil {
		e = verifyMS(e)
	}
	r.Exchanges = append(r.Exchanges, e)
	if c.Accounting {
		session := fmt.Sprintf("mcu-%x", randBytes(4))
		for i, kind := range []string{"accounting-start", "accounting-stop"} {
			a := &Packet{Code: AccountingRequest, ID: randBytes(1)[0]}
			a.Add(AttrAcctStatusType, u32(uint32(i+1)))
			a.Add(AttrAcctSessionID, []byte(session))
			a.Add(AttrUserName, []byte(c.Username))
			if i == 1 {
				a.Add(AttrAcctSessionTime, u32(1))
			}
			a.Attrs = append(a.Attrs, nas...)
			r.Exchanges = append(r.Exchanges, exchange(ctx, d, c, c.AcctPort, kind, a, a.SignAccounting(c.Secret)))
		}
	}
	r.findings()
	return r, nil
}

func vsa(vendor uint32, typ byte, v []byte) []byte {
	return append(append(u32(vendor), typ, byte(len(v)+2)), v...)
}

// exchange envía con reintentos y espera la respuesta con el mismo ID. La conexión
// UDP conectada solo entrega datagramas del servidor contactado.
func exchange(ctx context.Context, d Dialer, c Config, port uint16, kind string, req *Packet, wire []byte) Exchange {
	e := Exchange{Kind: kind}
	copy(req.Authenticator[:], wire[4:20]) // accounting lo calcula al firmar
	conn, err := d(ctx, "udp", c.Host, port)
	if err != nil {
		e.Error = err.Error()
		return e
	}
	defer conn.Close()
	buf := make([]byte, maxPacket)
	unauth := "" // código de una respuesta con el ID correcto que no autenticó
	for e.Attempts = 1; e.Attempts <= c.Retries+1; e.Attempts++ {
		start := time.Now()
		if _, err := conn.Write(wire); err != nil {
			e.Error = err.Error()
			return e
		}
		deadline := start.Add(c.Timeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		conn.SetReadDeadline(deadline)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break // tiempo agotado o ICMP inalcanzable: siguiente intento
			}
			resp, err := Decode(buf[:n])
			if err != nil || resp.ID != req.ID {
				continue
			}
			// Decode ya validó Length ≤ n; el relleno posterior no entra en los autenticadores.
			raw := buf[:binary.BigEndian.Uint16(buf[2:4])]
			if !verifyResponse(raw, req.Authenticator, c.Secret) {
				// Secreto distinto o datagrama falsificado: no es el resultado; se sigue esperando.
				unauth = codeNames[resp.Code]
				continue
			}
			e.RTTMillis = float64(time.Since(start).Microseconds()) / 1000
			return e.fill(raw, resp, req, c.Secret)
		}
		if ctx.Err() != nil || unauth != "" { // el servidor sí contestó: reintentar no cambia nada
			break
		}
	}
	if unauth != "" {
		e.Attempts = min(e.Attempts, c.Retries+1)
		e.Error = fmt.Sprintf("llegó una respuesta (%s) cuyo autenticador no verifica: el secreto compartido no coincide con el del servidor (o la respuesta es falsificada); se descarta", unauth)
		return e
	}
	e.Attempts = min(e.Attempts, c.Retries+1)
	e.Error = fmt.Sprintf("sin respuesta tras %d intentos de %s", e.Attempts, c.Timeout)
	return e
}

func (e Exchange) fill(raw []byte, resp, req *Packet, secret []byte) Exchange {
	e.Code = codeNames[resp.Code]
	if e.Code == "" {
		e.Code = fmt.Sprintf("código %d", resp.Code)
	}
	switch {
	case maOffset(raw) < 0:
		e.MessageAuthenticator = "ausente"
	case checkMA(raw, secret, req.Authenticator):
		e.MessageAuthenticator = "válido"
	default:
		e.MessageAuthenticator = "inválido"
	}
	for _, a := range resp.Attrs {
		if a.Type != AttrMessageAuthenticator {
			e.Attrs = append(e.Attrs, describe(a)...)
		}
	}
	return e
}

func (r *Report) findings() {
	add := func(sev, code, detail string) { r.Findings = append(r.Findings, Finding{sev, code, detail}) }
	for _, e := range r.Exchanges {
		switch {
		case strings.HasPrefix(e.Error, "sin respuesta"):
			add("error", "sin-respuesta", e.Kind+": el servidor no respondió. Causas usuales: este equipo no está dado de alta como NAS/dispositivo de red en el servidor, secreto compartido distinto (la petición se descarta por Message-Authenticator), UDP "+map[bool]string{true: "1813", false: "1812"}[strings.HasPrefix(e.Kind, "accounting")]+" filtrado o puerto equivocado (1645/1646 heredados).")
		case e.Error != "":
			add("error", "respuesta-invalida", e.Kind+": "+e.Error)
		}
		if e.Code != "" && e.Kind != "accounting-start" && e.Kind != "accounting-stop" {
			switch e.MessageAuthenticator {
			case "ausente":
				add("aviso", "blast-radius", e.Kind+": la respuesta no trae Message-Authenticator; el servidor es vulnerable a Blast-RADIUS (CVE-2024-3596). Actualízalo y exige Message-Authenticator.")
			case "inválido":
				add("error", "ma-invalido", e.Kind+": Message-Authenticator inválido en la respuesta (secreto distinto o paquete alterado).")
			}
		}
		if e.Code == "Access-Reject" {
			add("info", "reject", "El servidor rechazó la autenticación. Revisa en el servidor (ISE: Operations > RADIUS > Live Logs) el motivo exacto; Reply-Message: "+valueOf(e, "Reply-Message"))
		}
	}
}

func valueOf(e Exchange, name string) string {
	for _, a := range e.Attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return "(ninguno)"
}

// Text es el resumen legible.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Servidor RADIUS %s", r.Server)
	if r.Method != "" {
		fmt.Fprintf(&b, " (método %s)", strings.ToUpper(r.Method))
	}
	b.WriteString("\n")
	for _, e := range r.Exchanges {
		fmt.Fprintf(&b, "\n%s: ", e.Kind)
		if e.Code != "" {
			fmt.Fprintf(&b, "%s en %.1f ms (intento %d, Message-Authenticator %s)\n", e.Code, e.RTTMillis, e.Attempts, e.MessageAuthenticator)
		} else {
			b.WriteString("sin respuesta\n")
		}
		if e.Error != "" {
			fmt.Fprintf(&b, "  ! %s\n", e.Error)
		}
		for _, a := range e.Attrs {
			fmt.Fprintf(&b, "  %-26s %s\n", a.Name, a.Value)
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\nHallazgos:\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  [%s] %s\n", f.Severity, f.Detail)
		}
	}
	return b.String()
}
