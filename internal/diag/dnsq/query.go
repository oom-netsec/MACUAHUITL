// Package dnsq hace consultas y diagnóstico DNS: ligero (una consulta, comparar
// resolvedores) y profundo (traza desde la raíz, consistencia de autoritativos,
// cadena DNSSEC, transporte, higiene de correo y exposición).
//
// Toda conexión sale por el Dialer que entrega el núcleo, que pasa por
// EgressGuard y audita cada servidor contactado (spec §6.1).
package dnsq

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Dialer abre una conexión tcp o udp hacia host:port. En producción la arma el
// núcleo sobre transport.Guard; en pruebas apunta al laboratorio local.
type Dialer func(ctx context.Context, network, host string, port uint16) (net.Conn, error)

// Server es un servidor DNS con su transporte.
type Server struct {
	Transport string // udp, tcp, dot, doh
	Host      string
	Port      uint16
	TLSName   string // dot y doh
	Path      string // doh
}

func (s Server) String() string {
	switch s.Transport {
	case "dot":
		return fmt.Sprintf("tls://%s#%s", netip.AddrPortFrom(mustAddr(s.Host), s.Port), s.TLSName)
	case "doh":
		return fmt.Sprintf("https://%s:%d%s", s.Host, s.Port, s.Path)
	}
	if a, err := netip.ParseAddr(s.Host); err == nil {
		return s.Transport + "://" + netip.AddrPortFrom(a, s.Port).String()
	}
	return fmt.Sprintf("%s://%s:%d", s.Transport, s.Host, s.Port)
}

func mustAddr(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }

// ParseServer entiende "192.0.2.1", "192.0.2.1:5353", "tcp://…", "tls://IP#nombre" y "https://host/ruta".
func ParseServer(s string) (Server, error) {
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\n") {
		return Server{}, i18n.New("dns.parse.err.server", i18n.A("server", s))
	}
	if strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return Server{}, i18n.New("dns.parse.err.doh_url", i18n.A("server", s))
		}
		port := uint16(443)
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return Server{}, i18n.New("dns.parse.err.port", i18n.A("port", p))
			}
			port = uint16(n)
		}
		path := u.Path
		if path == "" {
			path = "/dns-query"
		}
		return Server{Transport: "doh", Host: u.Hostname(), Port: port, TLSName: u.Hostname(), Path: path}, nil
	}
	srv := Server{Transport: "udp", Port: 53}
	rest := s
	for _, p := range [][2]string{{"udp://", "udp"}, {"tcp://", "tcp"}, {"tls://", "dot"}} {
		if after, ok := strings.CutPrefix(s, p[0]); ok {
			srv.Transport, rest = p[1], after
		}
	}
	if strings.Contains(rest, "://") {
		return Server{}, i18n.New("dns.parse.err.scheme", i18n.A("server", s))
	}
	if srv.Transport == "dot" {
		srv.Port = 853
		host, name, ok := strings.Cut(rest, "#")
		if !ok || name == "" {
			return Server{}, i18n.New("dns.parse.err.dot_name", nil)
		}
		srv.TLSName, rest = name, host
	}
	if ap, err := netip.ParseAddrPort(rest); err == nil {
		if ap.Port() == 0 {
			return Server{}, i18n.New("dns.parse.err.port_zero", nil)
		}
		srv.Host, srv.Port = ap.Addr().String(), ap.Port()
		return srv, nil
	}
	if a, err := netip.ParseAddr(strings.Trim(rest, "[]")); err == nil {
		srv.Host = a.String()
		return srv, nil
	}
	if h, p, err := net.SplitHostPort(rest); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Server{}, i18n.New("dns.parse.err.port", i18n.A("port", p))
		}
		srv.Host, srv.Port = h, uint16(n)
	} else {
		srv.Host = rest
	}
	if _, ok := dns.IsDomainName(srv.Host); !ok || srv.Host == "" {
		return Server{}, i18n.New("dns.parse.err.server", i18n.A("server", s))
	}
	return srv, nil
}

// Options controla cada consulta.
type Options struct {
	Timeout   time.Duration // por consulta; 5 s por defecto
	DNSSEC    bool          // bit DO
	NoRecurse bool          // RD=0
	BufSize   uint16        // EDNS; 0 = 1232 si hay EDNS
	NoEDNS    bool
	TLSRoots  *x509.CertPool   // pruebas; nil = raíces del sistema
	OnContact func(srv string) // el núcleo audita cada servidor contactado
	Now       func() time.Time // pruebas
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 5 * time.Second
	}
	return o.Timeout
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

type Flags struct{ AA, TC, RD, RA, AD, CD bool }

// Answer es una respuesta legible; RR en formato de zona.
type Answer struct {
	Server     string
	Name, Type string
	RCode      string
	Flags      Flags
	Answer     []string
	Authority  []string
	Additional []string
	RTT        time.Duration
	Size       int
	Truncated  bool
	RetriedTCP bool
	EDNS       bool
	Error      string `json:",omitempty"`
	// ErrorText es Error como texto de catálogo; no viaja en el JSON.
	ErrorText i18n.Text `json:"-"`
	msg       *dns.Msg
}

func newMsg(name string, qtype uint16, o Options) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = !o.NoRecurse
	if !o.NoEDNS {
		size := o.BufSize
		if size == 0 {
			size = 1232
		}
		m.SetEdns0(size, o.DNSSEC)
	}
	return m
}

// exchange manda m por el transporte del servidor y valida que la respuesta sea la suya.
func exchange(ctx context.Context, d Dialer, s Server, m *dns.Msg, o Options) (*dns.Msg, time.Duration, int, error) {
	ctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	if o.OnContact != nil {
		o.OnContact(s.String())
	}
	start := o.now()
	var r *dns.Msg
	var size int
	var err error
	switch s.Transport {
	case "udp", "tcp":
		r, size, err = exchangeConn(ctx, d, s.Transport, s.Host, s.Port, nil, m)
	case "dot":
		cfg := &tls.Config{ServerName: s.TLSName, RootCAs: o.TLSRoots, MinVersion: tls.VersionTLS12}
		r, size, err = exchangeConn(ctx, d, "tcp", s.Host, s.Port, cfg, m)
	case "doh":
		r, size, err = exchangeDoH(ctx, d, s, m, o)
	default:
		err = i18n.New("dns.exch.transport", i18n.A("transport", s.Transport))
	}
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, 0, i18n.Wrap("dns.exch.wrap", err, i18n.A("server", s.String()))
	}
	if r.Id != m.Id && s.Transport != "doh" { // DoH usa ID 0 por RFC 8484
		return nil, rtt, size, i18n.New("dns.exch.bad_id", i18n.A("server", s.String(), "got", r.Id, "want", m.Id))
	}
	if len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, m.Question[0].Name) || r.Question[0].Qtype != m.Question[0].Qtype || r.Question[0].Qclass != m.Question[0].Qclass {
		return nil, rtt, size, i18n.New("dns.exch.mismatch", i18n.A("server", s.String()))
	}
	return r, rtt, size, nil
}

func exchangeConn(ctx context.Context, d Dialer, network, host string, port uint16, tlsCfg *tls.Config, m *dns.Msg) (*dns.Msg, int, error) {
	c, err := d(ctx, network, host, port)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if tlsCfg != nil {
		tc := tls.Client(c, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, 0, fmt.Errorf("TLS: %w", err)
		}
		c = tc
	}
	co := &dns.Conn{Conn: c, UDPSize: 65535}
	if err := co.WriteMsg(m); err != nil {
		return nil, 0, err
	}
	r, err := co.ReadMsg()
	if err != nil {
		return nil, 0, err
	}
	return r, r.Len(), nil
}

func exchangeDoH(ctx context.Context, d Dialer, s Server, m *dns.Msg, o Options) (*dns.Msg, int, error) {
	mm := m.Copy()
	mm.Id = 0
	body, err := mm.Pack()
	if err != nil {
		return nil, 0, err
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			n, _ := strconv.Atoi(p)
			return d(ctx, "tcp", h, uint16(n))
		},
		TLSClientConfig:   &tls.Config{ServerName: s.TLSName, RootCAs: o.TLSRoots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		Proxy:             nil, // nunca un proxy del entorno: el destino lo decide el ingeniero
	}
	defer tr.CloseIdleConnections()
	u := fmt.Sprintf("https://%s%s", net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port))), s.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, i18n.New("dns.exch.doh_http", i18n.A("status", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, 0, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(raw); err != nil {
		return nil, 0, i18n.Wrap("dns.exch.doh_unreadable", err, nil)
	}
	return r, len(raw), nil
}

func toAnswer(s Server, name string, qtype uint16, r *dns.Msg, rtt time.Duration, size int) Answer {
	a := Answer{Server: s.String(), Name: dns.Fqdn(name), Type: dns.TypeToString[qtype], RCode: dns.RcodeToString[r.Rcode], RTT: rtt, Size: size,
		Flags: Flags{AA: r.Authoritative, TC: r.Truncated, RD: r.RecursionDesired, RA: r.RecursionAvailable, AD: r.AuthenticatedData, CD: r.CheckingDisabled},
		EDNS:  r.IsEdns0() != nil, msg: r}
	for _, rr := range r.Answer {
		a.Answer = append(a.Answer, rr.String())
	}
	for _, rr := range r.Ns {
		a.Authority = append(a.Authority, rr.String())
	}
	for _, rr := range r.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			a.Additional = append(a.Additional, rr.String())
		}
	}
	return a
}

// Query hace una consulta. Por UDP, si la respuesta viene truncada, la repite por TCP.
func Query(ctx context.Context, d Dialer, s Server, name string, qtype uint16, o Options) (Answer, error) {
	m := newMsg(name, qtype, o)
	r, rtt, size, err := exchange(ctx, d, s, m, o)
	if err != nil {
		return Answer{Server: s.String(), Name: dns.Fqdn(name), Type: dns.TypeToString[qtype], Error: err.Error(), ErrorText: i18n.FromErr(err)}, err
	}
	if s.Transport == "udp" && r.Truncated {
		ts := s
		ts.Transport = "tcp"
		r2, rtt2, size2, err := exchange(ctx, d, ts, newMsg(name, qtype, o), o)
		if err != nil {
			a := toAnswer(s, name, qtype, r, rtt, size)
			e := i18n.Wrap("dns.exch.trunc_failed", err, nil)
			a.Truncated, a.Error, a.ErrorText = true, e.Error(), i18n.FromErr(e)
			return a, err
		}
		a := toAnswer(s, name, qtype, r2, rtt+rtt2, size2)
		a.Truncated, a.RetriedTCP = true, true
		return a, nil
	}
	return toAnswer(s, name, qtype, r, rtt, size), nil
}

// In devuelve el resultado con el error de cada respuesta en el idioma dado (es es el de siempre).
func (r CompareResult) In(loc string) CompareResult {
	if r.Answers == nil {
		return r
	}
	r.Answers = append([]Answer(nil), r.Answers...)
	for i := range r.Answers {
		if !r.Answers[i].ErrorText.Empty() {
			r.Answers[i].Error = r.Answers[i].ErrorText.In(loc)
		}
	}
	return r
}

// CompareResult es la misma pregunta hecha a varios servidores.
type CompareResult struct {
	Name, Type string
	Answers    []Answer
	Consistent bool // todos devolvieron el mismo conjunto de datos (sin contar TTL)
}

// Compare pregunta lo mismo a cada servidor y dice si coinciden.
func Compare(ctx context.Context, d Dialer, servers []Server, name string, qtype uint16, o Options) CompareResult {
	res := CompareResult{Name: dns.Fqdn(name), Type: dns.TypeToString[qtype], Consistent: true}
	var first string
	for i, s := range servers {
		a, _ := Query(ctx, d, s, name, qtype, o)
		res.Answers = append(res.Answers, a)
		sig := a.RCode + "|" + strings.Join(rdata(a.msg), ",")
		if a.Error != "" {
			sig = "error"
		}
		if i == 0 {
			first = sig
		} else if sig != first {
			res.Consistent = false
		}
	}
	return res
}

// rdata resume la sección de respuesta sin TTL, ordenada, para comparar.
func rdata(m *dns.Msg) []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, rr := range m.Answer {
		h := rr.Header()
		txt := strings.TrimPrefix(rr.String(), h.String())
		out = append(out, strings.ToLower(h.Name)+" "+dns.TypeToString[h.Rrtype]+" "+txt)
	}
	sort.Strings(out)
	return out
}

// PublicResolvers son los resolvedores para revisar propagación (solo con el modo profundo).
var PublicResolvers = []Server{
	{Transport: "udp", Host: "1.1.1.1", Port: 53},
	{Transport: "udp", Host: "8.8.8.8", Port: 53},
	{Transport: "udp", Host: "9.9.9.9", Port: 53},
	{Transport: "udp", Host: "208.67.222.222", Port: 53},
}

// ParseType convierte "A", "mx", "TYPE65"... en el código de tipo; vacío = A.
func ParseType(s string) (uint16, error) {
	if s == "" {
		return dns.TypeA, nil
	}
	if t, ok := dns.StringToType[strings.ToUpper(s)]; ok {
		return t, nil
	}
	return 0, i18n.New("dns.parse.err.type", i18n.A("type", s))
}

// SystemResolvers lee los nameserver de un resolv.conf (normalmente /etc/resolv.conf).
func SystemResolvers(path string) ([]Server, error) {
	cc, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("dnsq: %w", err)
	}
	var out []Server
	for _, s := range cc.Servers {
		out = append(out, Server{Transport: "udp", Host: s, Port: 53})
	}
	if len(out) == 0 {
		return nil, i18n.New("dns.parse.err.no_nameserver", i18n.A("path", path))
	}
	return out, nil
}
