package radiustest

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func direct(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(port))))
}

func fake(t *testing.T, cfg FakeConfig) (string, uint16, *Fake) {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = "lab-secret"
	}
	if cfg.Users == nil {
		cfg.Users = map[string]string{"alice": "pw-alice"}
	}
	f, err := StartFake(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	h, p, _ := net.SplitHostPort(f.Addr())
	port, _ := strconv.Atoi(p)
	return h, uint16(port), f
}

func base(host string, port uint16) Config {
	return Config{Host: host, AuthPort: port, AcctPort: port, Secret: []byte("lab-secret"), Username: "alice",
		Password: []byte("pw-alice"), NASIP: "10.0.0.5", NASPortType: "ethernet", ServiceType: "framed",
		CalledStationID: "AA-BB-CC-00-11-22", CallingStationID: "00-11-22-33-44-55", Timeout: 300 * time.Millisecond, Retries: 1}
}

func attr(e Exchange, name string) string {
	var vs []string
	for _, a := range e.Attrs {
		if a.Name == name {
			vs = append(vs, a.Value)
		}
	}
	return strings.Join(vs, "|")
}

func TestAccessAcceptDecodesAuthorization(t *testing.T) {
	h, p, f := fake(t, FakeConfig{Reply: AuthzReply()})
	for _, m := range []string{"pap", "chap", "mschapv2"} {
		cfg := base(h, p)
		cfg.Method = m
		r, err := Run(context.Background(), direct, cfg)
		if err != nil {
			t.Fatal(err)
		}
		e := r.Exchanges[0]
		if e.Code != "Access-Accept" || e.Error != "" || e.MessageAuthenticator != "válido" || e.RTTMillis < 0 {
			t.Fatalf("%s: %+v", m, e)
		}
		if got := attr(e, "Tunnel-Private-Group-ID"); got != "10" {
			t.Errorf("%s: VLAN = %q", m, got)
		}
		if got := attr(e, "Tunnel-Type"); got != "VLAN (13)" {
			t.Errorf("Tunnel-Type = %q", got)
		}
		if got := attr(e, "Cisco-AVPair"); got != "shell:priv-lvl=15|url-redirect-acl=ACL-REDIR" {
			t.Errorf("Cisco-AVPair = %q", got)
		}
		if attr(e, "Filter-Id") != "PERMIT-ALL.in" || attr(e, "Session-Timeout") != "3600" || attr(e, "Class") == "" {
			t.Errorf("attrs = %+v", e.Attrs)
		}
		if m == "mschapv2" && !strings.Contains(attr(e, "MS-CHAP2-Success"), "verificada") {
			t.Errorf("MS-CHAP2-Success = %q", attr(e, "MS-CHAP2-Success"))
		}
	}
	// Los atributos del NAS llegaron como se pidieron.
	req := f.Last()
	for typ, want := range map[byte]string{AttrNASIPAddress: "\x0a\x00\x00\x05", AttrCalledStationID: "AA-BB-CC-00-11-22", AttrCallingStationID: "00-11-22-33-44-55",
		AttrNASPortType: "\x00\x00\x00\x0f", AttrServiceType: "\x00\x00\x00\x02"} {
		if v, _ := req.Get(typ); string(v) != want {
			t.Errorf("atributo %d = %q", typ, v)
		}
	}
	if req.Attrs[0].Type != AttrMessageAuthenticator {
		t.Error("la petición no lleva Message-Authenticator primero")
	}
}

func TestRejectWrongPasswordAndNoSecretsInReport(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{})
	cfg := base(h, p)
	cfg.Password = []byte("MARCA-mala-9f3")
	r, err := Run(context.Background(), direct, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Exchanges[0].Code != "Access-Reject" || attr(r.Exchanges[0], "Reply-Message") == "" {
		t.Fatalf("%+v", r.Exchanges[0])
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b)+r.Text(), "MARCA-mala") || strings.Contains(string(b)+r.Text(), "lab-secret") {
		t.Fatal("el reporte contiene secretos")
	}
}

func TestWrongSecretIsReported(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{})
	cfg := base(h, p)
	cfg.Secret = []byte("otro")
	r, _ := Run(context.Background(), direct, cfg)
	// El servidor descarta la petición por Message-Authenticator inválido: no hay respuesta.
	if e := r.Exchanges[0]; e.Code != "" || !strings.Contains(e.Error, "sin respuesta") || e.Attempts != 2 {
		t.Fatalf("%+v", e)
	}
	if !hasFinding(r, "no_response") {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestResponseAuthenticatorMismatch(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{IgnoreMA: true, ReplySecret: "distinto"})
	r, _ := Run(context.Background(), direct, base(h, p))
	// Revisión: una respuesta que no autentica no se presenta como resultado.
	if e := r.Exchanges[0]; !strings.Contains(e.Error, "secreto") || e.Code != "" || len(e.Attrs) != 0 {
		t.Fatalf("%+v", e)
	}
}

func TestMissingMessageAuthenticatorWarns(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{NoReplyMA: true})
	r, _ := Run(context.Background(), direct, base(h, p))
	if r.Exchanges[0].MessageAuthenticator != "ausente" || !hasFinding(r, "blast_radius") {
		t.Fatalf("%+v %+v", r.Exchanges[0], r.Findings)
	}
}

func TestChallenge(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{ChallengeUser: "alice"})
	r, _ := Run(context.Background(), direct, base(h, p))
	if e := r.Exchanges[0]; e.Code != "Access-Challenge" || attr(e, "State") == "" {
		t.Fatalf("%+v", e)
	}
}

func TestStatusServerAndAccounting(t *testing.T) {
	h, p, f := fake(t, FakeConfig{})
	cfg := base(h, p)
	cfg.StatusServer = true
	r, err := Run(context.Background(), direct, cfg)
	if err != nil || len(r.Exchanges) != 1 || r.Exchanges[0].Kind != "status-server" || r.Exchanges[0].Code != "Access-Accept" {
		t.Fatalf("%+v %v", r, err)
	}
	cfg = base(h, p)
	cfg.Accounting = true
	r, _ = Run(context.Background(), direct, cfg)
	if len(r.Exchanges) != 3 || r.Exchanges[1].Code != "Accounting-Response" || r.Exchanges[2].Kind != "accounting-stop" || r.Exchanges[2].Error != "" {
		t.Fatalf("%+v", r.Exchanges)
	}
	if v, _ := f.Last().Get(AttrAcctStatusType); string(v) != "\x00\x00\x00\x02" {
		t.Fatalf("último Acct-Status-Type = %x", v)
	}
}

func TestConfigValidation(t *testing.T) {
	good := base("127.0.0.1", 1812)
	for name, mut := range map[string]func(*Config){
		"sin secreto":    func(c *Config) { c.Secret = nil },
		"sin usuario":    func(c *Config) { c.Username = "" },
		"método":         func(c *Config) { c.Method = "eap-tls" },
		"nas ip":         func(c *Config) { c.NASIP = "nope" },
		"port type":      func(c *Config) { c.NASPortType = "frob" },
		"contraseña 129": func(c *Config) { c.Password = make([]byte, 129) },
	} {
		c := good
		mut(&c)
		if _, err := Run(context.Background(), direct, c); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
}

func TestMaliciousRepliesDoNotCrash(t *testing.T) {
	for _, b := range [][]byte{nil, {2}, make([]byte, 20), append([]byte{2, 0, 0, 30}, make([]byte, 26)...), append([]byte{2, 0, 0, 24}, append(make([]byte, 16), 26, 4, 0, 0)...)} {
		if p, err := Decode(b); err == nil {
			for _, a := range p.Attrs {
				describe(a)
			}
		}
	}
	// VSA truncado y Tunnel sin valor.
	for _, a := range []Attr{{26, []byte{0, 0, 0, 9, 1, 50, 'x'}}, {64, nil}, {81, nil}, {26, []byte{0}}} {
		describe(a)
	}
}

func hasFinding(r Report, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestTaggedTunnelAttributes(t *testing.T) {
	for a, want := range map[*Attr]string{
		{64, []byte{1, 0, 0, 13}}: "VLAN (13) [etiqueta 1]",
		{81, []byte("\x01VOZ")}:   "VOZ [etiqueta 1]",
		{81, []byte("200")}:       "200",
		{6, []byte{0, 0, 0, 2}}:   "Framed (2)",
	} {
		if got := describe(*a)[0].Value; got != want {
			t.Errorf("%d: %q, want %q", a.Type, got, want)
		}
	}
}

// Revisión: los bytes tras Length no entran en los autenticadores.
func TestPaddingAfterLengthIsIgnored(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{PadReply: 4})
	r, _ := Run(context.Background(), direct, base(h, p))
	if e := r.Exchanges[0]; e.Code != "Access-Accept" || e.Error != "" || e.MessageAuthenticator != "válido" {
		t.Fatalf("%+v", e)
	}
}

// Revisión: un atributo de texto de más de 253 bytes no cabe y debe rechazarse antes de enviar.
func TestLongNASIdentifierRejected(t *testing.T) {
	c := base("127.0.0.1", 1812)
	c.NASIdentifier = strings.Repeat("n", 300)
	if _, err := Run(context.Background(), direct, c); err == nil || !strings.Contains(err.Error(), "253") {
		t.Fatalf("err = %v", err)
	}
}

// Revisión: una respuesta falsificada con el ID correcto no tapa la verdadera.
func TestForgedResponseIsSkipped(t *testing.T) {
	h, p, _ := fake(t, FakeConfig{SpoofFirst: true, Reply: AuthzReply()})
	r, _ := Run(context.Background(), direct, base(h, p))
	if e := r.Exchanges[0]; e.Code != "Access-Accept" || e.Error != "" || attr(e, "Tunnel-Private-Group-ID") != "10" {
		t.Fatalf("%+v", e)
	}
}

// Un Message-Authenticator inválido en la respuesta da ma_invalid (error), sin blast_radius.
func TestInvalidMessageAuthenticatorFinding(t *testing.T) {
	r := Report{Exchanges: []Exchange{{Kind: "access-request", Code: "Access-Accept", MessageAuthenticator: "inválido"}}}
	r.findings()
	if len(r.Findings) != 1 || r.Findings[0].Code != "ma_invalid" || r.Findings[0].Severity != "error" || hasFinding(r, "blast_radius") {
		t.Fatalf("%+v", r.Findings)
	}
}
