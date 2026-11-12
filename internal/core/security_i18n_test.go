package core

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/radiustest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tacacstest"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/pki"
)

var rttRE = regexp.MustCompile(`[0-9]+\.[0-9] ms`)

// radiusClosed pide una prueba contra un puerto cerrado: sin respuesta, determinista.
func radiusClosed(t *testing.T, c v1.SecurityServiceClient, lang string) *v1.RadiusTestResponse {
	t.Helper()
	r, err := c.RadiusTest(con(t, lang), &v1.RadiusTestRequest{Host: "127.0.0.1", AuthPort: 9, Username: "a", TimeoutMs: 100,
		SharedSecret: &v1.SecretSource{Value: []byte("MARCA-SECRETO")}, Password: &v1.SecretSource{Value: []byte("MARCA-CLAVE")}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Regresión por RPC: sin accept-language, con es, con es-MX o con un idioma desconocido el texto es el de siempre.
func TestSeguridadRegresionEs(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewSecurityServiceClient(h.conn)
	const want = "Servidor RADIUS 127.0.0.1 (método PAP)\n\naccess-request: sin respuesta\n  ! sin respuesta tras 1 intentos de 100ms\n\n" +
		"Hallazgos:\n  [error] access-request: el servidor no respondió. Causas usuales: este equipo no está dado de alta como NAS/dispositivo de red en el servidor, " +
		"secreto compartido distinto (la petición se descarta por Message-Authenticator), UDP 1812 filtrado o puerto equivocado (1645/1646 heredados).\n"
	for _, lang := range []string{"", "es", "es-MX", "fr"} {
		if got := radiusClosed(t, c, lang).Report.Text; got != want {
			t.Errorf("radius con %q:\n%q", lang, got)
		}
	}
	// Con una prueba que sí contesta: el texto es el mismo en todos los idiomas que no son en.
	f, _ := tacacstest.StartFake(tacacstest.FakeConfig{Secret: "s", Users: map[string]string{"admin": "pw"}, Permit: map[string][]string{"show": {"priv-lvl=15"}}})
	defer f.Close()
	host, port := split(t, f.Addr())
	var first string
	for _, lang := range []string{"", "es", "fr"} {
		r, err := c.TacacsTest(con(t, lang), &v1.TacacsTestRequest{Host: host, Port: port, Username: "admin", SharedSecret: &v1.SecretSource{Value: []byte("s")},
			Password: &v1.SecretSource{Value: []byte("pw")}, Command: "show version", Accounting: true})
		if err != nil {
			t.Fatal(err)
		}
		txt := rttRE.ReplaceAllString(r.Report.Text, "N ms")
		txt = regexp.MustCompile(`(task_id|start_time|stop_time)=[0-9]+|127\.0\.0\.1:[0-9]+`).ReplaceAllString(txt, "X")
		if first == "" {
			first = txt
		} else if txt != first {
			t.Errorf("tacacs con %q difiere:\n%s\n---\n%s", lang, txt, first)
		}
		for _, frag := range []string{"Servidor TACACS+ X\n\nauthentication: PASS en N ms\n", "  servidor pidió: ", "  enviado  service=shell\n", "  recibido priv-lvl=15\n"} {
			if !strings.Contains(txt, frag) {
				t.Errorf("tacacs con %q: falta %q en\n%s", lang, frag, txt)
			}
		}
	}
	ca, _ := c.PkiCaInit(con(t, ""), &v1.PkiCaInitRequest{Name: "Lab CA", KeyPassword: []byte("x")})
	if !strings.HasPrefix(ca.Report.Text, pki.LabWarning+"\n\ncertificado: CN=Lab CA,OU=Laboratorio - no confiable\n  Emisor           CN=Lab CA") || !strings.Contains(ca.Report.Text, " días)\n") {
		t.Errorf("pki: %q", ca.Report.Text)
	}
}

// Lo estructurado de RADIUS dice lo mismo que el informe, sin secretos, y con en el texto sale en inglés.
func TestRadiusEstructuradoYEn(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewSecurityServiceClient(h.conn)
	f, err := radiustest.StartFake(radiustest.FakeConfig{Secret: "MARCA-SECRETO", Users: map[string]string{"alice": "MARCA-CLAVE"}, Reply: radiustest.AuthzReply(), NoReplyMA: true})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	host, port := split(t, f.Addr())
	ask := func(lang string) *v1.RadiusTestResponse {
		r, err := c.RadiusTest(con(t, lang), &v1.RadiusTestRequest{Host: host, AuthPort: port, AcctPort: port, Accounting: true, Username: "alice", TimeoutMs: 500,
			SharedSecret: &v1.SecretSource{Value: []byte("MARCA-SECRETO")}, Password: &v1.SecretSource{Value: []byte("MARCA-CLAVE")}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := ask("")
	var js struct {
		Server    string
		Method    string
		Exchanges []struct {
			Kind, Code string
			Attempts   int
			Attrs      []struct{ Name, Value string }
		}
		Findings []struct{ Severity, Code string }
	}
	if err := json.Unmarshal([]byte(r.Report.Json), &js); err != nil {
		t.Fatal(err)
	}
	if r.Server != js.Server || r.Method != "PAP" || len(r.Exchanges) != len(js.Exchanges) || len(r.Exchanges) != 3 {
		t.Fatalf("%+v", r)
	}
	for i, e := range r.Exchanges {
		j := js.Exchanges[i]
		if e.Kind != j.Kind || e.Code != j.Code || int(e.Attempts) != j.Attempts || len(e.Attrs) != len(j.Attrs) || e.Error != nil {
			t.Errorf("intercambio %d: %+v vs %+v", i, e, j)
		}
		for k, a := range e.Attrs {
			if a.Name != j.Attrs[k].Name || a.Value != j.Attrs[k].Value || !strings.Contains(r.Report.Text, a.Name) {
				t.Errorf("atributo %+v", a)
			}
		}
	}
	if r.Exchanges[0].MessageAuthenticator != "absent" || r.Exchanges[0].Code != "Access-Accept" {
		t.Errorf("MA: %+v", r.Exchanges[0])
	}
	if len(r.Findings) != 1 || r.Findings[0].Code != "blast_radius" || r.Findings[0].Severity != "warning" || r.Findings[0].Args["kind"] != "access-request" ||
		js.Findings[0].Severity != "aviso" || !strings.Contains(r.Report.Text, "[aviso] "+r.Findings[0].Message) {
		t.Errorf("hallazgos: %+v", r.Findings)
	}
	if strings.Contains(r.String(), "MARCA") {
		t.Fatal("secreto en la respuesta")
	}
	en := ask("en-US")
	if !strings.Contains(en.Report.Text, "RADIUS server 127.0.0.1 (method PAP)") || !strings.Contains(en.Report.Text, "attempt 1, Message-Authenticator absent") ||
		!strings.Contains(en.Report.Text, "Findings:\n  [warning] access-request: the response has no Message-Authenticator") ||
		strings.Contains(en.Report.Text, "Servidor") || strings.Contains(en.Report.Text, "Hallazgos") || strings.Contains(en.String(), "MARCA") {
		t.Errorf("en:\n%s", en.Report.Text)
	}
	if en.Findings[0].Message != i18n.Msg(i18n.En, "security.radius.finding.blast_radius", i18n.A("kind", "access-request")) || en.Findings[0].Code != "blast_radius" {
		t.Errorf("hallazgo en: %+v", en.Findings[0])
	}
	// Sin respuesta: el error es un texto con clave y el hallazgo lo cita en el idioma pedido.
	es, en2 := radiusClosed(t, c, ""), radiusClosed(t, c, "en")
	e := es.Exchanges[0]
	if e.Error.GetKey() != "security.radius.err.no_response" || e.Error.Args["attempts"] != "1" || e.Error.Text != "sin respuesta tras 1 intentos de 100ms" || e.Code != "" || e.MessageAuthenticator != "" {
		t.Errorf("error: %+v", e)
	}
	if got := en2.Exchanges[0].Error.Text; got != "no response after 1 attempt (100ms each)" || !strings.Contains(en2.Report.Text, "! no response after 1 attempt (100ms each)") ||
		!strings.Contains(en2.Report.Text, "UDP 1812 filtered") || en2.Findings[0].Code != "no_response" || en2.Findings[0].Args["port"] != "1812" {
		t.Errorf("sin respuesta en: %+v\n%s", en2.Exchanges[0], en2.Report.Text)
	}
}

func TestTacacsEstructuradoYEn(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewSecurityServiceClient(h.conn)
	f, _ := tacacstest.StartFake(tacacstest.FakeConfig{Secret: "MARCA-TAC", Users: map[string]string{"admin": "MARCA-PW"}, Permit: map[string][]string{"show": {"priv-lvl=15"}}})
	defer f.Close()
	host, port := split(t, f.Addr())
	ask := func(lang, pw, cmd string) *v1.TacacsTestResponse {
		r, err := c.TacacsTest(con(t, lang), &v1.TacacsTestRequest{Host: host, Port: port, Username: "admin", SharedSecret: &v1.SecretSource{Value: []byte("MARCA-TAC")},
			Password: &v1.SecretSource{Value: []byte(pw)}, Command: cmd, Accounting: true})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := ask("", "MARCA-PW", "show version")
	var js struct {
		Server string
		Steps  []struct {
			Kind, Status, ServerMsg, Data string
			Prompts, Sent, AVPairs        []string
		}
	}
	if err := json.Unmarshal([]byte(r.Report.Json), &js); err != nil {
		t.Fatal(err)
	}
	if r.Server != js.Server || len(r.Steps) != 4 || len(js.Steps) != 4 {
		t.Fatalf("%+v", r)
	}
	for i, s := range r.Steps {
		j := js.Steps[i]
		var sent, recv []string
		for _, a := range s.AvPairs {
			if a.Direction == "sent" {
				sent = append(sent, a.Value)
			} else if a.Direction == "received" {
				recv = append(recv, a.Value)
			} else {
				t.Errorf("dirección %q", a.Direction)
			}
		}
		if s.Kind != j.Kind || s.Status != j.Status || s.Message != j.ServerMsg || s.Data != j.Data || s.Error != nil ||
			strings.Join(s.Prompts, "|") != strings.Join(j.Prompts, "|") || strings.Join(sent, "|") != strings.Join(j.Sent, "|") || strings.Join(recv, "|") != strings.Join(j.AVPairs, "|") {
			t.Errorf("paso %d: %+v vs %+v", i, s, j)
		}
	}
	if len(r.Steps[1].AvPairs) == 0 || r.Steps[1].AvPairs[len(r.Steps[1].AvPairs)-1].Direction != "received" || len(r.Findings) != 0 || strings.Contains(r.String(), "MARCA") {
		t.Errorf("%+v", r.Steps[1])
	}
	bad := ask("en", "otra", "show version")
	if len(bad.Findings) != 1 || bad.Findings[0].Code != "authen_fail" || bad.Findings[0].Severity != "info" ||
		bad.Findings[0].Message != i18n.Msg(i18n.En, "security.tacacs.finding.authen_fail", nil) ||
		!strings.Contains(bad.Report.Text, "TACACS+ server ") || !strings.Contains(bad.Report.Text, "FAIL in ") || !strings.Contains(bad.Report.Text, "Findings:\n  [info] Authentication rejected") ||
		strings.Contains(bad.String(), "MARCA") || strings.Contains(bad.String(), "otra") {
		t.Errorf("%+v\n%s", bad.Findings, bad.Report.Text)
	}
	cl, err := c.TacacsTest(con(t, "en"), &v1.TacacsTestRequest{Host: "127.0.0.1", Port: 1, Username: "a", SharedSecret: &v1.SecretSource{Value: []byte("s")}, Password: &v1.SecretSource{Value: []byte("p")}, TimeoutMs: 200})
	if err != nil {
		t.Fatal(err)
	}
	if cl.Steps[0].Error.GetKey() != "security.tacacs.err.system" || cl.Findings[0].Code != "no_response" || cl.Findings[0].Severity != "error" ||
		!strings.Contains(cl.Findings[0].Message, "Check connectivity to TCP 1 and that the device is registered.") || strings.Contains(cl.Report.Text, "Revisa") {
		t.Errorf("cerrado: %+v %+v", cl.Steps[0], cl.Findings)
	}
}

func TestPkiEstructuradoYEn(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewSecurityServiceClient(h.conn)
	ca, err := c.PkiCaInit(con(t, "en"), &v1.PkiCaInitRequest{Name: "Lab CA", Days: 20, KeyPassword: []byte("MARCA-CAPW")})
	if err != nil {
		t.Fatal(err)
	}
	if !ca.LabWarning || !strings.HasPrefix(ca.Report.Text, i18n.Msg(i18n.En, "security.pki.lab_warning", nil)+"\n\ncertificate: CN=Lab CA,OU=Laboratorio - no confiable\n  Issuer           CN=Lab CA") ||
		strings.Contains(ca.Report.Text, "Emisor") || !strings.Contains(ca.Report.Text, " days)\n") || !strings.Contains(ca.Report.Text, "  CA               yes\n") {
		t.Errorf("en:\n%s", ca.Report.Text)
	}
	csr, _ := c.PkiCsr(con(t, ""), &v1.PkiCsrRequest{Algorithm: "p256", KeyPassword: []byte("x"), Subject: &v1.PkiSubject{Cn: "ise01.lab"}})
	if len(csr.Certificates) != 1 {
		t.Fatal("csr")
	}
	cert, err := c.PkiCaSign(con(t, ""), &v1.PkiCaSignRequest{CaCertPem: ca.CaCertPem, CaSealedKeyPem: ca.SealedKeyPem, CaKeyPassword: []byte("MARCA-CAPW"), CsrPem: csr.CsrPem, Profile: "server", Days: 10})
	if err != nil {
		t.Fatal(err)
	}
	var js []struct {
		Kind, Subject, Issuer, Serial, NotBefore, NotAfter, KeyType, SigAlg, SHA1, SHA256 string
		DaysLeft                                                                          int
		SANs, KeyUsage, ExtKeyUsage                                                       []string
		IsCA, SelfSigned                                                                  bool
		Warnings                                                                          []string
	}
	if err := json.Unmarshal([]byte(cert.Report.Json), &js); err != nil || len(js) != 1 || len(cert.Certificates) != 1 {
		t.Fatalf("%v %s", err, cert.Report.Json)
	}
	x, j := cert.Certificates[0], js[0]
	if x.Kind != "certificate" || x.Subject != j.Subject || x.Issuer != j.Issuer || x.Serial != j.Serial || x.NotBefore != j.NotBefore || x.NotAfter != j.NotAfter ||
		x.GetDaysLeft() != int32(j.DaysLeft) || x.DaysLeft == nil || x.Key.Description != j.KeyType || x.Key.Algorithm != "ECDSA" || x.Key.Bits != 256 || x.Key.Curve != "P-256" ||
		x.Signature.Algorithm != j.SigAlg || x.Signature.Valid != nil || x.Sha1 != j.SHA1 || x.Sha256 != j.SHA256 || x.IsCa != j.IsCA || x.SelfSigned != j.SelfSigned ||
		strings.Join(x.San, ",") != strings.Join(j.SANs, ",") || strings.Join(x.KeyUsage, ",") != strings.Join(j.KeyUsage, ",") || strings.Join(x.ExtKeyUsage, ",") != strings.Join(j.ExtKeyUsage, ",") ||
		x.Serial == "" || len(x.Sha256) != 64 || len(x.Warnings) != len(j.Warnings) || len(x.Warnings) == 0 || x.Warnings[0].Message != j.Warnings[0] {
		t.Errorf("certificado: %+v vs %+v", x, j)
	}
	// Los avisos llevan código y args: «sin SAN» (no pedimos SAN) y «vence en N días».
	var codes []string
	for _, w := range x.Warnings {
		codes = append(codes, w.Code)
		if w.Code == "expires_soon" && w.Args["days"] != "9" && w.Args["days"] != "10" {
			t.Errorf("días: %v", w.Args)
		}
	}
	if strings.Join(codes, ",") != "expires_soon,no_san" {
		t.Errorf("avisos: %v", codes)
	}
	dec, _ := c.PkiDecode(con(t, "en"), &v1.PkiDecodeRequest{Data: []byte(csr.CsrPem)})
	k := dec.Certificates[0]
	if k.Kind != "csr" || k.NotAfter != "" || k.DaysLeft != nil || k.Signature.Valid == nil || !*k.Signature.Valid || !strings.Contains(dec.Report.Text, "CSR: CN=ise01.lab") ||
		!strings.Contains(dec.Report.Text, "Signature valid  yes") || !strings.Contains(dec.Report.Text, "! no SAN: modern clients ignore the CN") || k.Warnings[0].Message != "no SAN: modern clients ignore the CN; add the DNS/IP name as a SAN" {
		t.Errorf("csr: %+v\n%s", k, dec.Report.Text)
	}
	if strings.Contains(cert.String()+ca.String()+csr.String(), "MARCA") && !strings.Contains(ca.SealedKeyPem, "MARCA") {
		t.Fatal("contraseña en la respuesta")
	}
}

// Fase 30c-A: mschap2_verified solo aparece con MS-CHAPv2 y dice si el servidor quedó verificado.
func TestRadiusMschap2Verified(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewSecurityServiceClient(h.conn)
	f, err := radiustest.StartFake(radiustest.FakeConfig{Secret: "S", Users: map[string]string{"alice": "pw"}, Reply: radiustest.AuthzReply()})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	host, port := split(t, f.Addr())
	ask := func(method string) *v1.RadiusTestResponse {
		r, err := c.RadiusTest(con(t, ""), &v1.RadiusTestRequest{Host: host, AuthPort: port, AcctPort: port, Username: "alice", Method: method, TimeoutMs: 500,
			SharedSecret: &v1.SecretSource{Value: []byte("S")}, Password: &v1.SecretSource{Value: []byte("pw")}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if v := ask("mschapv2").Exchanges[0].Mschap2Verified; v == nil || !*v {
		t.Errorf("mschapv2: %v", v)
	}
	if v := ask("pap").Exchanges[0].Mschap2Verified; v != nil {
		t.Errorf("pap no debe traerlo: %v", *v)
	}
}
