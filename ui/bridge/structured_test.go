package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeStruct struct {
	v1.UnimplementedSecurityServiceServer
	v1.UnimplementedToolsServiceServer
	v1.UnimplementedCalcServiceServer
}

var yes = true
var days = int32(9)

var cert = &v1.PkiCertificate{Kind: "certificate", Subject: "CN=a", Issuer: "CN=ca", Serial: "AB", NotBefore: "2026-11-12T00:00:00Z", NotAfter: "2026-11-21T00:00:00Z", DaysLeft: &days,
	Key: &v1.PkiKey{Algorithm: "ECDSA", Bits: 256, Curve: "P-256", Description: "ECDSA P-256"}, Signature: &v1.PkiSignature{Algorithm: "ECDSA-SHA256", Valid: &yes},
	San: []string{"a.lab"}, KeyUsage: []string{"digitalSignature"}, IsCa: true, Sha256: "FF",
	Warnings: []*v1.PkiWarning{{Code: "expires_soon", Args: map[string]string{"days": "9"}, Message: "vence en 9 días"}}}

func (fakeStruct) RadiusTest(context.Context, *v1.RadiusTestRequest) (*v1.RadiusTestResponse, error) {
	return &v1.RadiusTestResponse{Report: &v1.ToolReport{Text: "radius"}, Server: "10.0.0.1", Method: "PAP",
		Exchanges: []*v1.RadiusExchange{{Kind: "access-request", Code: "Access-Accept", RttMs: 1.5, Attempts: 1, MessageAuthenticator: "absent", Attrs: []*v1.RadiusAttribute{{Name: "Filter-Id", Value: "x"}}},
			{Kind: "accounting-start", Attempts: 2, Error: &v1.SecText{Key: "security.radius.err.no_response", Args: map[string]string{"attempts": "2"}, Text: "sin respuesta tras 2 intentos de 1s"}}},
		Findings: []*v1.SecFinding{{Code: "blast-radius", Severity: "warning", Args: map[string]string{"kind": "access-request"}, Message: "m"}}}, nil
}

func (fakeStruct) TacacsTest(context.Context, *v1.TacacsTestRequest) (*v1.TacacsTestResponse, error) {
	return &v1.TacacsTestResponse{Report: &v1.ToolReport{Text: "tacacs"}, Server: "10.0.0.1:49",
		Steps:    []*v1.TacacsStep{{Kind: "authorization", Status: "PASS_ADD", RttMs: 2, Prompts: []string{"Password: "}, AvPairs: []*v1.TacacsAvPair{{Direction: "sent", Value: "service=shell"}, {Direction: "received", Value: "priv-lvl=15"}}}},
		Findings: []*v1.SecFinding{{Code: "authen-fail", Severity: "info", Message: "m"}}}, nil
}

func (fakeStruct) PkiDecode(context.Context, *v1.PkiDecodeRequest) (*v1.PkiDecodeResponse, error) {
	return &v1.PkiDecodeResponse{Report: &v1.ToolReport{Text: "pki"}, Certificates: []*v1.PkiCertificate{cert, {Kind: "csr", Subject: "CN=b", Key: &v1.PkiKey{Description: "RSA 2048"}, Signature: &v1.PkiSignature{}}}}, nil
}

func (fakeStruct) PkiCaInit(context.Context, *v1.PkiCaInitRequest) (*v1.PkiCaInitResponse, error) {
	return &v1.PkiCaInitResponse{CaCertPem: "PEM", Report: &v1.ToolReport{Text: "ca"}, Certificates: []*v1.PkiCertificate{cert}, LabWarning: true}, nil
}

func (fakeStruct) AnalyzePcap(context.Context, *v1.AnalyzePcapRequest) (*v1.AnalyzePcapResponse, error) {
	return &v1.AnalyzePcapResponse{Report: &v1.ToolReport{Text: "pcap"}, Summary: &v1.PcapSummary{File: "/x.pcap", Packets: 5, Bytes: 5000000000, DurationMs: 11, Start: "2026-11-06T18:00:00Z"},
		Conversations: []*v1.PcapConversation{{Proto: "tcp", A: "a", B: "b", Packets: 3, Bytes: 5000000000}}, TopTalkers: []*v1.PcapTalker{{Ip: "10.0.0.1", Packets: 3, Bytes: 9}},
		Protocols: []*v1.PcapProtocol{{Proto: "tcp", Packets: 3, Bytes: 9}}, Neighbors: []*v1.PcapNeighbor{{Protocol: "cdp", DeviceId: "SW", NativeVlan: 10}},
		Tcp: &v1.PcapTcp{Handshakes: 1, RttMaxMs: 4, FailedHandshakesTotal: 1, FailedHandshakes: []*v1.PcapFlow{{Client: "c", Server: "s", Count: 2}}},
		Dns: &v1.PcapDns{Queries: 1, Unanswered: []*v1.PcapDnsQuery{{Name: "n", Type: "A", Server: "s"}}}, Icmp: &v1.PcapIcmp{Unreachable: []*v1.PcapIcmpEvent{{From: "f", Target: "t", Code: 1}}},
		ArpConflicts: []*v1.PcapArpConflict{{Ip: "10.0.0.50", Macs: []string{"m1", "m2"}}}, Fragments: 1,
		Warnings: []*v1.PcapWarning{{Key: "pcap.warn.truncated", Args: map[string]string{"packets": "25"}, Text: "t"}},
		Sections: []*v1.PcapSection{{Key: "pcap.section.tcp", Title: "TCP"}, {Key: "pcap.section.arp_conflict", Args: map[string]string{"ip": "10.0.0.50"}, Title: "CONFLICTO ARP"}}}, nil
}

func (fakeStruct) Subnet(context.Context, *v1.SubnetRequest) (*v1.SubnetResponse, error) {
	return &v1.SubnetResponse{Result: &v1.CalcResult{Text: "t", Notes: []string{"n"}, NotesStructured: []*v1.CalcNote{{Key: "calc.note.host_in_subnet", Args: map[string]string{"addr": "a"}}},
		Tables: []*v1.CalcTable{{Title: "Subred x", Head: []string{"Campo", "Valor"}, TitleKey: "calc.title.subnet", TitleArgs: map[string]string{"prefix": "x"},
			Columns: []*v1.CalcColumn{{Key: "calc.col.field"}, {Key: "calc.col.value"}},
			Rows:    []*v1.CalcRow{{Cells: []string{"Red", "10.0.0.0"}, LabelKey: "calc.row.network"}, {Cells: []string{"a", "b"}}}}}}}, nil
}

func asJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEstructuradoBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := fakeStruct{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterSecurityServiceServer(r, f)
		v1.RegisterToolsServiceServer(r, f)
		v1.RegisterCalcServiceServer(r, f)
	})
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	// RADIUS
	rr, err := b.SecRadiusReport(RadiusDTO{Host: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	m := asJSON(t, rr)
	ex := m["exchanges"].([]any)
	e0, e1 := ex[0].(map[string]any), ex[1].(map[string]any)
	if m["server"] != "10.0.0.1" || m["method"] != "PAP" || e0["messageAuthenticator"] != "absent" || e0["rttMs"] != 1.5 || e0["attrs"].([]any)[0].(map[string]any)["name"] != "Filter-Id" {
		t.Errorf("radius: %v", m)
	}
	if _, ok := e0["error"]; ok || e1["error"].(map[string]any)["key"] != "security.radius.err.no_response" || e1["error"].(map[string]any)["args"].(map[string]any)["attempts"] != "2" {
		t.Errorf("error: %v %v", e0, e1)
	}
	if _, ok := e1["code"]; ok {
		t.Errorf("code vacío debe omitirse: %v", e1)
	}
	if fd := m["findings"].([]any)[0].(map[string]any); fd["code"] != "blast-radius" || fd["severity"] != "warning" {
		t.Errorf("findings: %v", fd)
	}
	// TACACS
	tr, err := b.SecTacacsReport(TacacsDTO{Host: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	st := asJSON(t, tr)["steps"].([]any)[0].(map[string]any)
	if st["status"] != "PASS_ADD" || st["avPairs"].([]any)[1].(map[string]any)["direction"] != "received" || st["prompts"].([]any)[0] != "Password: " {
		t.Errorf("tacacs: %v", st)
	}
	// PKI
	pr, err := b.SecPkiDecodeReport("x")
	if err != nil || pr.Text != "pki" || len(pr.Certificates) != 2 {
		t.Fatalf("%+v %v", pr, err)
	}
	c0, c1 := asJSON(t, pr.Certificates[0]), asJSON(t, pr.Certificates[1])
	if c0["daysLeft"] != 9.0 || c0["key"].(map[string]any)["curve"] != "P-256" || c0["signature"].(map[string]any)["valid"] != true || c0["isCa"] != true ||
		c0["warnings"].([]any)[0].(map[string]any)["code"] != "expires_soon" || c0["notAfter"] != "2026-11-21T00:00:00Z" {
		t.Errorf("certificado: %v", c0)
	}
	for _, k := range []string{"daysLeft", "notAfter", "notBefore", "issuer", "serial"} {
		if _, ok := c1[k]; ok {
			t.Errorf("csr: %s debe omitirse: %v", k, c1)
		}
	}
	if _, ok := c1["signature"].(map[string]any)["valid"]; ok || c1["kind"] != "csr" || c1["san"] == nil || c1["warnings"] == nil {
		t.Errorf("csr: %v", c1)
	}
	ca, err := b.SecPkiCaInit("ca", 10, "p256", "pw")
	if err != nil || !ca.LabWarning || len(ca.Certificates) != 1 || ca.Pem != "PEM" {
		t.Fatalf("%+v %v", ca, err)
	}
	// pcap
	pc, err := b.ToolsPcapReport("/x.pcap", 0)
	if err != nil {
		t.Fatal(err)
	}
	pm := asJSON(t, pc)
	sum := pm["summary"].(map[string]any)
	if sum["packets"] != 5.0 || sum["bytes"] != 5000000000.0 || sum["durationMs"] != 11.0 || pm["fragments"] != 1.0 || pm["topTalkers"].([]any)[0].(map[string]any)["ip"] != "10.0.0.1" ||
		pm["tcp"].(map[string]any)["failedHandshakes"].([]any)[0].(map[string]any)["count"] != 2.0 || pm["dns"].(map[string]any)["unanswered"].([]any)[0].(map[string]any)["name"] != "n" ||
		pm["neighbors"].([]any)[0].(map[string]any)["nativeVlan"] != 10.0 || pm["arpConflicts"].([]any)[0].(map[string]any)["macs"].([]any)[1] != "m2" ||
		pm["sections"].([]any)[1].(map[string]any)["args"].(map[string]any)["ip"] != "10.0.0.50" || pm["warnings"].([]any)[0].(map[string]any)["key"] != "pcap.warn.truncated" || pm["tls"] == nil {
		t.Errorf("pcap: %v", pm)
	}
	// calc: campos nuevos
	cr, err := b.Calc("subnet", `{"prefix":"x"}`)
	if err != nil {
		t.Fatal(err)
	}
	cm := asJSON(t, cr)
	tb := cm["tables"].([]any)[0].(map[string]any)
	rl := tb["rowLabels"].([]any)
	if tb["titleKey"] != "calc.title.subnet" || tb["titleArgs"].(map[string]any)["prefix"] != "x" || tb["columns"].([]any)[1].(map[string]any)["key"] != "calc.col.value" ||
		rl[0].(map[string]any)["key"] != "calc.row.network" || rl[1].(map[string]any)["key"] != "" || cm["notesStructured"].([]any)[0].(map[string]any)["key"] != "calc.note.host_in_subnet" {
		t.Errorf("calc: %v", cm)
	}
}

// El JSON de hoy no cambia: sin claves en la respuesta del núcleo, los DTO no agregan campos.
func TestDTOsSinCamposNuevosSiNoHayDato(t *testing.T) {
	old := CalcResultDTO{Text: "ok", Tables: []CalcTableDTO{{Title: "T", Head: []string{"a"}, Rows: [][]string{{"1"}}}}, Notes: []string{"n"}}
	b, _ := json.Marshal(old)
	if want := `{"text":"ok","tables":[{"title":"T","head":["a"],"rows":[["1"]]}],"notes":["n"]}`; string(b) != want {
		t.Errorf("calc: %s", b)
	}
	b, _ = json.Marshal(PkiResultDTO{Pem: "p", Key: "k", Text: "t"})
	if want := `{"pem":"p","key":"k","text":"t"}`; string(b) != want {
		t.Errorf("pki: %s", b)
	}
	if strings.Contains(string(b), "certificates") {
		t.Error("certificates sin dato")
	}
}
