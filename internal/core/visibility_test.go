package core

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp/snmptest"
)

func TestVisibilityTopologyFromDir(t *testing.T) {
	h := newHarness(t, nil)
	vc := v1.NewVisibilityServiceClient(h.conn)
	dir, _ := filepath.Abs("../topo/testdata/trabajo_20261104-100000")
	r, err := vc.BuildTopology(ctx(t), &v1.BuildTopologyRequest{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Nodes    []any `json:"nodes"`
		Findings []any `json:"findings"`
	}
	if json.Unmarshal([]byte(r.Report.Json), &g) != nil || len(g.Nodes) != 4 || len(g.Findings) != 4 || !strings.HasPrefix(r.Svg, "<svg") || r.Report.Text == "" {
		t.Fatalf("respuesta = %+v", r)
	}
	if !strings.Contains(h.auditText(t), `"action":"visibility.topo"`) {
		t.Fatal("topología sin auditoría")
	}
	for _, req := range []*v1.BuildTopologyRequest{{}, {Dir: "relativa"}, {PcapPath: "x.pcap"}} {
		if _, err := vc.BuildTopology(ctx(t), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%+v: %v", req, err)
		}
	}
	if _, err := vc.BuildTopology(ctx(t), &v1.BuildTopologyRequest{JobId: "nada"}); status.Code(err) != codes.NotFound {
		t.Errorf("trabajo inexistente: %v", err)
	}
}

func TestVisibilitySnmpConCredencialDeBoveda(t *testing.T) {
	h := newHarness(t, nil)
	vc := v1.NewVisibilityServiceClient(h.conn)
	a := snmptest.New(t, "COMUNIDAD-SECRETA", nil)
	tg := &v1.SnmpTarget{Host: "127.0.0.1", Port: uint32(a.Port()), Version: "2c", CredentialId: "x", TimeoutMs: 500}
	if _, err := vc.SnmpGet(ctx(t), &v1.SnmpGetRequest{Target: tg, Oids: []string{"1.3.6.1.2.1.1.5.0"}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sin bóveda: %v", err)
	}
	h.ready(t)
	cr, _ := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "snmp-lab", Username: "snmp", Password: []byte("COMUNIDAD-SECRETA")})
	tg.CredentialId = cr.Id
	r, err := vc.SnmpGet(ctx(t), &v1.SnmpGetRequest{Target: tg, Oids: []string{"1.3.6.1.2.1.1.5.0"}})
	if err != nil || !strings.Contains(r.Report.Json, `"SW1"`) {
		t.Fatalf("get: %+v %v", r, err)
	}
	w, err := vc.SnmpWalk(ctx(t), &v1.SnmpWalkRequest{Target: tg, Oid: "1.3.6.1.2.1.31.1.1.1.1", Bulk: true})
	if err != nil || !strings.Contains(w.Report.Json, "Gi1/0/2") {
		t.Fatalf("walk: %+v %v", w, err)
	}
	st, err := vc.SnmpPoll(ctx(t), &v1.SnmpPollRequest{Target: tg, Profiles: []string{"interfaces", "cpu"}, IntervalSeconds: 1, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	var samples int
	for {
		s, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		samples++
		if !strings.Contains(s.Json, "Gi1/0/1") {
			t.Fatalf("muestra = %s", s.Json)
		}
	}
	if samples != 2 {
		t.Fatalf("muestras = %d", samples)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"visibility.snmp"`) || strings.Contains(txt, "COMUNIDAD-SECRETA") {
		t.Fatalf("auditoría:\n%s", txt)
	}
	// Destino distinto al autorizado: la consulta no sale (EgressGuard).
	if _, err := vc.SnmpGet(ctx(t), &v1.SnmpGetRequest{Target: &v1.SnmpTarget{Host: "-x", Version: "2c", CredentialId: cr.Id}, Oids: []string{"1.3.6.1"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("host inválido: %v", err)
	}
}

func TestVisibilitySnmpV3(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	a := snmptest.New(t, "", &gosnmp.UsmSecurityParameters{UserName: "noc", AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "authpass123",
		PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123"})
	cr, _ := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "snmpv3", Username: "noc", Password: []byte("authpass123"), EnableSecret: []byte("privpass123")})
	r, err := v1.NewVisibilityServiceClient(h.conn).SnmpGet(ctx(t), &v1.SnmpGetRequest{Target: &v1.SnmpTarget{Host: "127.0.0.1", Port: uint32(a.Port()), Version: "3",
		CredentialId: cr.Id, AuthProtocol: "SHA", PrivProtocol: "AES", TimeoutMs: 1000}, Oids: []string{"1.3.6.1.2.1.1.5.0"}})
	if err != nil || !strings.Contains(r.Report.Json, `"SW1"`) {
		t.Fatalf("v3: %+v %v", r, err)
	}
	if strings.Contains(h.auditText(t), "authpass123") {
		t.Fatal("llave en la auditoría")
	}
}

func TestVisibilityListeners(t *testing.T) {
	h := newHarness(t, nil)
	vc := v1.NewVisibilityServiceClient(h.conn)
	tr, err := vc.SnmpTraps(ctx(t), &v1.SnmpTrapsRequest{Addr: "127.0.0.1:162"})
	if err == nil {
		_, err = tr.Recv()
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("162: %v", err)
	}
	tr, err = vc.SnmpTraps(ctx(t), &v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := tr.Recv()
	if err != nil || !strings.HasPrefix(first.Listening, "127.0.0.1:") || !strings.HasPrefix(first.OutputPath, h.out) {
		t.Fatalf("traps = %+v %v", first, err)
	}
	for err == nil {
		_, err = tr.Recv()
	}
	fl, err := vc.Flows(ctx(t), &v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	var final bool
	for {
		r, err := fl.Recv()
		if err != nil {
			break
		}
		final = final || r.Final
	}
	if !final {
		t.Fatal("sin resumen final de flujos")
	}
	txt := h.auditText(t)
	for _, a := range []string{"visibility.traps", "visibility.traps.done", "visibility.flows", "visibility.flows.done"} {
		if !strings.Contains(txt, `"action":"`+a+`"`) {
			t.Errorf("falta %s en la auditoría", a)
		}
	}
}

func TestVisibilityGnmi(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	cr, _ := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "gnmi", Username: "noc", Password: []byte("GNMI-PW")})
	vc := v1.NewVisibilityServiceClient(h.conn)
	tg := &v1.GnmiTarget{Host: "127.0.0.1", Port: 1, CredentialId: cr.Id, TimeoutMs: 500}
	if _, err := vc.GnmiGet(ctx(t), &v1.GnmiGetRequest{Target: tg, Paths: []string{"/system"}}); status.Code(err) != codes.Unavailable {
		t.Fatalf("puerto cerrado: %v", err)
	}
	tg.CaPath = "ca.pem"
	if _, err := vc.GnmiGet(ctx(t), &v1.GnmiGetRequest{Target: tg, Paths: []string{"/system"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CA relativa: %v", err)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"visibility.gnmi"`) || strings.Contains(txt, "GNMI-PW") {
		t.Fatalf("auditoría:\n%s", txt)
	}
}
