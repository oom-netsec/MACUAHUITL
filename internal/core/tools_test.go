package core

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/syslogd/syslogdtest"
)

func TestToolsPcapAnalyzesAndAudits(t *testing.T) {
	h := newHarness(t, nil)
	p := filepath.Join(t.TempDir(), "vacia.pcap")
	f, _ := os.Create(p)
	pcapgo.NewWriter(f).WriteFileHeader(65535, layers.LinkTypeEthernet)
	f.Close()
	tc := v1.NewToolsServiceClient(h.conn)
	r, err := tc.AnalyzePcap(ctx(t), &v1.AnalyzePcapRequest{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Text == "" || !json.Valid([]byte(r.Report.Json)) {
		t.Fatalf("report: %+v", r.Report)
	}
	if !strings.Contains(h.auditText(t), `"action":"tools.pcap"`) {
		t.Fatal("pcap not audited")
	}
	if _, err := tc.AnalyzePcap(ctx(t), &v1.AnalyzePcapRequest{Path: "rel.pcap"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("relative path: %v", err)
	}
}

func TestToolsDnsDeepModesRequireDeep(t *testing.T) {
	h := newHarness(t, nil)
	tc := v1.NewToolsServiceClient(h.conn)
	for _, m := range []v1.DnsMode{v1.DnsMode_DNS_MODE_TRACE, v1.DnsMode_DNS_MODE_ZONE, v1.DnsMode_DNS_MODE_DNSSEC} {
		if _, err := tc.Dns(ctx(t), &v1.DnsRequest{Mode: m, Name: "example.com"}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%v without deep: %v", m, err)
		}
	}
	if strings.Contains(h.auditText(t), `"action":"dns.contact"`) {
		t.Fatal("contacted servers without deep")
	}
	if _, err := tc.Dns(ctx(t), &v1.DnsRequest{Mode: v1.DnsMode_DNS_MODE_QUERY, Name: "x", Servers: []string{"udp://-bad"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad server: %v", err)
	}
}

func TestToolsDnsLightAuditsEachContact(t *testing.T) {
	h := newHarness(t, nil)
	r, err := v1.NewToolsServiceClient(h.conn).Dns(ctx(t), &v1.DnsRequest{Mode: v1.DnsMode_DNS_MODE_QUERY, Name: "example.com", Servers: []string{"127.0.0.1:1"}, TimeoutMs: 300})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(r.Report.Json)) {
		t.Fatalf("json: %s", r.Report.Json)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"dns.run"`) || !strings.Contains(txt, `"action":"dns.contact"`) || !strings.Contains(txt, `127.0.0.1`) {
		t.Fatalf("audit:\n%s", txt)
	}
}

func TestToolsTlsAuditsAndReportsFailure(t *testing.T) {
	h := newHarness(t, nil)
	_, err := v1.NewToolsServiceClient(h.conn).InspectTls(ctx(t), &v1.InspectTlsRequest{Host: "127.0.0.1", Port: 1, TimeoutMs: 300})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(h.auditText(t), `"action":"tools.tls"`) {
		t.Fatal("tls not audited")
	}
}

func TestToolsSyslogListensAndStops(t *testing.T) {
	h := newHarness(t, nil)
	tc := v1.NewToolsServiceClient(h.conn)
	st, err := tc.Syslog(ctx(t), &v1.SyslogRequest{Addr: "0.0.0.0:5514"})
	if err == nil {
		_, err = st.Recv()
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("0.0.0.0 without allow_any: %v", err)
	}
	st, err = tc.Syslog(ctx(t), &v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil || !strings.HasPrefix(first.Listening, "127.0.0.1:") || !strings.HasPrefix(first.OutputPath, h.out) {
		t.Fatalf("first = %+v, %v", first, err)
	}
	for {
		if _, err = st.Recv(); err != nil {
			break
		}
	}
	if err != io.EOF {
		t.Fatalf("stream end: %v", err)
	}
	a := h.auditText(t)
	if !strings.Contains(a, `"action":"tools.syslog"`) {
		t.Fatal("syslog not audited")
	}
	for _, want := range []string{"tasa_origen=100", "rafaga_origen=200", "tasa_global=1000", "rafaga_global=2000", "cola=4096", "rotar_mb=50", "rotar_min=0", "max_archivos=20", "plantilla=syslog_{fecha}_{hora}", "formato=texto"} {
		if !strings.Contains(a, want) {
			t.Errorf("default sin auditar: %s", want)
		}
	}
}

// Fase 28a: cada tope y cada campo del archivo se valida antes de abrir el socket.
func TestToolsSyslogRejectsOutOfRange(t *testing.T) {
	h := newHarness(t, nil)
	tc := v1.NewToolsServiceClient(h.conn)
	for name, r := range map[string]*v1.SyslogRequest{
		"tasa origen alta":    {RatePerSource: 10001},
		"tasa origen neg":     {RatePerSource: -1},
		"rafaga origen neg":   {BurstPerSource: -1},
		"tasa global alta":    {RateGlobal: 100001},
		"rafaga global":       {BurstGlobal: 1000001},
		"cola baja":           {QueueSize: 63},
		"cola alta":           {QueueSize: 65537},
		"mb alto":             {RotateMb: 1025},
		"mb neg":              {RotateMb: -1},
		"minutos neg":         {RotateMinutes: -1},
		"minutos altos":       {RotateMinutes: 7*24*60 + 1},
		"minutos enormes":     {RotateMinutes: 2147483647},
		"archivos alto":       {MaxFiles: 1001},
		"archivos neg":        {MaxFiles: -2},
		"formato":             {Format: "xml"},
		"plantilla":           {NameTemplate: "../x"},
		"plantilla sin fecha": {NameTemplate: "fijo"},
	} {
		r.Addr = "127.0.0.1:0"
		st, err := tc.Syslog(ctx(t), r)
		if err == nil {
			_, err = st.Recv()
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestToolsSyslogAuditsConfigRetentionAndDrops(t *testing.T) {
	h := newHarness(t, nil)
	tc := v1.NewToolsServiceClient(h.conn)
	dir := filepath.Join(h.out, "syslog")
	os.MkdirAll(dir, 0o700)
	old := time.Now().Add(-48 * time.Hour)
	for _, n := range []string{"lab_20200101_000000.jsonl", "lab_20200102_000000.jsonl", "ajeno.jsonl"} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600)
		os.Chtimes(filepath.Join(dir, n), old, old)
	}
	st, err := tc.Syslog(ctx(t), &v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 2, Save: true, MaxFiles: 1, NameTemplate: "lab_{fecha}_{hora}", Format: "jsonl",
		RatePerSource: 1, BurstPerSource: 1, RotateMb: 5})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil || first.OutputPath != dir {
		t.Fatalf("first = %+v, %v", first, err)
	}
	// un origen inunda: pasa 1 y el resto se descarta
	if err := syslogdtest.SendUDP(first.Listening, "<14>hola", 20); err != nil {
		t.Fatal(err)
	}
	var rotated string
	var drops *v1.SyslogDrops
	for {
		r, err := st.Recv()
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
		if r.RotatedPath != "" {
			rotated = r.RotatedPath
		}
		if r.Drops != nil {
			drops = r.Drops
		}
	}
	if !strings.HasPrefix(rotated, dir+string(filepath.Separator)+"lab_") || !strings.HasSuffix(rotated, ".jsonl") {
		t.Errorf("rotated_path = %q", rotated)
	}
	if drops == nil || drops.PorOrigen == 0 || drops.Total != drops.PorOrigen || drops.SinceMs == 0 || len(drops.Top) != 1 || drops.Top[0].Source != "127.0.0.1" {
		t.Errorf("drops = %+v", drops)
	}
	left := map[string]bool{}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		left[e.Name()] = true
	}
	if left["lab_20200101_000000.jsonl"] || left["lab_20200102_000000.jsonl"] || !left["ajeno.jsonl"] || len(left) != 2 {
		t.Errorf("archivos = %v", left)
	}
	a := h.auditText(t)
	for _, want := range []string{`"action":"tools.syslog"`, "tasa_origen=1", "rafaga_origen=1", "tasa_global=1000", "cola=4096", "rotar_mb=5", "max_archivos=1", "formato=jsonl", "plantilla=lab_{fecha}_{hora}",
		`"action":"tools.syslog.retencion"`, "lab_20200101_000000.jsonl", "lab_20200102_000000.jsonl", `"action":"tools.syslog.done"`, "descartes=", "por_origen="} {
		if !strings.Contains(a, want) {
			t.Errorf("la auditoría no trae %q", want)
		}
	}
	if strings.Contains(a, "ajeno.jsonl") {
		t.Error("el archivo ajeno no debía aparecer")
	}
}
