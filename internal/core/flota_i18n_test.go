package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// flotaRec es lo que se compara de cada respuesta: el informe (json y texto) o el error, y lo suelto de ACL.
type flotaRec struct {
	Json, Text, Err string `json:",omitempty"`
	Extra           string `json:",omitempty"`
	// Keys son las claves de textos del informe (ToolReport.keys); no entran en la comparación con el golden.
	Keys textRefs `json:"-"`
}

func (r flotaRec) same(o flotaRec) bool {
	r.Keys, o.Keys = nil, nil
	return reflect.DeepEqual(r, o)
}

func recOf(r interface{ GetReport() *v1.ToolReport }, err error) flotaRec {
	if err != nil {
		return flotaRec{Err: err.Error()}
	}
	return flotaRec{Json: r.GetReport().GetJson(), Text: r.GetReport().GetText(), Keys: keysOf(r.GetReport())}
}

// changeDirs arma dos trabajos de Patrol terminados (PRE y POST) con las salidas de prueba del paquete change.
func changeDirs(t *testing.T) (pre, post string) {
	t.Helper()
	mk := func(file string) string {
		dir := t.TempDir()
		b, err := os.ReadFile("../change/testdata/" + file)
		if err != nil {
			t.Fatal(err)
		}
		man := patrol.Manifest{Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "192.0.2.1"}, Round: 1, Hostname: "DIST-01", State: "completed"}}}
		mb, _ := json.Marshal(man)
		os.WriteFile(filepath.Join(dir, "manifest.json"), mb, 0o600)
		dd := filepath.Join(dir, patrol.DeviceDir("DIST-01", "192.0.2.1"))
		os.MkdirAll(dd, 0o755)
		os.WriteFile(filepath.Join(dd, "r001_20261106-100000.txt"), b, 0o600)
		return dir
	}
	return mk("pre.txt"), mk("post.txt")
}

// flotaCases corre cada RPC de flota, análisis, ACL, cambios y deriva con entradas que recorren sus textos.
func flotaCases(t *testing.T, h *harness, lang string, fx flotaFx) map[string]flotaRec {
	t.Helper()
	c := func() ctxT { return con(t, lang) }
	out := map[string]flotaRec{}
	fdir, _ := filepath.Abs("../fleet/testdata/outputs")
	fc := v1.NewFleetServiceClient(h.conn)
	for _, q := range []string{"10.1.10.20", "aabb.cc00.0a01", "dist1", "nada"} {
		r, err := fc.Find(c(), &v1.FindRequest{Dir: fdir, Query: q})
		out["fleet.find."+q] = recOf(r, err)
	}
	for _, q := range []string{"aabb.cc00.0a01", "aabb.cc00.9999", "10.7.7.7", "x"} {
		r, err := fc.Trace(c(), &v1.TraceRequest{Dir: fdir, Query: q})
		out["fleet.trace."+q] = recOf(r, err)
	}
	for _, p := range [][2]string{{"10.1.10.20", "10.1.20.50"}, {"10.1.10.20", "172.31.0.1"}, {"10.1.20.50", "192.0.2.1"}, {"203.0.113.5", "10.1.20.50"}, {"x", "y"}} {
		r, err := fc.Path(c(), &v1.PathRequest{Dir: fdir, Query: p[0], Dst: p[1]})
		rec := recOf(r, err)
		rec.Extra = r.GetSvg()
		out["fleet.path."+p[0]+">"+p[1]] = rec
	}
	rh, err := fc.Health(c(), &v1.HealthRequest{Dir: fdir})
	out["fleet.health"] = recOf(rh, err)
	rs, err := fc.Summary(c(), &v1.SummaryRequest{Dir: fdir})
	out["fleet.summary"] = recOf(rs, err)
	rc, err := fc.Capacity(c(), &v1.CapacityRequest{Dir: fdir, Need: "1G"})
	out["fleet.capacity"] = recOf(rc, err)
	ri, err := fc.Inventory(c(), &v1.InventoryRequest{Dir: fdir})
	out["fleet.inventory"] = recOf(ri, err)

	ac := v1.NewAnalysisServiceClient(h.conn)
	for _, rd := range []uint32{0, 1, 2, 3} {
		r, err := ac.AnalyzeJob(c(), &v1.AnalyzeJobRequest{Job: labDir(t), Round: rd})
		out["analysis.job."+string(rune('0'+rd))] = recOf(r, err)
	}
	for _, d := range [][2]uint32{{1, 2}, {2, 3}, {1, 3}} {
		r, err := ac.DiffRounds(c(), &v1.DiffRoundsRequest{Job: labDir(t), From: d[0], To: d[1]})
		out["analysis.diff."+string(rune('0'+d[0]))+string(rune('0'+d[1]))] = recOf(r, err)
	}
	r1, err := ac.Timeline(c(), &v1.TimelineRequest{Job: labDir(t)})
	out["analysis.timeline.all"] = recOf(r1, err)
	r2, err := ac.Timeline(c(), &v1.TimelineRequest{Job: labDir(t), Around: timestamppb.New(time.Date(2026, 11, 4, 10, 9, 18, 0, time.UTC)), WindowSeconds: 30, Device: "RTR2"})
	out["analysis.timeline.rtr2"] = recOf(r2, err)

	al := v1.NewAclServiceClient(h.conn)
	for _, v := range []string{"asa", "ios-xe", "nx-os"} {
		b, _ := os.ReadFile("../acl/testdata/" + map[string]string{"asa": "asa.txt", "ios-xe": "iosxe.txt", "nx-os": "nxos.txt"}[v])
		imp, err := al.Import(c(), &v1.ImportRequest{Vendor: v, Text: string(b)})
		if err != nil {
			out["acl.import."+v] = flotaRec{Err: err.Error()}
			continue
		}
		an, err := al.Analyze(c(), &v1.AnalyzeRequest{Acl: imp.Acl})
		out["acl.analyze."+v] = aclRec(an.GetFindings(), err)
		for _, tgt := range []string{"ios-xe", "nx-os", "asa", "junos"} {
			g, err := al.Generate(c(), &v1.GenerateRequest{Acl: imp.Acl, Vendor: tgt})
			out["acl.generate."+v+">"+tgt] = flotaRec{Text: g.GetScript(), Err: errStr(err)}
		}
	}
	for i, txt := range []string{"access-list X extended permit ip 10.0.0.0 0.0.0.255 any\n", "access-list EDGE extended permit tcp any any eq\n", "basura\n", ""} {
		_, err := al.Import(c(), &v1.ImportRequest{Vendor: "asa", Text: txt})
		out["acl.import.err."+string(rune('0'+i))] = flotaRec{Err: errStr(err)}
	}
	shadow := &v1.Acl{Name: "T", Rules: []*v1.AclRule{
		{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: "ip", Source: "10.0.0.0/8", Destination: "0.0.0.0/0"},
		{Action: v1.AclAction_ACL_ACTION_DENY, Protocol: "tcp", Source: "10.1.0.0/16", Destination: "0.0.0.0/0", DestinationPorts: "eq 22"},
		{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: "tcp", Source: "10.1.0.0/16", Destination: "0.0.0.0/0", DestinationPorts: "eq 80"},
		{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: "icmp", Source: "10.0.0.0/8", Destination: "0.0.0.0/0", DestinationPorts: "eq 80"},
	}}
	an, err := al.Analyze(c(), &v1.AnalyzeRequest{Acl: shadow})
	out["acl.analyze.shadow"] = aclRec(an.GetFindings(), err)
	_, err = al.Analyze(c(), &v1.AnalyzeRequest{Acl: &v1.Acl{Rules: []*v1.AclRule{{Source: "mal", Destination: "0.0.0.0/0"}}}})
	out["acl.analyze.err"] = flotaRec{Err: errStr(err)}

	cc := v1.NewChangeServiceClient(h.conn)
	pre, post := fx.pre, fx.post
	rg, err := cc.GetChangeReport(c(), &v1.GetChangeReportRequest{PreDir: pre, PostDir: post})
	out["change.report"] = recOf(rg, err)
	rg, err = cc.GetChangeReport(c(), &v1.GetChangeReportRequest{PreDir: post, PostDir: pre})
	out["change.report.inverso"] = recOf(rg, err)
	rg, err = cc.GetChangeReport(c(), &v1.GetChangeReportRequest{PreDir: pre, PostDir: fx.empty})
	out["change.report.err"] = recOf(rg, err)
	for _, f := range []string{"c9600-install-sso.txt", "isr4451-bundle.txt"} {
		b, _ := os.ReadFile("../upgrade/testdata/" + f)
		for i, img := range []*v1.CheckUpgradeRequest{
			{ImageFile: "cat9k_iosxe.17.12.04.SPA.bin", ImageSize: 1197445748, ImageMd5: "7C2FE5E8A1F6A8E4AD3CD1C7A2D1B0E9"},
			{ImageFile: "bootflash:isr4400-universalk9.17.09.04a.SPA.bin", ImageSize: 700000000, ImageMd5: "0123456789abcdef0123456789abcdef"},
			{ImageFile: "x.bin", ImageSize: 1 << 40},
		} {
			img.Outputs = string(b)
			r, err := cc.CheckUpgrade(c(), img)
			out["upgrade."+f+"."+string(rune('0'+i))] = recOf(r, err)
		}
	}
	_, err = cc.CheckUpgrade(c(), &v1.CheckUpgradeRequest{Outputs: "nada"})
	out["upgrade.err"] = flotaRec{Err: errStr(err)}
	for _, f := range []string{"debil.txt", "endurecido.txt"} {
		b, _ := os.ReadFile("../compliance/testdata/" + f)
		r, err := cc.CheckCompliance(c(), &v1.CheckComplianceRequest{Config: string(b)})
		out["compliance."+f] = recOf(r, err)
		tp, _ := os.ReadFile("../compliance/testdata/plantilla.txt")
		r, err = cc.CheckCompliance(c(), &v1.CheckComplianceRequest{Config: string(b), Template: string(tp)})
		out["compliance.plantilla."+f] = recOf(r, err)
	}
	_, err = cc.CheckCompliance(c(), &v1.CheckComplianceRequest{Config: "hostname X\n", Template: "[[mal"})
	out["compliance.err"] = flotaRec{Err: errStr(err)}

	dc := v1.NewDriftServiceClient(h.conn)
	ddir := fx.drift
	for _, q := range []*v1.DriftRequest{{Job: ddir}, {Job: ddir, Round: 2, Device: "sw2"}, {Job: ddir, Round: 2}} {
		r, err := dc.Drift(c(), q)
		out["drift."+string(rune('0'+q.Round))+q.Device] = recOf(r, err)
	}
	_, err = dc.Drift(c(), &v1.DriftRequest{Job: ddir, Round: 1})
	out["drift.err"] = flotaRec{Err: errStr(err)}

	cl := v1.NewCleanerServiceClient(h.conn)
	b, _ := os.ReadFile("../cleaner/testdata/sucia.txt")
	r, err := cl.Clean(c(), &v1.CleanRequest{Text: string(b)})
	rec := recOf(r, err)
	rec.Extra = r.GetOutput()
	out["cleaner.sucia"] = rec
	extraCases(t, h, c, fx, out)
	// las rutas de carpetas temporales cambian en cada corrida
	rep := strings.NewReplacer(fx.driftMasked, "<DRIFTM>", fx.diffJob, "<DIFFJOB>", fx.pcap, "<PCAP>", fx.pcapTrunc, "<PCAPT>", fx.pre, "<PRE>", fx.post, "<POST>", fx.empty, "<EMPTY>", fx.drift, "<DRIFT>", labDir(t), "<LAB>", fdir, "<FLEET>")
	for k, v := range out {
		out[k] = flotaRec{Json: rep.Replace(v.Json), Text: rep.Replace(v.Text), Err: rep.Replace(v.Err), Extra: rep.Replace(v.Extra), Keys: v.Keys}
	}
	return out
}

// flotaFx son las carpetas de entrada, iguales en todas las corridas de una prueba.
type flotaFx struct {
	pre, post, empty, drift string
	driftMasked, diffJob    string // deriva con secretos enmascarados; trabajo con diferencias enormes entre rondas
	pcap, pcapTrunc         string // capturas de prueba (la segunda, truncada)
}

func newFlotaFx(t *testing.T) flotaFx {
	pre, post := changeDirs(t)
	masked := driftDir(t)
	mb, _ := json.Marshal(patrol.Manifest{Masked: true})
	os.WriteFile(filepath.Join(masked, "manifest.json"), mb, 0o600)
	return flotaFx{pre, post, t.TempDir(), driftDir(t), masked, diffJobDir(t), writePcap(t, false), writePcap(t, true)}
}

// aclRec es la respuesta de Analyze con los tres campos de siempre en el json; las claves de cada detalle van aparte.
func aclRec(fs []*v1.Finding, err error) flotaRec {
	type old struct {
		RuleIndex uint32 `json:"rule_index,omitempty"`
		Kind      string `json:"kind,omitempty"`
		Detail    string `json:"detail,omitempty"`
	}
	var o []old
	for _, f := range fs {
		o = append(o, old{f.RuleIndex, f.Kind, f.Detail})
	}
	bj, _ := json.Marshal(o)
	return flotaRec{Json: string(bj), Err: errStr(err), Keys: aclKeysOf(fs)}
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Regresión: sin accept-language, o con es, cada RPC de flota, análisis, ACL, cambios y deriva da lo de antes de la fase.
func TestFlotaRegresionEs(t *testing.T) {
	h := newHarness(t, nil)
	fx := newFlotaFx(t)
	base := flotaCases(t, h, "", fx)
	for _, lang := range []string{"es", "es-MX", "fr"} {
		for n, r := range flotaCases(t, h, lang, fx) {
			if !r.same(base[n]) {
				t.Errorf("%s con %q difiere de sin idioma", n, lang)
			}
		}
	}
	const file = "testdata/flota_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(base, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]flotaRec
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(base))
	for n := range base {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if n == "compliance.plantilla.debil.txt" { // la fase 30c también oculta la comunidad de snmp-server: es lo único que cambia
			w := want[n]
			re := regexp.MustCompile(`(snmp-server community) [A-Za-z0-9_-]+`)
			w.Json, w.Text = re.ReplaceAllString(w.Json, `$1 \u003coculto\u003e`), re.ReplaceAllString(w.Text, "$1 <oculto>")
			want[n] = w
		}
		if !base[n].same(want[n]) {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, base[n], want[n])
		}
	}
	if len(base) != len(want) {
		t.Errorf("casos: %d vs %d", len(base), len(want))
	}
}

// bigLines arma n líneas distintas con el prefijo p.
func bigLines(n int, p string) string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, p+strconv.Itoa(i))
	}
	return strings.Join(l, "\n")
}

// diffJobDir arma un trabajo con dos rondas cuyas diferencias son demasiado grandes y demasiado largas.
func diffJobDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	put := func(dev, file, body string) {
		p := filepath.Join(d, dev)
		os.MkdirAll(p, 0o755)
		os.WriteFile(filepath.Join(p, file), []byte(body), 0o600)
	}
	sec := func(ts, cmd, body string) string { return "===== " + ts + " · " + cmd + " =====\n" + body + "\n" }
	put("R1_10.0.0.1", "r001_20261104-100000.txt", sec("2026-11-04T10:00:01Z", "show alfa", "uno")+sec("2026-11-04T10:00:02Z", "show enorme", bigLines(2100, "a"))+sec("2026-11-04T10:00:03Z", "show largo", bigLines(10, "l")))
	put("R1_10.0.0.1", "r002_20261104-101000.txt", sec("2026-11-04T10:10:01Z", "show beta", "dos")+sec("2026-11-04T10:10:02Z", "show enorme", bigLines(2100, "b"))+sec("2026-11-04T10:10:03Z", "show largo", bigLines(500, "m")))
	put("R2_10.0.0.2", "r001_20261104-100000.txt", sec("2026-11-04T10:00:01Z", "show alfa", "uno"))
	return d
}

// extraCases son los escenarios que los datos de ejemplo de arriba no alcanzan: limpieza con orden, deriva con
// secretos enmascarados, línea de tiempo con captura y syslog, diferencias enormes y errores de entrada.
func extraCases(t *testing.T, h *harness, c func() ctxT, fx flotaFx, out map[string]flotaRec) {
	t.Helper()
	cl := v1.NewCleanerServiceClient(h.conn)
	b, _ := os.ReadFile("../cleaner/testdata/sucia.txt")
	r, err := cl.Clean(c(), &v1.CleanRequest{Text: string(b), Sort: true})
	rec := recOf(r, err)
	rec.Extra = r.GetOutput()
	out["cleaner.sucia-orden"] = rec
	dc := v1.NewDriftServiceClient(h.conn)
	dr, err := dc.Drift(c(), &v1.DriftRequest{Job: fx.driftMasked})
	out["drift.enmascarada"] = recOf(dr, err)

	ac := v1.NewAnalysisServiceClient(h.conn)
	dd, err := ac.DiffRounds(c(), &v1.DiffRoundsRequest{Job: fx.diffJob, From: 1, To: 2})
	out["analysis.diff.notas"] = recOf(dd, err)
	// syslog del receptor, con una línea malformada, y una captura completa y otra truncada
	dir := filepath.Join(h.out, "syslog")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "syslog_20261105-000000.log"), []byte("2026-11-06T18:00:03Z 10.0.0.2:514 <189>%BGP-5-ADJCHANGE: neighbor 10.0.13.1 Down\nmalformada\n"), 0o600)
	around := timestamppb.New(time.Date(2026, 11, 6, 18, 0, 5, 0, time.UTC))
	for name, p := range map[string]string{"pcap": fx.pcap, "pcap-truncada": fx.pcapTrunc} {
		tr, err := ac.Timeline(c(), &v1.TimelineRequest{Job: labDir(t), Around: around, WindowSeconds: 3600, PcapPath: p})
		out["analysis.timeline."+name] = recOf(tr, err)
	}

	cc := v1.NewChangeServiceClient(h.conn)
	for i, img := range []*v1.CheckUpgradeRequest{{ImageFile: ""}, {ImageFile: "a/b.bin"}, {ImageFile: "x.bin", ImageMd5: "zz"}, {ImageFile: "x.bin", ImageSize: -1}} {
		bb, _ := os.ReadFile("../upgrade/testdata/c9600-install-sso.txt")
		img.Outputs = string(bb)
		_, err := cc.CheckUpgrade(c(), img)
		out["upgrade.err."+strconv.Itoa(i)] = flotaRec{Err: errStr(err)}
	}
	for i, q := range []*v1.CheckComplianceRequest{{Config: ""}, {Config: "hostname X\n", Template: "- foo\n bar\n"}, {Config: "hostname X\n", Template: "? foo\n"}, {Config: "hostname X\n", Template: "# nada\n"}} {
		_, err := cc.CheckCompliance(c(), q)
		out["compliance.err."+strconv.Itoa(i)] = flotaRec{Err: errStr(err)}
	}
	// más variantes de cambios: POST fallido, POST sin un comando y PRE y POST al revés
	pre, post := fx.pre, fx.post
	for name, q := range map[string]*v1.GetChangeReportRequest{"inverso": {PreDir: post, PostDir: pre}, "igual": {PreDir: pre, PostDir: pre}} {
		rg, err := cc.GetChangeReport(c(), q)
		out["change.report."+name] = recOf(rg, err)
	}
}
