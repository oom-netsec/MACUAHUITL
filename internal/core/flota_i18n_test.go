package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// flotaRec es lo que se compara de cada respuesta: el informe (json y texto) o el error, y lo suelto de ACL.
type flotaRec struct {
	Json, Text, Err string `json:",omitempty"`
	Extra           string `json:",omitempty"`
	// Keys son las claves de textos del informe (ToolReport.keys); no entran en la comparación con el golden.
	Keys map[string]*v1.TextRef `json:"-"`
}

func (r flotaRec) same(o flotaRec) bool {
	r.Keys, o.Keys = nil, nil
	return reflect.DeepEqual(r, o)
}

func recOf(r interface{ GetReport() *v1.ToolReport }, err error) flotaRec {
	if err != nil {
		return flotaRec{Err: err.Error()}
	}
	return flotaRec{Json: r.GetReport().GetJson(), Text: r.GetReport().GetText(), Keys: r.GetReport().GetKeys()}
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
	// las rutas de carpetas temporales cambian en cada corrida
	rep := strings.NewReplacer(fx.pre, "<PRE>", fx.post, "<POST>", fx.empty, "<EMPTY>", fx.drift, "<DRIFT>", labDir(t), "<LAB>", fdir, "<FLEET>")
	for k, v := range out {
		out[k] = flotaRec{Json: rep.Replace(v.Json), Text: rep.Replace(v.Text), Err: rep.Replace(v.Err), Extra: rep.Replace(v.Extra), Keys: v.Keys}
	}
	return out
}

// flotaFx son las carpetas de entrada, iguales en todas las corridas de una prueba.
type flotaFx struct{ pre, post, empty, drift string }

func newFlotaFx(t *testing.T) flotaFx {
	pre, post := changeDirs(t)
	return flotaFx{pre, post, t.TempDir(), driftDir(t)}
}

// aclRec es la respuesta de Analyze con los tres campos de siempre en el json; las claves de cada detalle van aparte.
func aclRec(fs []*v1.Finding, err error) flotaRec {
	type old struct {
		RuleIndex uint32 `json:"rule_index,omitempty"`
		Kind      string `json:"kind,omitempty"`
		Detail    string `json:"detail,omitempty"`
	}
	var o []old
	keys := map[string]*v1.TextRef{}
	for i, f := range fs {
		o = append(o, old{f.RuleIndex, f.Kind, f.Detail})
		if f.DetailKey != "" {
			keys[strconv.Itoa(i)+".detail"] = &v1.TextRef{Key: f.DetailKey, Args: f.DetailArgs}
		}
	}
	bj, _ := json.Marshal(o)
	return flotaRec{Json: string(bj), Err: errStr(err), Keys: keys}
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
		if !base[n].same(want[n]) {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, base[n], want[n])
		}
	}
	if len(base) != len(want) {
		t.Errorf("casos: %d vs %d", len(base), len(want))
	}
}

// jsonAt busca en un JSON decodificado la ruta rows.2.detail (índices numéricos para las listas).
func jsonAt(v any, path string) (string, bool) {
	for _, p := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i >= len(x) {
				return "", false
			}
			v = x[i]
		default:
			return "", false
		}
	}
	s, ok := v.(string)
	return s, ok
}

// checkKeys: cada clave de ToolReport.keys cae sobre un texto del json que es exactamente su plantilla en el idioma pedido.
func checkKeys(t *testing.T, lang string, cases map[string]flotaRec) (total int) {
	t.Helper()
	loc := i18n.Normalize(lang)
	for n, r := range cases {
		var doc any
		if r.Json == "" {
			continue
		}
		if err := json.Unmarshal([]byte(r.Json), &doc); err != nil {
			continue // algunas respuestas llevan otro JSON (hallazgos de ACL)
		}
		for path, ref := range r.Keys {
			got, ok := jsonAt(doc, path)
			if want := i18n.Msg(loc, ref.Key, ref.Args); !ok || got != want {
				t.Errorf("%s %s (%s): json %q, clave da %q", n, path, ref.Key, got, want)
			}
			total++
		}
	}
	return total
}
