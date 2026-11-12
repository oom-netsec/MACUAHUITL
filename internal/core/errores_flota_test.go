package core

import (
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Los errores gRPC de flota, análisis, deriva y cambios: con es, el texto de siempre; con en, inglés con su reason.
func TestErroresGrpcDeFlotaAnalisisCambiosYDeriva(t *testing.T) {
	h := newHarness(t, nil)
	fx := newFlotaFx(t)
	fc := v1.NewFleetServiceClient(h.conn)
	ac := v1.NewAnalysisServiceClient(h.conn)
	dc := v1.NewDriftServiceClient(h.conn)
	cc := v1.NewChangeServiceClient(h.conn)
	fdir := fixFleetDir(t)
	for _, c := range []struct {
		name   string
		call   func(lang string) error
		code   codes.Code
		es, en string
		reason string
	}{
		{"ruta relativa", func(l string) error { _, e := fc.Find(con(t, l), &v1.FindRequest{Dir: "rel", Query: "x"}); return e }, codes.InvalidArgument, `la ruta "rel" debe ser absoluta`, `the path "rel" must be absolute`, "fleet.err.relative_path"},
		{"sin consulta", func(l string) error { _, e := fc.Find(con(t, l), &v1.FindRequest{Dir: fdir}); return e }, codes.InvalidArgument, "indica una IP, MAC o nombre", "give an IP, MAC or name", "fleet.err.empty_query"},
		{"trace", func(l string) error { _, e := fc.Trace(con(t, l), &v1.TraceRequest{Dir: fdir}); return e }, codes.InvalidArgument, "indica una MAC o una IP", "give a MAC or an IP", "fleet.err.empty_trace"},
		{"path", func(l string) error { _, e := fc.Path(con(t, l), &v1.PathRequest{Dir: fdir}); return e }, codes.InvalidArgument, "indica origen y destino", "give a source and a destination", "fleet.err.empty_path"},
		{"tamaño", func(l string) error {
			_, e := fc.Capacity(con(t, l), &v1.CapacityRequest{Dir: fdir, Need: "mucho"})
			return e
		}, codes.InvalidArgument, `tamaño "mucho" inválido: usa 800M, 1.2G, 500000`, `invalid size "mucho": use 800M, 1.2G, 500000`, "fleet.err.bad_size"},
		{"sin salidas", func(l string) error { _, e := fc.Summary(con(t, l), &v1.SummaryRequest{Dir: fx.empty}); return e }, codes.FailedPrecondition, "flota: " + fx.empty + " no contiene salidas de Patrol (carpetas <equipo>_<ip> con encabezados =====)", "fleet: " + fx.empty + " has no Patrol outputs (<device>_<ip> folders with ===== headers)", "fleet.err.no_outputs"},
		{"rondas", func(l string) error {
			_, e := ac.DiffRounds(con(t, l), &v1.DiffRoundsRequest{Job: labDir(t), From: 1, To: 9})
			return e
		}, codes.InvalidArgument, "analyze: el trabajo tiene las rondas [1 2 3]; no hay 1 o 9", "analyze: the job has rounds [1 2 3]; there is no 1 or 9", "analyze.err.rounds"},
		{"carpeta vacía", func(l string) error {
			_, e := ac.AnalyzeJob(con(t, l), &v1.AnalyzeJobRequest{Job: fx.empty})
			return e
		}, codes.FailedPrecondition, "analyze: " + fx.empty + " no contiene salidas de Patrol", "analyze: " + fx.empty + " has no Patrol outputs", "analyze.err.no_outputs"},
		{"pcap relativo", func(l string) error {
			_, e := ac.Timeline(con(t, l), &v1.TimelineRequest{Job: labDir(t), PcapPath: "rel.pcap"})
			return e
		}, codes.InvalidArgument, "la ruta de la captura debe ser absoluta", "the capture path must be absolute", "analyze.err.pcap_path"},
		{"deriva carpeta vacía", func(l string) error { _, e := dc.Drift(con(t, l), &v1.DriftRequest{Job: fx.empty}); return e }, codes.FailedPrecondition, "analyze: " + fx.empty + " no contiene salidas de Patrol", "analyze: " + fx.empty + " has no Patrol outputs", "analyze.err.no_outputs"},
		{"cambio sin entrada", func(l string) error { _, e := cc.GetChangeReport(con(t, l), &v1.GetChangeReportRequest{}); return e }, codes.InvalidArgument, "indica el cambio o las dos carpetas (rutas absolutas)", "give the change or the two folders (absolute paths)", "change.err.no_input"},
		{"cambio inexistente", func(l string) error {
			_, e := cc.GetChangeReport(con(t, l), &v1.GetChangeReportRequest{ChangeId: "nada"})
			return e
		}, codes.NotFound, "cambio nada no existe", "change nada does not exist", "change.err.not_found"},
		{"sin definición", func(l string) error { _, e := cc.CreateChange(con(t, l), &v1.CreateChangeRequest{}); return e }, codes.InvalidArgument, "falta la definición del cambio", "the change definition is missing", "change.err.no_spec"},
		{"upgrade sin salidas", func(l string) error {
			_, e := cc.CheckUpgrade(con(t, l), &v1.CheckUpgradeRequest{Outputs: "nada"})
			return e
		}, codes.InvalidArgument, "no se reconocieron salidas: usa un archivo de Patrol o una sesión con prompts (SW1#show version)", "no outputs were recognized: use a Patrol file or a session with prompts (SW1#show version)", "upgrade.err.no_outputs"},
	} {
		for _, lang := range []string{"", "es", "fr"} {
			if err := c.call(lang); status.Code(err) != c.code || status.Convert(err).Message() != c.es {
				t.Errorf("%s con %q: %v, quería %q", c.name, lang, err, c.es)
			}
		}
		err := c.call("en")
		if status.Code(err) != c.code || status.Convert(err).Message() != c.en {
			t.Errorf("%s en: %v, quería %q", c.name, err, c.en)
		}
		if why, _ := reasonOf(err); why != c.reason {
			t.Errorf("%s: reason %q, quería %q", c.name, why, c.reason)
		}
		if m := españolFlota.FindString(strings.ReplaceAll(status.Convert(err).Message(), "<equipo>", "")); m != "" {
			t.Errorf("%s: español (%s) en %q", c.name, m, status.Convert(err).Message())
		}
	}
}

func fixFleetDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs("../fleet/testdata/outputs")
	if err != nil {
		t.Fatal(err)
	}
	return d
}
