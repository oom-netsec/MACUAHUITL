package core

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// 43d-2 M5: una ruta que manda el cliente debe llevar letra de unidad en Windows (aquí simulado con OutputsGOOS): una UNC, \\?\ o \\.\
// abren SMB o dispositivos. «/abs/x» es absoluta en Linux pero no tiene letra de unidad, así que la regla de Windows la rechaza.
func TestRutasDelClienteExigenUnidadEnWindows(t *testing.T) {
	h := newHarness(t, nil)
	old := service.OutputsGOOS
	service.OutputsGOOS = "windows"
	t.Cleanup(func() { service.OutputsGOOS = old })
	const p = "/abs/x"
	fc := v1.NewFleetServiceClient(h.conn)
	ac := v1.NewAnalysisServiceClient(h.conn)
	cc := v1.NewChangeServiceClient(h.conn)
	tc := v1.NewToolsServiceClient(h.conn)
	mc := v1.NewMetricsServiceClient(h.conn)
	for _, c := range []struct {
		name   string
		call   func() error
		reason string
	}{
		{"flota", func() error { _, e := fc.Find(con(t, "en"), &v1.FindRequest{Dir: p, Query: "x"}); return e }, "fleet.err.relative_path"},
		{"cambio pre", func() error {
			_, e := cc.GetChangeReport(con(t, "en"), &v1.GetChangeReportRequest{PreDir: p, PostDir: "/abs/y"})
			return e
		}, "change.err.no_input"},
		{"cambio post", func() error {
			_, e := cc.GetChangeReport(con(t, "en"), &v1.GetChangeReportRequest{PreDir: "/abs/y", PostDir: p})
			return e
		}, "change.err.no_input"},
		{"métricas", func() error { _, e := mc.GetJobMetrics(con(t, "en"), &v1.GetJobMetricsRequest{Dir: p}); return e }, "metrics.svc.relative"},
		{"herramientas", func() error { _, e := tc.AnalyzePcap(con(t, "en"), &v1.AnalyzePcapRequest{Path: p}); return e }, "tools.svc.pcap_path"},
		{"análisis", func() error {
			_, e := ac.Timeline(con(t, "en"), &v1.TimelineRequest{Job: labDir(t), PcapPath: p})
			return e
		}, "analyze.err.pcap_path"},
	} {
		err := c.call()
		if why, _ := reasonOf(err); status.Code(err) != codes.InvalidArgument || why != c.reason {
			t.Errorf("%s: %v (reason %q), quería InvalidArgument %q", c.name, err, why, c.reason)
		}
	}
}
