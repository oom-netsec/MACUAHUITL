package core

import (
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestFleetServiceAuditedAndValidated(t *testing.T) {
	h := newHarness(t, nil)
	fc := v1.NewFleetServiceClient(h.conn)
	dir, _ := filepath.Abs("../fleet/testdata/outputs")
	r, err := fc.Find(ctx(t), &v1.FindRequest{Dir: dir, Query: "10.1.10.20"})
	if err != nil || !strings.Contains(r.Report.Json, `"mode":"ip"`) {
		t.Fatalf("find %v %v", err, r)
	}
	if !strings.Contains(h.auditText(t), `"action":"fleet.find"`) {
		t.Error("sin auditoría")
	}
	if _, err := fc.Find(ctx(t), &v1.FindRequest{Dir: "relativa", Query: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("ruta relativa: %v", err)
	}
	if _, err := fc.Find(ctx(t), &v1.FindRequest{Dir: dir}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("sin consulta: %v", err)
	}
	if _, err := fc.Capacity(ctx(t), &v1.CapacityRequest{Dir: dir, Need: "mucho"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("tamaño: %v", err)
	}
	if _, err := fc.Summary(ctx(t), &v1.SummaryRequest{Dir: t.TempDir()}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("sin salidas: %v", err)
	}
}
