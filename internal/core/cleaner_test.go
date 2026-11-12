package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestCleanerLimpiaYAudita(t *testing.T) {
	h := newHarness(t, nil)
	cc := v1.NewCleanerServiceClient(h.conn)
	b, err := os.ReadFile("../cleaner/testdata/sucia.txt")
	if err != nil {
		t.Fatal(err)
	}
	r, err := cc.Clean(ctx(t), &v1.CleanRequest{Text: string(b)})
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Changes []struct{ Rule string }
		Orphans []struct{ Line int }
		Output  string
	}
	if err := json.Unmarshal([]byte(r.Report.Json), &rep); err != nil || len(rep.Changes) != 5 || len(rep.Orphans) != 5 || rep.Output != "" {
		t.Fatalf("informe %v: %s", err, r.Report.Json)
	}
	if strings.Contains(r.Output, "SW1   ") || !strings.Contains(r.Output, "! HUERFANA: route-map RM-FALTA") {
		t.Errorf("salida:\n%s", r.Output)
	}
	if !strings.Contains(h.auditText(t), `"action":"cleaner.clean"`) {
		t.Error("no quedó en la bitácora")
	}
	if _, err := cc.Clean(ctx(t), &v1.CleanRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("vacío: %v", err)
	}
}
