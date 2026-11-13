package metrics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// jobDeps le da a servicetest.Deps el Job que en la app presta Patrol.
type jobDeps struct {
	*servicetest.Deps
	dir string
}

func (d jobDeps) Job(_ context.Context, id string) (service.JobInfo, error) {
	if id != "trabajo1" {
		return service.JobInfo{}, status.Error(codes.NotFound, "no existe")
	}
	return service.JobInfo{State: "DONE", Dir: d.dir}, nil
}

func job(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for r := 0; r < 2; r++ {
		ts := t0.Add(time.Duration(r) * 5 * time.Minute).Format(time.RFC3339)
		fmt.Fprintf(&b, "===== ronda %d · %s · show processes cpu sorted =====\nCPU utilization for five seconds: %d%%/0%%; one minute: 2%%; five minutes: 3%%\n", r+1, ts, 10+r)
	}
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(b.String()), 0o600)
	return dir
}

func TestGetJobMetrics(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: jobDeps{d, job(t)}}
	r, err := s.GetJobMetrics(context.Background(), &v1.GetJobMetricsRequest{JobId: "trabajo1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 1 || len(r.Devices[0].Cpu) != 2 || r.Devices[0].Cpu[1].FiveSec != 11 || r.Devices[0].Cpu[1].Round != 2 || r.Devices[0].Cpu[0].AtMs != time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC).UnixMilli() {
		t.Fatalf("respuesta = %v", r)
	}
	// lo que el trabajo no recolectó viene vacío y con aviso
	w := strings.Join(r.Devices[0].Warnings, "|")
	if len(r.Devices[0].Memory) != 0 || !strings.Contains(w, "show memory statistics") || !strings.Contains(w, "show interfaces") {
		t.Fatalf("avisos = %v", r.Devices[0].Warnings)
	}
	if !strings.Contains(d.AuditText(), `"action":"metrics.job"`) {
		t.Fatalf("falta la auditoría:\n%s", d.AuditText())
	}
}

func TestGetJobMetricsEntradasInvalidas(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: jobDeps{d, job(t)}}
	for name, req := range map[string]*v1.GetJobMetricsRequest{
		"sin trabajo ni carpeta": {},
		"ruta relativa":          {Dir: "relativa/x"},
		"tope negativo":          {JobId: "trabajo1", MaxPoints: -1},
		"demasiadas interfaces":  {JobId: "trabajo1", Interfaces: make([]string, 100)},
		"carpeta inexistente":    {Dir: filepath.Join(t.TempDir(), "nada")},
	} {
		if _, err := s.GetJobMetrics(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := s.GetJobMetrics(context.Background(), &v1.GetJobMetricsRequest{JobId: "otro"}); status.Code(err) != codes.NotFound {
		t.Errorf("trabajo inexistente: %v", err)
	}
}
