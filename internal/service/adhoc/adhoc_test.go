package adhoc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type jobDeps struct {
	*servicetest.Deps
	info service.JobInfo
}

func (d jobDeps) Job(context.Context, string) (service.JobInfo, error) { return d.info, nil }

func TestResultadoFinalLiberaLosComandos(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"devices":[]}`), 0o600)
	s := &adhocSvc{d: jobDeps{servicetest.New(t), service.JobInfo{State: "completed", Dir: dir}}, cmds: map[string][]string{"j1": {"show clock"}}}
	r, err := s.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: "j1"})
	if err != nil || !r.Done || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if len(s.cmds) != 0 {
		t.Errorf("cmds no se liberó: %v", s.cmds)
	}
}

func TestResultadoConFinishFallidoTerminaConError(t *testing.T) {
	s := &adhocSvc{d: jobDeps{servicetest.New(t), service.JobInfo{State: "completed", Dir: t.TempDir(), FinishErr: "disco lleno"}}, cmds: map[string][]string{"j1": {"show clock"}}}
	r, err := s.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: "j1"})
	if err != nil || !r.Done || r.Error != "disco lleno" || r.Report != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if len(s.cmds) != 0 {
		t.Errorf("cmds no se liberó: %v", s.cmds)
	}
	// Sin error de cierre, un manifest que aún no existe no es final.
	s.d = jobDeps{servicetest.New(t), service.JobInfo{State: "completed", Dir: t.TempDir()}}
	if r, _ = s.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: "j1"}); r.Done {
		t.Errorf("sin manifest ni error no está listo: %+v", r)
	}
}

// Fase 30d: los rechazos de StartAdhoc salen en el idioma pedido; con es el texto es el de siempre.
func TestStartAdhocRechazosEsYEn(t *testing.T) {
	s := &adhocSvc{d: servicetest.New(t), cmds: map[string][]string{}}
	for _, c := range []struct {
		req    *v1.StartAdhocRequest
		es, en string
		reason string
	}{
		{&v1.StartAdhocRequest{Commands: "configure terminal"}, `playbook: comando no permitido en una recolección (solo lectura): "configure terminal" (no es un comando de lectura)`,
			`playbook: command not allowed in a collection (read-only): "configure terminal" (not a read command)`, "playbook.err.denied_cmd"},
		{&v1.StartAdhocRequest{Commands: "show clock"}, "indica al menos un equipo", "specify at least one device", "adhoc.err.no_targets"},
	} {
		for loc, want := range map[string]string{"es": c.es, "en": c.en} {
			_, err := s.StartAdhoc(i18n.WithLocale(context.Background(), loc), c.req)
			st := status.Convert(err)
			if st.Code() != codes.InvalidArgument || st.Message() != want {
				t.Errorf("%s: %v, quería %q", loc, err, want)
			}
			if ei, _ := st.Details()[0].(*errdetails.ErrorInfo); ei == nil || ei.Reason != c.reason {
				t.Errorf("%s: sin reason %s: %v", loc, c.reason, st.Details())
			}
		}
	}
}

// Fase 30d: el detalle de adhoc.denied se audita en inglés completo, con cualquier idioma.
func TestAdhocDeniedAuditaEnIngles(t *testing.T) {
	for _, loc := range []string{"", "es", "en"} {
		d := servicetest.New(t)
		s := &adhocSvc{d: d, cmds: map[string][]string{}}
		s.StartAdhoc(i18n.WithLocale(context.Background(), loc), &v1.StartAdhocRequest{Commands: "configure terminal"})
		if got := d.AuditText(); !strings.Contains(got, `command not allowed in a collection (read-only): \"configure terminal\" (not a read command)`) {
			t.Errorf("%q: auditoría %s", loc, got)
		}
	}
}

// Fase 30e: los errores de AdhocResult salen en el idioma pedido; el máximo de comandos se audita en inglés.
func TestAdhocResultErroresEnElIdioma(t *testing.T) {
	cases := []struct {
		info   service.JobInfo
		es, en string
	}{
		{service.JobInfo{State: "failed"}, "el núcleo se detuvo con el lote en curso; vuelve a lanzarlo", "the core stopped with the batch in progress; launch it again"},
		{service.JobInfo{State: "completed"}, "el lote no conserva su carpeta de salida", "the batch no longer has its output folder"},
	}
	for _, c := range cases {
		for loc, want := range map[string]string{"": c.es, "es": c.es, "en": c.en} {
			s := &adhocSvc{d: jobDeps{servicetest.New(t), c.info}, cmds: map[string][]string{}}
			r, err := s.AdhocResult(i18n.WithLocale(context.Background(), loc), &v1.AdhocResultRequest{JobId: "j"})
			if err != nil || r.Error != want {
				t.Errorf("%q %s: %q %v", loc, c.info.State, r.GetError(), err)
			}
		}
	}
	d := servicetest.New(t)
	s := &adhocSvc{d: d, cmds: map[string][]string{}}
	s.StartAdhoc(i18n.WithLocale(context.Background(), "es"), &v1.StartAdhocRequest{Commands: strings.Repeat("show version\n", 51)})
	if got := d.AuditText(); !strings.Contains(got, "51 commands; the maximum is 50") {
		t.Errorf("auditoría %s", got)
	}
}
