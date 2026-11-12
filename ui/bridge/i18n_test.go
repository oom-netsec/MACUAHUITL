package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// i18nCore es un núcleo mínimo: ui.language se lee y se guarda; la clave "terminal" siempre falla con file.exists y
// anota el accept-language que llegó; ListJobs devuelve una fase con reason y args.
type i18nCore struct {
	v1.UnimplementedPrefsServiceServer
	v1.UnimplementedPatrolServiceServer
	v1.UnimplementedToolsServiceServer
	rec       *recorder
	mu        sync.Mutex
	lang      string
	langReads int
	seen      []string
}

func (f *i18nCore) GetPreference(ctx context.Context, r *v1.GetPreferenceRequest) (*v1.GetPreferenceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Key == "ui.language" {
		f.langReads++
		return &v1.GetPreferenceResponse{Value: f.lang, Found: f.lang != ""}, nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	f.seen = append(f.seen, strings.Join(md.Get("accept-language"), ","))
	return nil, service.Err(ctx, codes.AlreadyExists, "file.exists", i18n.A("path", "/x/a.txt", "secreto", "hunter2"))
}

func (f *i18nCore) SetPreference(_ context.Context, r *v1.SetPreferenceRequest) (*v1.SetPreferenceResponse, error) {
	f.mu.Lock()
	f.lang = r.Value
	f.mu.Unlock()
	return &v1.SetPreferenceResponse{}, nil
}

func (f *i18nCore) ListJobs(context.Context, *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	return &v1.ListJobsResponse{Jobs: []*v1.JobSummary{{JobId: "j", Phases: []*v1.JobPhase{
		{At: timestamppb.Now(), Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ARMED, Detail: "2 equipos", Reason: "phase.devices", Args: map[string]string{"n": "2"}}}}}}, nil
}

func i18nBridge(t *testing.T, lang string, localize bool) (*Bridge, *i18nCore) {
	t.Helper()
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &i18nCore{lang: lang}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterPrefsServiceServer(r, f)
		v1.RegisterPatrolServiceServer(r, f)
		v1.RegisterToolsServiceServer(r, f)
	}, ipc.LocaleOptions()...)
	f.rec = &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, f.rec.emit)
	b.Localize = localize
	Start(ctx, b)
	return b, f
}

// shape es lo que recibe TypeScript como causa del error: el JSON del error que devuelve el método.
func shape(t *testing.T, err error) (m struct {
	Message  string            `json:"message"`
	Code     string            `json:"code"`
	Reason   string            `json:"reason"`
	Metadata map[string]string `json:"metadata"`
}) {
	t.Helper()
	raw, jerr := json.Marshal(&err) // como Wails: json.Marshal(&err)
	if jerr != nil {
		t.Fatal(jerr)
	}
	if jerr := json.Unmarshal(raw, &m); jerr != nil {
		t.Fatal(jerr, string(raw))
	}
	return m
}

// Con la bandera apagada (por omisión) no viaja accept-language aunque haya preferencia: el texto es el de siempre.
func TestPuenteSinLocalizeNoMandaIdioma(t *testing.T) {
	b, f := i18nBridge(t, "en", false)
	_, err := b.GetPreference("terminal")
	if err == nil || err.Error() != "rpc error: code = AlreadyExists desc = el archivo ya existe" {
		t.Fatalf("texto de siempre: %v", err)
	}
	if f.seen[0] != "" || f.langReads != 0 {
		t.Fatalf("no debía mandar idioma ni leer la preferencia: %q %d", f.seen, f.langReads)
	}
	m := shape(t, err)
	if m.Code != "AlreadyExists" || m.Reason != "file.exists" || m.Metadata["path"] != "/x/a.txt" || len(m.Metadata) != 1 || m.Message != err.Error() {
		t.Fatalf("forma del error: %+v", m)
	}
}

func TestPuenteConLocalizeMandaLaPreferencia(t *testing.T) {
	b, f := i18nBridge(t, "en", true)
	_, err := b.GetPreference("terminal")
	if err == nil || !strings.HasSuffix(err.Error(), "desc = the file already exists") {
		t.Fatalf("en: %v", err)
	}
	if f.seen[0] != "en" {
		t.Fatalf("accept-language = %q", f.seen)
	}
	// Cambiar la preferencia por el puente cambia el idioma de la siguiente llamada, sin releerla.
	if err := b.SetPreference("ui.language", "es"); err != nil {
		t.Fatal(err)
	}
	_, err = b.GetPreference("terminal")
	if err == nil || !strings.HasSuffix(err.Error(), "desc = el archivo ya existe") || f.seen[1] != "es" || f.langReads != 1 {
		t.Fatalf("es tras cambiar la preferencia: %v %q reads=%d", err, f.seen, f.langReads)
	}
	// Sin preferencia guardada, la llamada sale sin idioma y el núcleo contesta en es.
	b2, f2 := i18nBridge(t, "", true)
	if _, err := b2.GetPreference("terminal"); err == nil || f2.seen[0] != "es" {
		t.Fatalf("sin preferencia: %v %q", err, f2.seen)
	}
}

func TestPuenteListJobsExponeReasonYArgs(t *testing.T) {
	b, _ := i18nBridge(t, "", false)
	jobs, err := b.ListJobs()
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	if p := jobs[0].Phases[0]; p.Detail != "2 equipos" || p.Reason != "phase.devices" || p.Args["n"] != "2" {
		t.Fatalf("fase: %+v", p)
	}
}

// Un error que no viene del núcleo también sale con la forma, con code y reason vacíos.
func TestErrorSinNucleoTieneLaMismaForma(t *testing.T) {
	b := New(func() (*ipc.ClientConn, error) { return nil, errors.New("sin socket") }, (&recorder{}).emit)
	_, err := b.GetPreference("terminal")
	if !errors.Is(err, ErrDisconnected) {
		t.Fatal(err)
	}
	if m := shape(t, err); m.Message != "núcleo desconectado" || m.Code != "" || m.Reason != "" || m.Metadata == nil {
		t.Fatalf("%+v", m)
	}
}

func TestWriteFileExistsLlevaReasonYRuta(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.txt")
	os.WriteFile(p, []byte("x"), 0o600)
	b := New(nil, nil)
	err := b.WriteFile(p, "y", "utf8", false)
	if !errors.Is(err, ErrFileExists) || err.Error() != "guardar: el archivo ya existe" {
		t.Fatalf("texto de siempre: %v", err)
	}
	if m := shape(t, err); m.Reason != "file.exists" || m.Metadata["path"] != p || m.Code != "AlreadyExists" || m.Message != "guardar: el archivo ya existe" {
		t.Fatalf("%+v", m)
	}
	// Con Localize y en, el texto sale en inglés (la lectura de la preferencia necesita el núcleo).
	b2, _ := i18nBridge(t, "en", true)
	err = b2.WriteFile(p, "y", "utf8", false)
	if err == nil || err.Error() != "save: the file already exists" || !errors.Is(err, ErrFileExists) {
		t.Fatalf("en: %v", err)
	}
}

func (f *i18nCore) Syslog(_ *v1.SyslogRequest, st v1.ToolsService_SyslogServer) error {
	return service.Err(st.Context(), codes.InvalidArgument, "ingest.invalid.queue_size", i18n.A("min", 64, "max", 65536, "value", 10))
}

// El stream que falla al validar cierra con error (texto de siempre) y errorInfo {code, reason, metadata}.
func TestStreamDoneLlevaErrorInfo(t *testing.T) {
	b, f := i18nBridge(t, "", false)
	if _, err := b.SyslogStart("127.0.0.1:0", "udp", false, false, SyslogOptions{}); err != nil {
		t.Fatal(err)
	}
	want := `syslog:done {"error":"rpc error: code = InvalidArgument desc = la cola debe estar entre 64 y 65536 (0 = default), no 10",` +
		`"errorInfo":{"code":"InvalidArgument","metadata":{"field":"queue_size","max":"65536","min":"64","value":"10"},"reason":"ingest.invalid"},"runId":"run-1"}`
	f.rec.waitFor(t, want)
}
