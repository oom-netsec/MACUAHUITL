package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/syslogd/syslogdtest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tlsinspect"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// Revisión final: sin servidores, el modo ligero usa el resolvedor del sistema, no terceros.
func TestToolsDnsLightDefaultsToSystemResolver(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(conf, []byte("nameserver 127.0.0.1\n"), 0o600)
	old := resolvConf
	resolvConf = conf
	t.Cleanup(func() { resolvConf = old })
	d := servicetest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := (&toolsSvc{d: d}).Dns(ctx, &v1.DnsRequest{Mode: v1.DnsMode_DNS_MODE_QUERY, Name: "example.com", TimeoutMs: 300}); err != nil {
		t.Fatal(err)
	}
	txt := d.AuditText()
	if strings.Contains(txt, "1.1.1.1") || strings.Contains(txt, "8.8.8.8") || !strings.Contains(txt, `"target":"udp://127.0.0.1:53"`) {
		t.Fatalf("light mode contacted public resolvers or not the system one:\n%s", txt)
	}
}

// stuckStream es un cliente gRPC atascado: el primer envío (la dirección) pasa y los demás
// no vuelven hasta que se libere, como un Send sin ventana de flujo.
type stuckStream struct {
	v1.ToolsService_SyslogServer
	ctx     context.Context
	release chan struct{}
	first   chan string
	sent    int
}

func (s *stuckStream) Context() context.Context { return s.ctx }
func (s *stuckStream) Send(m *v1.SyslogResponse) error {
	if s.sent++; s.sent == 1 {
		s.first <- m.Listening
		return nil
	}
	<-s.release
	return nil
}

// Revisión: un cliente atascado no cuelga el cierre, y lo que va al archivo sí se escribe.
func TestSyslogStuckClientDoesNotHangCloseAndFileKeepsEverything(t *testing.T) {
	oldGrace, oldQ := closeGrace, outQueue
	closeGrace, outQueue = 200*time.Millisecond, 8
	t.Cleanup(func() { closeGrace, outQueue = oldGrace, oldQ })
	d := servicetest.New(t)
	st := &stuckStream{ctx: context.Background(), release: make(chan struct{}), first: make(chan string, 1)}
	t.Cleanup(func() { close(st.release) })
	done := make(chan error, 1)
	go func() {
		done <- (&toolsSvc{d: d}).Syslog(&v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, Format: "crudo"}, st)
	}()
	addr := <-st.first
	if err := syslogdtest.SendUDP(addr, "<14>guardame", 50); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el RPC no terminó con el cliente atascado")
	}
	files, _ := filepath.Glob(filepath.Join(d.Outputs(), "syslog", "*.log"))
	if len(files) != 1 {
		t.Fatalf("archivos = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if got := strings.Count(string(b), "<14>guardame\n"); got != 50 {
		t.Fatalf("el archivo trae %d de 50 mensajes", got)
	}
	if a := d.AuditText(); !strings.Contains(a, "lost_on_interface=") || strings.Contains(a, "lost_on_interface=0") {
		t.Fatalf("lo que no cupo hacia el cliente debía auditarse:\n%s", a)
	}
}

// Una escucha sin opciones usa los defaults de archivo de las preferencias del núcleo; con opciones explícitas
// las ignora. Y cambiar la carpeta de salidas aplica a la escucha que empieza después, no a la que ya corre.
func TestSyslogUsaPreferenciasDelNucleo(t *testing.T) {
	d := servicetest.New(t)
	d.S.Apply("", service.IngestDefaults{RotateMB: 7, MaxFiles: 9, Format: "jsonl"})
	escucha := func(req *v1.SyslogRequest) {
		st := &stuckStream{ctx: context.Background(), release: make(chan struct{}), first: make(chan string, 1)}
		close(st.release)
		done := make(chan error, 1)
		go func() { done <- (&toolsSvc{d: d}).Syslog(req, st) }()
		<-st.first
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	escucha(&v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true})
	escucha(&v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, MaxFiles: 3, Format: "crudo"})
	a := d.AuditText()
	if !strings.Contains(a, "rotate_mb=7 ") || !strings.Contains(a, "max_files=9 format=jsonl") {
		t.Fatalf("la escucha sin opciones debía usar las preferencias:\n%s", a)
	}
	if !strings.Contains(a, "max_files=3 format=crudo") || !strings.Contains(a, "rotate_mb=7 ") {
		t.Fatalf("lo explícito debía ganar (y rotate_mb sigue de las preferencias):\n%s", a)
	}
}

func TestSyslogCambiarLaCarpetaAplicaALaSiguiente(t *testing.T) {
	d := servicetest.New(t)
	vieja := d.Outputs()
	nueva := filepath.Join(t.TempDir(), "nueva")
	st := &stuckStream{ctx: context.Background(), release: make(chan struct{}), first: make(chan string, 1)}
	close(st.release)
	done := make(chan error, 1)
	go func() {
		done <- (&toolsSvc{d: d}).Syslog(&v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, Format: "crudo"}, st)
	}()
	addr := <-st.first
	d.S.Apply(nueva, service.IngestDefaults{}) // cambia con la escucha en curso
	if err := syslogdtest.SendUDP(addr, "<14>sigue en la vieja", 1); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f, _ := filepath.Glob(filepath.Join(vieja, "syslog", "*.log")); len(f) != 1 {
		t.Fatalf("la escucha en curso debía seguir en %s: %v", vieja, f)
	}
	st2 := &stuckStream{ctx: context.Background(), release: make(chan struct{}), first: make(chan string, 1)}
	close(st2.release)
	go func() {
		done <- (&toolsSvc{d: d}).Syslog(&v1.SyslogRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, Format: "crudo"}, st2)
	}()
	addr = <-st2.first
	syslogdtest.SendUDP(addr, "<14>va a la nueva", 1)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f, _ := filepath.Glob(filepath.Join(nueva, "syslog", "*.log")); len(f) != 1 {
		t.Fatalf("la escucha nueva debía escribir en %s: %v", nueva, f)
	}
}

// Fase 30c-A: los hallazgos de DNS salen estructurados y su detalle en el idioma pedido, también en el JSON.
func TestDnsHallazgosEstructuradosYEn(t *testing.T) {
	srv := &mdns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		w.WriteMsg(m) // sin OPT: no anuncia EDNS; solo UDP: TCP/53 no responde
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ListenAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	d := servicetest.New(t)
	ask := func(loc string) *v1.DnsResponse {
		ctx, cancel := context.WithTimeout(i18n.WithLocale(context.Background(), loc), 20*time.Second)
		defer cancel()
		r, err := (&toolsSvc{d: d}).Dns(ctx, &v1.DnsRequest{Mode: v1.DnsMode_DNS_MODE_TRANSPORT, Name: "t.lab", Servers: []string{srv.PacketConn.LocalAddr().String()}, TimeoutMs: 400})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	es, en := ask("es"), ask("en")
	if len(es.Findings) != 2 || len(en.Findings) != 2 {
		t.Fatalf("%v / %v", es.Findings, en.Findings)
	}
	for i, want := range []struct{ code, sev, key, es, en string }{
		{"tcp-bloqueado", "error", "dns.finding.tcp_blocked", "TCP/53 no responde: las respuestas grandes y DNSSEC fallarán", "TCP/53 does not respond: large responses and DNSSEC will fail"},
		{"sin-edns", "info", "dns.finding.no_edns", "el servidor no anuncia EDNS(0)", "the server does not advertise EDNS(0)"},
	} {
		if f := es.Findings[i]; f.Code != want.code || f.Severity != want.sev || f.Key != want.key || f.Message != want.es {
			t.Errorf("es %d: %v", i, f)
		}
		if f := en.Findings[i]; f.Code != want.code || f.Key != want.key || f.Message != want.en || !strings.Contains(en.Report.Json, want.en) || strings.Contains(en.Report.Json, want.es) {
			t.Errorf("en %d: %v", i, f)
		}
		if !strings.Contains(es.Report.Json, want.es) {
			t.Errorf("el JSON en español debe traer %q", want.es)
		}
	}
}

// Fase 30c-A: los hallazgos de TLS salen estructurados y en el idioma pedido; el error de verificación (texto de
// la biblioteca x509) no se traduce pero trae su código.
func TestTlsRespuestaEstructuradaYEn(t *testing.T) {
	rep := tlsinspect.Report{VerifyError: "x509: certificate signed by unknown authority", VerifyCode: "unknown_authority",
		Findings: []tlsinspect.Finding{{Severity: "aviso", Code: "autofirmado", Detail: "el certificado es autofirmado; los clientes no lo validarán sin fijarlo", Text: i18n.Tx("tls.finding.self_signed")}}}
	const msgEs, msgEn = "el certificado es autofirmado; los clientes no lo validarán sin fijarlo", "the certificate is self-signed; clients will not validate it unless it is pinned"
	es, en := tlsResponse(rep, i18n.Es), tlsResponse(rep, i18n.En)
	if len(es.Findings) != 1 || es.Findings[0].Code != "autofirmado" || es.Findings[0].Severity != "warning" || es.Findings[0].Key != "tls.finding.self_signed" || es.Findings[0].Message != msgEs {
		t.Fatalf("es: %v", es.Findings)
	}
	if en.Findings[0].Message != msgEn || !strings.Contains(en.Report.Json, msgEn) || strings.Contains(en.Report.Json, msgEs) {
		t.Errorf("en: %v\n%s", en.Findings, en.Report.Json)
	}
	if !strings.Contains(es.Report.Json, msgEs) || es.VerifyCode != "unknown_authority" || en.VerifyCode != "unknown_authority" || !strings.Contains(en.Report.Json, "x509: certificate signed by unknown authority") {
		t.Errorf("es: %s / %q", es.Report.Json, es.VerifyCode)
	}
}
