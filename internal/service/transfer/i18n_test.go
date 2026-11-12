package transfer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

var (
	durationRe = regexp.MustCompile(`\d+(\.\d+)?(µs|ms|s)\b`)
	portRe     = regexp.MustCompile(`127\.0\.0\.1:\d+`)
)

// transferenciaCasos recorre los errores de validación, el informe de una descarga, el motivo de «no lista» y los
// rechazos de un servidor; ctx fija el idioma.
func transferenciaCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	var dirs []string
	tmp := func() string {
		d := t.TempDir()
		dirs = append(dirs, d)
		return d
	}
	defer func() {
		for k, v := range out {
			for _, d := range dirs {
				v = strings.ReplaceAll(v, d, "<dir>")
			}
			out[k] = portRe.ReplaceAllString(durationRe.ReplaceAllString(v, "<t>"), "127.0.0.1:<p>")
		}
	}()
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = "ERROR: " + err.Error()
		}
	}
	s, d := newTest(t)
	dirs = append(dirs, d.Out)
	pub, dest := tmp(), tmp()
	os.WriteFile(filepath.Join(pub, "r1.cfg"), []byte("hostname R1\n"), 0o600)
	sctx := func() *fakeStream { return &fakeStream{ctx: ctx, out: make(chan *v1.StartServerResponse, 4)} }

	for n, req := range map[string]*v1.StartServerRequest{
		"servidor_protocolo": {Protocol: "gopher", Listen: "127.0.0.1"}, "servidor_sin_nada": {Protocol: "tftp", Listen: "127.0.0.1"},
		"servidor_puerto_privilegiado": {Protocol: "tftp", Listen: "127.0.0.1:69", FromDir: pub}, "servidor_host": {Protocol: "tftp", Listen: "localhost:6969", FromDir: pub},
		"servidor_todas": {Protocol: "tftp", Listen: "0.0.0.0", FromDir: pub}, "servidor_escribir_sin_lista": {Protocol: "tftp", Listen: "0.0.0.0", AllowAny: true, Write: true},
		"servidor_ip_origen": {Protocol: "tftp", Listen: "127.0.0.1", FromDir: pub, Allow: []string{"no-es-ip"}}, "servidor_carpeta_sensible": {Protocol: "tftp", Listen: "127.0.0.1", FromDir: "/etc"},
		"servidor_recepcion_sensible": {Protocol: "ftp", Listen: "127.0.0.1", Write: true, RecvDir: "/usr/lib"}, "servidor_recepcion_relativa": {Protocol: "ftp", Listen: "127.0.0.1", Write: true, RecvDir: "rel"},
		"servidor_http_escritura": {Protocol: "http", Listen: "127.0.0.1", FromDir: pub, Write: true}, "servidor_pasivo": {Protocol: "ftp", Listen: "127.0.0.1", FromDir: pub, PassivePortMin: 5000, PassivePortMax: 4000},
		"servidor_pasivo_priv": {Protocol: "ftp", Listen: "127.0.0.1", FromDir: pub, PassivePortMin: 80, PassivePortMax: 90}, "servidor_archivo_relativo": {Protocol: "tftp", Listen: "127.0.0.1", Files: []string{"rel.txt"}},
		"servidor_archivo_no_existe": {Protocol: "tftp", Listen: "127.0.0.1", Files: []string{"/no/existe.txt"}},
		"servidor_tftp_sin_lista":    {Protocol: "tftp", Listen: "127.0.0.1", Write: true, RecvDir: dest},
		"servidor_ftp_todas":         {Protocol: "ftp", Listen: "0.0.0.0", AllowAny: true, Write: true, RecvDir: dest},
	} {
		put(n, s.StartServer(req, sctx()))
	}
	for n, r := range map[string]*v1.GetRequest{
		"get_clave_en_url": {Url: "ftp://u:p@127.0.0.1/a", DestDir: dest}, "get_esquema": {Url: "gopher://127.0.0.1/a", DestDir: dest}, "get_sin_host": {Url: "http:///a", DestDir: dest},
		"get_insecure": {Url: "http://127.0.0.1/a", DestDir: dest, Insecure: true}, "get_destino_sensible": {Url: "http://127.0.0.1/a", DestDir: "/etc"},
		"get_tiempo": {Url: "http://127.0.0.1/a", DestDir: dest, TimeoutSeconds: 99999}, "get_tope": {Url: "http://127.0.0.1/a", DestDir: dest, MaxBytes: -1},
		"get_sin_credencial": {Url: "scp://127.0.0.1/a", DestDir: dest}, "get_boveda": {Url: "scp://127.0.0.1/a", DestDir: dest, CredentialId: "x"},
		"get_url_mala": {Url: "%zz", DestDir: dest}, "get_ruta_larga": {Url: "http://127.0.0.1/a b", DestDir: dest},
	} {
		_, err := s.Get(ctx, r)
		put(n, err)
	}
	_, err := s.Put(ctx, &v1.PutRequest{Url: "http://127.0.0.1/a", FromDir: dest, Name: "x"})
	put("put_sin_archivo", err)
	_, err = s.Put(ctx, &v1.PutRequest{Url: "tftp://127.0.0.1/a", FromDir: dest, Name: "../x"})
	put("put_nombre", err)
	for n, r := range map[string]*v1.BrowseRequest{
		"browse_tftp": {Url: "tftp://127.0.0.1/"}, "browse_tope": {Url: "ftp://127.0.0.1/", MaxEntries: -1}, "browse_tiempo": {Url: "ftp://127.0.0.1/", TimeoutSeconds: 99999},
		"browse_insecure": {Url: "ftp://127.0.0.1/", Insecure: true}, "browse_sin_credencial": {Url: "sftp://127.0.0.1/"},
	} {
		_, err := s.Browse(ctx, r)
		put(n, err)
	}
	for n, r := range map[string]*v1.GetManyRequest{
		"muchos_sin_nombres": {Url: "ftp://127.0.0.1/"}, "muchos_url": {Url: "%zz", Names: []string{"a"}}, "muchos_tftp": {Url: "tftp://127.0.0.1/", Names: []string{"a"}},
		"muchos_destino": {Url: "ftp://127.0.0.1/", Names: []string{"a"}, DestDir: "/etc"}, "muchos_tope": {Url: "ftp://127.0.0.1/", Names: []string{"a"}, DestDir: dest, MaxBytes: -1},
	} {
		put(n, s.GetMany(r, &getManyStream{ctx: ctx}))
	}
	_, err = s.RedirectHint(ctx, &v1.RedirectHintRequest{Protocol: "tftp", Ip: "no-es-ip", Port: 6969})
	put("redirigir_ip", err)
	_, err = s.RedirectHint(ctx, &v1.RedirectHintRequest{Protocol: "http", Ip: "127.0.0.1", Port: 8080})
	put("redirigir_protocolo", err)

	// Una descarga buena: el informe de texto. Un servidor que rechaza el origen y otro archivo no publicado.
	run := startServerIn(t, s, ctx, &v1.StartServerRequest{Protocol: "http", Listen: "127.0.0.1:0", FromDir: pub})
	resp, err := s.Get(ctx, &v1.GetRequest{Url: "http://" + run.ready.Listening + "/r1.cfg", DestDir: tmp()})
	if err != nil {
		put("descarga", err)
	} else {
		b, _ := json.Marshal(resp.Result)
		out["descarga_informe"] = resp.Result.Report
		out["descarga_resultado"] = resp.Result.Verified
		_ = b
	}
	_, err = s.Get(ctx, &v1.GetRequest{Url: "http://" + run.ready.Listening + "/nope.cfg", DestDir: tmp()})
	put("descarga_no_publicada", err)
	run.transfers(t, 2)
	closed := startServerIn(t, s, ctx, &v1.StartServerRequest{Protocol: "http", Listen: "127.0.0.1:0", FromDir: pub, Allow: []string{"10.9.9.9"}})
	_, err = s.Get(ctx, &v1.GetRequest{Url: "http://" + closed.ready.Listening + "/r1.cfg", DestDir: tmp()})
	put("descarga_origen", err)
	for i, ev := range closed.transfers(t, 1) {
		out["rechazo_origen"] = ev["Error"].(string)
		_ = i
	}
	sum, err := s.Get(ctx, &v1.GetRequest{Url: "http://" + run.ready.Listening + "/r1.cfg", DestDir: tmp(), Sha512: strings.Repeat("0", 128)})
	put("descarga_sha512", err)
	_ = sum
	return out
}

type getManyStream struct {
	v1.TransferService_GetManyServer
	ctx context.Context
}

func (g *getManyStream) Context() context.Context { return g.ctx }

func TestTransferenciasRegresionEs(t *testing.T) {
	base := transferenciaCasos(t, context.Background())
	servicetest.Golden(t, "testdata/transferencias_es.golden.json", base)
	for _, loc := range []string{"es", "es-MX", "fr"} {
		for k, v := range transferenciaCasos(t, i18n.WithLocale(context.Background(), loc)) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de sin idioma: %q vs %q", k, loc, v, base[k])
			}
		}
	}
}

// Con en, los errores, el informe y los motivos de rechazo salen en inglés, sin español.
func TestTransferenciasEnSinEspanol(t *testing.T) {
	es := regexp.MustCompile(`[áéíóúñ¿]|\b(el|la|los|las|de|del|con|sin|para|solo|hay|ya|falta|una|un|abre|usa|indica|tope|máximo|bytes en|guardado|permitido)\b`)
	base := transferenciaCasos(t, context.Background())
	for k, v := range transferenciaCasos(t, i18n.WithLocale(context.Background(), "en")) {
		if v == base[k] && strings.HasPrefix(v, "ERROR") && !strings.Contains(v, "HTTP 40") && k != "get_ruta_larga" && k != "servidor_archivo_no_existe" {
			t.Errorf("%s: en igual a es: %s", k, v)
		}
		if m := es.FindString(v); m != "" {
			i := strings.Index(v, m)
			t.Errorf("%s: queda español (%q): ...%s...", k, m, v[max(0, i-30):min(len(v), i+50)])
		}
	}
	got := transferenciaCasos(t, i18n.WithLocale(context.Background(), "en"))
	if got["rechazo_origen"] != "origin not allowed" || !strings.HasPrefix(got["descarga_informe"], "saved  <dir>/r1.cfg (12 bytes in <t>)\nMD5 ") {
		t.Errorf("rechazo %q informe %q", got["rechazo_origen"], got["descarga_informe"])
	}
}

// startServerIn es startServer con el idioma de base en el contexto del stream.
func startServerIn(t *testing.T, s *svc, base context.Context, req *v1.StartServerRequest) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(base)
	st := &fakeStream{ctx: ctx, out: make(chan *v1.StartServerResponse, 64)}
	r := &running{out: st.out, done: make(chan error, 1), stop: cancel}
	go func() { r.done <- s.StartServer(req, st) }()
	select {
	case ev := <-st.out:
		r.ready = ev.GetReady()
	case err := <-r.done:
		cancel()
		t.Fatalf("StartServer: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("el servidor no abrió")
	}
	t.Cleanup(func() { cancel(); <-r.done })
	return r
}
