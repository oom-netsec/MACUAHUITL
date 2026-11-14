package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// metricasCasos recorre las RPC de métricas con entradas que disparan avisos y errores; ctx fija el idioma.
func metricasCasos(t *testing.T, ctx context.Context) map[string]string {
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
			out[k] = v
		}
	}()
	put := func(n string, v any, err error) {
		if err != nil {
			out[n] = "ERROR: " + err.Error()
			return
		}
		b, _ := json.Marshal(v)
		out[n] = string(b)
	}
	sd := servicetest.New(t)
	dirs = append(dirs, sd.Out)
	j := job(t)
	dirs = append(dirs, j)
	s := &svc{d: jobDeps{sd, j}}
	r, err := s.GetJobMetrics(ctx, &v1.GetJobMetricsRequest{JobId: "trabajo1"})
	put("metricas", r, err)
	r, err = s.GetJobMetrics(ctx, &v1.GetJobMetricsRequest{JobId: "trabajo1", Interfaces: []string{"Gi9/9"}})
	put("metricas_iface", r, err)
	r, err = s.GetJobMetrics(ctx, &v1.GetJobMetricsRequest{JobId: "trabajo1", Device: "otro"})
	put("metricas_equipo", r, err)
	for n, req := range map[string]*v1.GetJobMetricsRequest{
		"sin_trabajo": {}, "relativa": {Dir: "relativa/x"}, "tope": {JobId: "trabajo1", MaxPoints: -1}, "muchas": {JobId: "trabajo1", Interfaces: make([]string, 100)}, "no_existe": {Dir: filepath.Join(tmp(), "nada")},
	} {
		r, err := s.GetJobMetrics(ctx, req)
		put("metricas_err_"+n, r, err)
	}
	empty := &svc{d: jobDeps{sd, ""}}
	r, err = empty.GetJobMetrics(ctx, &v1.GetJobMetricsRequest{JobId: "trabajo1"})
	put("metricas_sin_salidas", r, err)

	pj := portsJob(t)
	dirs = append(dirs, pj)
	ps := &svc{d: jobDeps{sd, pj}}
	p, err := ps.GetPortStatus(ctx, &v1.GetPortStatusRequest{JobId: "trabajo1"})
	put("puertos", p, err)
	p, err = ps.GetPortStatus(ctx, &v1.GetPortStatusRequest{JobId: "trabajo1", Device: "otro"})
	put("puertos_equipo", p, err)
	// Sin trunk ni canales, y con salidas ilegibles.
	solo := tmp()
	os.MkdirAll(filepath.Join(solo, "SW1_10.0.0.1"), 0o700)
	os.WriteFile(filepath.Join(solo, "SW1_10.0.0.1", "a.txt"), []byte("===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\n"+fixture(t, "ios152_show-interfaces-status")), 0o600)
	p, err = (&svc{d: jobDeps{sd, solo}}).GetPortStatus(ctx, &v1.GetPortStatusRequest{JobId: "trabajo1"})
	put("puertos_sin_trunk", p, err)
	raro := tmp()
	os.MkdirAll(filepath.Join(raro, "SW1_10.0.0.1"), 0o700)
	os.WriteFile(filepath.Join(raro, "SW1_10.0.0.1", "a.txt"), []byte("===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\nbasura\n===== ronda 1 · 2026-11-06T10:00:01Z · show interfaces trunk =====\nbasura\n===== ronda 1 · 2026-11-06T10:00:02Z · show etherchannel summary =====\nbasura\n"), 0o600)
	p, err = (&svc{d: jobDeps{sd, raro}}).GetPortStatus(ctx, &v1.GetPortStatusRequest{JobId: "trabajo1"})
	put("puertos_ilegible", p, err)
	vacio := tmp()
	p, err = (&svc{d: jobDeps{sd, vacio}}).GetPortStatus(ctx, &v1.GetPortStatusRequest{JobId: "trabajo1"})
	put("puertos_sin_equipos", p, err)
	dos := tmp()
	for _, h := range []string{"SW1_10.0.0.1", "SW2_10.0.0.2"} {
		os.MkdirAll(filepath.Join(dos, h), 0o700)
		os.WriteFile(filepath.Join(dos, h, "a.txt"), []byte("===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\n"+fixture(t, "ios152_show-interfaces-status")), 0o600)
	}
	p, err = (&svc{d: jobDeps{sd, dos}}).GetPortStatus(ctx, &v1.GetPortStatusRequest{JobId: "trabajo1"})
	put("puertos_varios", p, err)
	for n, req := range map[string]*v1.GetPortStatusRequest{
		"sin_equipo": {CredentialId: "x"}, "opcion": {Device: "-oProxyCommand=x", CredentialId: "x"}, "sin_credencial": {Device: "10.0.0.1"}, "puerto": {Device: "10.0.0.1", CredentialId: "x", Port: 70000}, "boveda": {Device: "10.0.0.1", CredentialId: "x"},
	} {
		p, err := ps.GetPortStatus(ctx, req)
		put("puertos_vivo_"+n, p, err)
	}
	return out
}

// Regresión: sin idioma, con es o con uno desconocido, cada RPC de métricas devuelve lo mismo que antes del catálogo.
func TestMetricasRegresionEs(t *testing.T) {
	base := metricasCasos(t, i18n.WithLocale(context.Background(), "es"))
	i18ntest.Golden(t, "testdata/metricas_es.golden.json", base)
	for _, loc := range []string{"es", "es-MX"} {
		for k, v := range metricasCasos(t, i18n.WithLocale(i18n.WithLocale(context.Background(), "es"), loc)) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de es", k, loc)
			}
		}
	}
}

// Con en, ninguna RPC de métricas deja español en lo que traduce el núcleo.
func TestMetricasEnSinEspanol(t *testing.T) {
	es := regexp.MustCompile(`[áéíóúñ¿¡]|\b(falta|comando|equipo|equipos|trabajo|ronda|rondas|interfaz|interfaces con|no se pudo|solo|carpeta|ruta|topes|indica)\b`)
	base := metricasCasos(t, i18n.WithLocale(context.Background(), "es"))
	for k, v := range metricasCasos(t, i18n.WithLocale(context.Background(), "en")) {
		if v == base[k] && !strings.HasPrefix(k, "puertos_vivo") && k != "metricas" && k != "puertos" && k != "puertos_sin_trunk" && k != "puertos_ilegible" {
			if es.MatchString(v) {
				t.Errorf("%s: en igual a es: %.160s", k, v)
			}
			continue
		}
		if m := es.FindString(v); m != "" {
			i := strings.Index(v, m)
			t.Errorf("%s: queda español (%q) en: ...%s...", k, m, v[max(0, i-40):min(len(v), i+60)])
		}
	}
}
