package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

var tmpPath = regexp.MustCompile(`/tmp/[^"\s:]*|/var/folders/[^"\s:]*`)

// informesCasos recorre los textos de CollectBackups, ListBackups y DiffBackups (avisos incluidos); ctx fija el idioma.
func informesCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	dump := func(n, js, tx string, err error) {
		out[n] = tmpPath.ReplaceAllString(i18ntest.Dump(js, tx, err), "<DIR>")
	}
	collect := func(n string, s *backupSvc) {
		r, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
		dump(n, r.GetReport().GetJson(), r.GetReport().GetText(), err)
	}
	// sin bóveda: se guarda sin firma, y el startup inválido avisa
	s, _, _, dir := nuevo(t, "completed")
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\ninterface Gi1/0/1\n description PC-01\n", "hostname SW1\nntp clock-period 2\ninterface Gi1/0/1\n description PC-02\n")
	collect("collect-sin-boveda", s)
	collect("collect-idempotente", s)
	l, err := s.ListBackups(ctx, &v1.ListBackupsRequest{})
	dump("list", l.GetReport().GetJson(), l.GetReport().GetText(), err)
	a, b := "SW1_192.0.2.1/20261106T100001Z-running", "SW1_192.0.2.1/20261106T110001Z-running"
	d, err := s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: a, To: b})
	dump("diff", d.GetReport().GetJson(), d.GetReport().GetText(), err)
	d, err = s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: a, To: a})
	dump("diff-igual", d.GetReport().GetJson(), d.GetReport().GetText(), err)
	_, err = s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: a, To: "SW1_192.0.2.1/20261106T110001Z-startup"})
	dump("diff-no-existe", "", "", err)
	// lista vacía
	s2, _, _, _ := nuevo(t, "completed")
	l, err = s2.ListBackups(ctx, &v1.ListBackupsRequest{})
	dump("list-vacia", l.GetReport().GetJson(), l.GetReport().GetText(), err)
	// retención
	s3, sd3, info3, _ := nuevo(t, "completed")
	lote, pj := trabajoPropio(t, s3, sd3, info3, 1)
	_ = lote
	carpeta(t, pj, "hostname SW1\n", "hostname SW1\nvlan 10\n", "hostname SW1\nvlan 20\n")
	collect("collect-retencion", s3)
	// secciones fuera de ventana y duplicadas
	s4, sd4, info4, _ := nuevo(t, "completed")
	_, pj4 := trabajoPropio(t, s4, sd4, info4, 3)
	var sb strings.Builder
	sb.WriteString("===== 2026-11-06T10:00:01Z · show running-config =====\nhostname SW1\n")
	sb.WriteString("===== ronda 2 · 2099-01-01T00:00:00Z · show running-config =====\nfalso\n")
	os.MkdirAll(filepath.Join(pj4, dev), 0o755)
	os.WriteFile(filepath.Join(pj4, dev, "r001_20261106-100000.txt"), []byte(sb.String()), 0o600)
	collect("collect-fuera-ventana", s4)
	s5, sd5, info5, _ := nuevo(t, "completed")
	_, pj5 := trabajoPropio(t, s5, sd5, info5, 3)
	os.MkdirAll(filepath.Join(pj5, dev), 0o755)
	os.WriteFile(filepath.Join(pj5, dev, "r001_20261106-100000.txt"), []byte("===== 2026-11-06T10:00:01Z · show running-config =====\nhostname SW1\n===== 2026-11-06T10:30:00Z · show running-config =====\nfalso\n"), 0o600)
	collect("collect-duplicadas", s5)
	// tope de lectura
	for n, lim := range map[string][2]int64{"total": {1 << 20, 120}, "recorte": {60, 1 << 20}} {
		s6, sd6, info6, _ := nuevo(t, "completed")
		_, pj6 := trabajoPropio(t, s6, sd6, info6, 3)
		carpeta(t, pj6, strings.Repeat("hostname SW1\n", 20))
		restore := analyze.SetLimits(lim[0], lim[1])
		collect("collect-tope-"+n, s6)
		restore()
	}
	_ = fmt.Sprint
	return out
}

func TestInformesRespaldosRegresionEs(t *testing.T) {
	i18ntest.Golden(t, "testdata/informes_es.golden.json", informesCasos(t, context.Background()))
}

// Con en, los informes de respaldos salen sin español (salvo los datos); los errores del almacén llevan código.
func TestInformesRespaldosEnSinEspanol(t *testing.T) {
	es := informesCasos(t, context.Background())
	en := informesCasos(t, i18n.WithLocale(context.Background(), "en"))
	spanish := regexp.MustCompile(`(?i)\b(respaldo|respaldos|guardado|guardados|Aviso|AVISO|enmascarado|sin diferencias|cambios|agregadas|quitadas|ignoradas|contra|firma|bóveda|no existe|equipo no devolvió|ventana|descartó|retención|existían|borrado)\b`)
	for k, v := range en {
		if k == "diff-no-existe" {
			if !strings.Contains(v, "does not exist") {
				t.Errorf("%s: %q", k, v)
			}
			continue
		}
		// el JSON de los informes sigue en español (los campos de datos): solo se revisa el texto
		_, text, _ := strings.Cut(v, "\n---\n")
		if m := spanish.FindString(text); m != "" {
			t.Errorf("%s: queda %q en\n%s", k, m, text)
		}
		if k != "diff-no-existe" && es[k] == v {
			t.Errorf("%s: igual en es y en", k)
		}
	}
	if !strings.Contains(en["collect-sin-boveda"], "2 backup(s) saved, 0 already existed") || !strings.Contains(en["list"], "WARNING: the backups marked \"masked\"") ||
		!strings.Contains(en["diff"], "2 changes (1 added, 1 removed)") {
		t.Errorf("faltan frases en inglés:\n%s\n%s\n%s", en["collect-sin-boveda"], en["list"], en["diff"])
	}
}
