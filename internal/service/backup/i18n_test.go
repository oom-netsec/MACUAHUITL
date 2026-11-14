package backup

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// respaldoCasos recorre los errores de validación de los RPC de respaldos; ctx fija el idioma.
func respaldoCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = "ERROR: " + err.Error()
		}
	}
	sd := servicetest.New(t)
	info := &service.JobInfo{State: "completed", Dir: t.TempDir()}
	s := newSvc(jobDeps{sd, info})
	t.Cleanup(s.close)
	_, err := s.StartBackup(ctx, &v1.StartBackupRequest{})
	put("sin_equipos", err)
	_, err = s.StartBackup(ctx, &v1.StartBackupRequest{Targets: []*v1.Target{{Address: "192.0.2.1"}}, Keep: 100000})
	put("retencion", err)
	_, err = s.StartBackup(ctx, &v1.StartBackupRequest{Targets: []*v1.Target{{Address: "192.0.2.1"}}, IntervalSeconds: 60, Rounds: 1})
	put("rondas", err)
	_, err = s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1", Keep: 100000})
	put("recoger_retencion", err)
	_, err = s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: "no-existe-a", To: "no-existe-b"})
	put("diff_no_existe", err)
	_, err = s.GetBackup(ctx, &v1.GetBackupRequest{Id: "no-existe"})
	put("obtener_no_existe", err)
	_, err = s.ListBackups(ctx, &v1.ListBackupsRequest{Device: "../x"})
	put("listar_equipo", err)
	return out
}

func TestRespaldosRegresionEs(t *testing.T) {
	base := respaldoCasos(t, i18n.WithLocale(context.Background(), "es"))
	i18ntest.Golden(t, "testdata/respaldos_es.golden.json", base)
	for _, loc := range []string{"es", "es-MX"} {
		for k, v := range respaldoCasos(t, i18n.WithLocale(i18n.WithLocale(context.Background(), "es"), loc)) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de es", k, loc)
			}
		}
	}
}

func TestRespaldosEnSinEspanol(t *testing.T) {
	for k, v := range respaldoCasos(t, i18n.WithLocale(context.Background(), "en")) {
		if strings.ContainsAny(v, "áéíóúñ¿") || strings.Contains(v, "indica") || strings.Contains(v, "compara") {
			if strings.HasPrefix(k, "diff_") || strings.HasPrefix(k, "obtener_") || strings.HasPrefix(k, "listar_") { // texto de internal/backup (fuera del bloque D)
				continue
			}
			t.Errorf("%s: queda español: %q", k, v)
		}
	}
}
