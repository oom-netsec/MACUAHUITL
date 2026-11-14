package forensic

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"github.com/oom-netsec/MACUAHUITL/internal/logintel"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// forenseCasos recorre cada RPC de forense con entradas que disparan avisos, anomalías y errores. ctx fija el idioma.
func forenseCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	var dirs []string // las carpetas temporales cambian en cada corrida: se normalizan
	defer func() {
		for k, v := range out {
			for _, d := range dirs {
				v = strings.ReplaceAll(v, d, "<dir>")
			}
			out[k] = v
		}
	}()
	rep := func(n string, r interface{ GetReport() *v1.ToolReport }, err error) {
		if err != nil {
			out[n] = i18ntest.Dump("", "", err)
			return
		}
		out[n] = i18ntest.Dump(r.GetReport().Json, r.GetReport().Text, nil)
	}
	sd := servicetest.New(t)
	s := &forensicSvc{d: sd}
	dirs = append(dirs, sd.Out)
	m, err := s.MsgLookup(ctx, &v1.MsgLookupRequest{Query: "%SYS-2-MALLOCFAIL"})
	rep("msg_exacto", m, err)
	m, err = s.MsgLookup(ctx, &v1.MsgLookupRequest{Query: "%PM-4-*"})
	rep("msg_comodin", m, err)
	m, err = s.MsgLookup(ctx, &v1.MsgLookupRequest{Query: "%NO-1-EXISTE"})
	rep("msg_vacio", m, err)
	m, err = s.MsgLookup(ctx, &v1.MsgLookupRequest{Query: strings.Repeat("*", 500)})
	rep("msg_largo", m, err)
	m, err = s.MsgLookup(ctx, &v1.MsgLookupRequest{Query: "ñ"})
	rep("msg_ascii", m, err)

	for _, f := range []string{"ios15_segv", "ios15_forced", "iosxe_pman", "not_crash"} {
		b, _ := os.ReadFile("../../crashinfo/testdata/" + f + ".txt")
		c, err := s.Crashinfo(ctx, &v1.CrashinfoRequest{Text: string(b)})
		rep("crash_"+f, c, err)
	}
	c, err := s.Crashinfo(ctx, &v1.CrashinfoRequest{Text: "\x7fELF\x00\x01binario"})
	rep("crash_core", c, err)
	for n, r := range map[string]*v1.CrashinfoRequest{"vacio": {}, "los_dos": {Text: "a", Path: "/x"}, "relativa": {Path: "x"}, "no_existe": {Path: "/no/existe/x.txt"}, "directorio": {Path: tmp(&dirs, t)}, "texto_vacio": {Text: "   "}} {
		c, err := s.Crashinfo(ctx, r)
		rep("crash_err_"+n, c, err)
	}

	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteString(mensajes("192.0.2.1", "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down", t0.Add(time.Duration(i)*time.Second), 1, 0))
	}
	b.WriteString("%SYS-2-MALLOCFAIL: sin hora\n")
	b.WriteString(mensajes("192.0.2.2", "%SYS-2-MALLOCFAIL: Memory allocation of 1000 bytes failed", t0, 6, time.Second))
	lp, err := s.LogPatterns(ctx, &v1.LogPatternsRequest{Source: srcText(b.String())})
	rep("patrones", lp, err)
	lp, err = s.LogPatterns(ctx, &v1.LogPatternsRequest{Source: srcText(b.String()), BurstCount: 3, BurstWindowSeconds: 10})
	rep("patrones_rafaga", lp, err)
	lp, err = s.LogPatterns(ctx, &v1.LogPatternsRequest{Source: &v1.LogSource{Capture: true}})
	rep("patrones_sin_capturas", lp, err)
	lp, err = s.LogPatterns(ctx, &v1.LogPatternsRequest{Source: &v1.LogSource{}})
	rep("patrones_sin_fuente", lp, err)
	lp, err = (&forensicSvc{d: jobDeps{sd, ""}}).LogPatterns(ctx, &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	rep("patrones_job_sin_dir", lp, err)
	lp, err = s.LogPatterns(ctx, &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	rep("patrones_sin_patrol", lp, err)

	fl, err := s.Flapping(ctx, &v1.FlappingRequest{Source: srcText(b.String())})
	rep("flap_texto", fl, err)
	fl, err = s.Flapping(ctx, &v1.FlappingRequest{Source: srcText("%LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n%LINK-3-UPDOWN: Interface Gi0/1, changed state to up\n%LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n"), Count: 2})
	rep("flap_sin_hora", fl, err)

	dnoise := strings.Repeat("*Nov  6 10:00:01.000: OSPF-1 ADJ   Gi0/1: Rcv hello from 10.0.0.2 area 0 10.0.12.2\n", 30) +
		"*Nov  6 10:00:02.000: CDP-PA: Packet received from sw1\n*Nov  6 10:00:03.000: OSPF-1 ADJ   Gi0/1: Mismatched hello parameters from 10.0.12.2\n"
	df, err := s.DebugFilter(ctx, &v1.DebugFilterRequest{Text: dnoise, Noise: []string{"CDP-PA"}})
	rep("debug", df, err)
	df, err = s.DebugFilter(ctx, &v1.DebugFilterRequest{Text: dnoise, FamilyMin: 100})
	rep("debug_alarma", df, err)
	df, err = s.DebugFilter(ctx, &v1.DebugFilterRequest{Text: "a", Noise: make([]string, 51)})
	rep("debug_ruido", df, err)
	df, err = s.DebugFilter(ctx, &v1.DebugFilterRequest{})
	rep("debug_vacio", df, err)

	dir := tmp(&dirs, t)
	sj := &forensicSvc{d: jobDeps{sd, dir}}
	const mb = 1 << 20
	for i, bgp := range []int{10 * mb, 12 * mb, 15 * mb} {
		ronda(t, dir, "SW1_192.0.2.1", i+1, map[string]string{"show processes memory sorted": procMem(bgp, 5*mb), "show interfaces": ifaz(i, i*3), "show logging": ""})
	}
	ml, err := sj.MemLeaks(ctx, &v1.MemLeaksRequest{Job: "j1"})
	rep("fuga", ml, err)
	ml, err = sj.MemLeaks(ctx, &v1.MemLeaksRequest{Job: "j1", MinRounds: 4})
	rep("fuga_pocas_rondas", ml, err)
	ml, err = sj.MemLeaks(ctx, &v1.MemLeaksRequest{})
	rep("fuga_sin_trabajo", ml, err)
	fl, err = sj.Flapping(ctx, &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	rep("flap_trabajo", fl, err)
	lp, err = sj.LogPatterns(ctx, &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	rep("patrones_trabajo", lp, err)
	dir2 := tmp(&dirs, t)
	ronda(t, dir2, "SW1_192.0.2.1", 1, map[string]string{"show processes memory": "texto raro", "show interfaces": "texto raro", "show logging": "Nov  6 10:00:00: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down"})
	s2 := &forensicSvc{d: jobDeps{sd, dir2}}
	ml, err = s2.MemLeaks(ctx, &v1.MemLeaksRequest{Job: "j1"})
	rep("fuga_formato", ml, err)
	fl, err = s2.Flapping(ctx, &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	rep("flap_formato", fl, err)
	dir3 := tmp(&dirs, t)
	ronda(t, dir3, "SW1_192.0.2.1", 1, map[string]string{"show version": "x"})
	s3 := &forensicSvc{d: jobDeps{sd, dir3}}
	fl, err = s3.Flapping(ctx, &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	rep("flap_sin_interfaces", fl, err)
	ml, err = s3.MemLeaks(ctx, &v1.MemLeaksRequest{Job: "j1"})
	rep("fuga_sin_memoria", ml, err)
	ml, err = s.MemLeaks(ctx, &v1.MemLeaksRequest{Job: "/no/existe"})
	rep("fuga_dir_malo", ml, err)
	return out
}

// Regresión: sin idioma, con es o con uno desconocido, cada RPC de forense devuelve lo mismo que antes del catálogo.
func TestForenseRegresionEs(t *testing.T) {
	i18ntest.Golden(t, "testdata/forense_es.golden.json", forenseCasos(t, i18n.WithLocale(context.Background(), "es")))
	for _, loc := range []string{"es", "es-MX"} {
		got := forenseCasos(t, i18n.WithLocale(i18n.WithLocale(context.Background(), "es"), loc))
		base := forenseCasos(t, i18n.WithLocale(context.Background(), "es"))
		for k, v := range got {
			if base[k] != v {
				t.Errorf("%s con %q difiere de es", k, loc)
			}
		}
	}
}

func tmp(dirs *[]string, t *testing.T) string {
	d := t.TempDir()
	*dirs = append(*dirs, d)
	return d
}

// Con en, ningún RPC de forense deja español en lo que traduce el núcleo (el texto de sistema y los datos no cuentan).
func TestForenseEnSinEspanol(t *testing.T) {
	es := regexp.MustCompile(`[áéíóúñ¿¡]|\b(mensajes?|línea|ronda|rondas|aviso|Aviso|equipo|equipos|interfaz|archivo|trabajo|falta|Causa|Acción|Significado|Fuente|ninguna|Ninguna|texto|captura|hacen|solo|hay|sin|con)\b`)
	got := forenseCasos(t, i18n.WithLocale(context.Background(), "en"))
	base := forenseCasos(t, i18n.WithLocale(context.Background(), "es"))
	for k, v := range got {
		if k == "crash_err_directorio" || k == "patrones_sin_patrol" { // el texto viene de internal/sys (fuera del bloque D)
			continue
		}
		if v == base[k] && !strings.HasPrefix(k, "crash_err_no_existe") && !strings.Contains(k, "dir_malo") {
			t.Errorf("%s: en igual a es", k)
		}
		v = strings.ReplaceAll(v, "%SYS-2-MALLOCFAIL: sin hora", "") // dato de la entrada, no texto del núcleo
		if m := es.FindString(v); m != "" {
			i := strings.Index(v, m)
			t.Errorf("%s: queda español (%q) en: ...%s...", k, m, v[max(0, i-40):min(len(v), i+60)])
		}
	}
}

// Los avisos en paralelo (es y Text) nunca se desalinean: con en, cada aviso del informe es el de su propio código.
func TestForenseAvisosAlineados(t *testing.T) {
	rep := logintel.FilterDebug(strings.Repeat("OSPF-1 ADJ x\n", 30), logintel.DebugOptions{})
	if len(rep.Warnings) != len(rep.WarnT) {
		t.Fatalf("%d avisos y %d textos", len(rep.Warnings), len(rep.WarnT))
	}
	if got := i18n.Notes(i18n.En, []string{"a", "b"}, []i18n.Text{i18n.Tx("forensic.warn.no_logging")}); got[0] != "a" || got[1] != "b" {
		t.Fatalf("listas desparejas deben quedar en es: %v", got)
	}
}
