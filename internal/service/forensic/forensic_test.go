package forensic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

func nuevo(t *testing.T) (*forensicSvc, *servicetest.Deps) {
	sd := servicetest.New(t)
	return &forensicSvc{d: sd}, sd
}

func code(err error) codes.Code { return status.Code(err) }

func TestMsgLookupExactoComodinYAuditoria(t *testing.T) {
	s, sd := nuevo(t)
	r, err := s.MsgLookup(context.Background(), &v1.MsgLookupRequest{Query: "%SYS-2-MALLOCFAIL"})
	if err != nil || !strings.Contains(r.Report.Text, "Causa probable") {
		t.Fatalf("%v %v", r, err)
	}
	var es []struct{ ID string }
	if json.Unmarshal([]byte(r.Report.Json), &es) != nil || len(es) != 1 {
		t.Fatalf("json %s", r.Report.Json)
	}
	if r, err = s.MsgLookup(context.Background(), &v1.MsgLookupRequest{Query: "%PM-4-*"}); err != nil || strings.Count(r.Report.Json, `"id"`) < 2 {
		t.Fatalf("%v %v", r, err)
	}
	if r, err = s.MsgLookup(context.Background(), &v1.MsgLookupRequest{Query: "%NO-1-EXISTE"}); err != nil || r.Report.Json != "[]" {
		t.Fatalf("sin resultados debe ser []: %v %v", r, err)
	}
	if _, err = s.MsgLookup(context.Background(), &v1.MsgLookupRequest{Query: strings.Repeat("*", 500)}); code(err) != codes.InvalidArgument {
		t.Fatalf("consulta enorme: %v", err)
	}
	if !strings.Contains(sd.AuditText(), `"action":"forensic.msg"`) {
		t.Fatal("sin auditoría")
	}
}

func TestCrashinfoPorTextoYPorRuta(t *testing.T) {
	s, sd := nuevo(t)
	b, _ := os.ReadFile("../../crashinfo/testdata/ios15_segv.txt")
	r, err := s.Crashinfo(context.Background(), &v1.CrashinfoRequest{Text: string(b)})
	if err != nil || !strings.Contains(r.Report.Text, "IP Input") || !strings.Contains(r.Report.Text, "MALLOCFAIL") || !strings.Contains(r.Report.Text, "Causa probable") {
		t.Fatalf("%v %v", r, err)
	}
	p := filepath.Join(t.TempDir(), "crashinfo_1")
	os.WriteFile(p, b, 0o600)
	if r, err = s.Crashinfo(context.Background(), &v1.CrashinfoRequest{Path: p}); err != nil || !strings.Contains(r.Report.Text, "SegV") {
		t.Fatalf("%v %v", r, err)
	}
	if !strings.Contains(sd.AuditText(), `"action":"forensic.crashinfo"`) {
		t.Fatal("sin auditoría")
	}
}

func TestCrashinfoEntradaMala(t *testing.T) {
	s, _ := nuevo(t)
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	os.WriteFile(big, []byte("System returned to ROM by power-on\n"+strings.Repeat("x", 5<<20)), 0o600)
	for name, c := range map[string]struct {
		r    *v1.CrashinfoRequest
		want codes.Code
	}{
		"vacío":        {&v1.CrashinfoRequest{}, codes.InvalidArgument},
		"los dos":      {&v1.CrashinfoRequest{Text: "a", Path: "/x"}, codes.InvalidArgument},
		"relativa":     {&v1.CrashinfoRequest{Path: "crash.txt"}, codes.InvalidArgument},
		"no existe":    {&v1.CrashinfoRequest{Path: filepath.Join(dir, "no")}, codes.NotFound},
		"directorio":   {&v1.CrashinfoRequest{Path: dir}, codes.InvalidArgument},
		"dispositivo":  {&v1.CrashinfoRequest{Path: "/dev/zero"}, codes.InvalidArgument},
		"solo blancos": {&v1.CrashinfoRequest{Text: "  \n"}, codes.InvalidArgument},
		"texto enorme": {&v1.CrashinfoRequest{Text: strings.Repeat("a", maxText+1)}, codes.InvalidArgument},
	} {
		if _, err := s.Crashinfo(context.Background(), c.r); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	r, err := s.Crashinfo(context.Background(), &v1.CrashinfoRequest{Path: big})
	if err != nil || !strings.Contains(r.Report.Json, `"truncated":true`) || !strings.Contains(r.Report.Json, `"bytes":4194305`) {
		t.Fatalf("archivo grande debe truncarse: %v %v", r, err)
	}
}

// jobDeps responde Job con una carpeta fija (el doble de servicetest no tiene Patrol).
type jobDeps struct {
	*servicetest.Deps
	dir string
}

func (d jobDeps) Job(context.Context, string) (service.JobInfo, error) {
	return service.JobInfo{State: "completed", Dir: d.dir}, nil
}

// ronda escribe la salida de una ronda de un equipo con los comandos dados (comando → salida).
func ronda(t *testing.T, dir, dev string, n int, cmds map[string]string) {
	t.Helper()
	rondaAt(t, dir, dev, n, time.Date(2026, 11, 6, 10+n, 0, 0, 0, time.UTC), cmds)
}

// rondaAt escribe la ronda n de un equipo con la hora at (el comando i lleva at+i segundos).
func rondaAt(t *testing.T, dir, dev string, n int, at time.Time, cmds map[string]string) {
	t.Helper()
	d := filepath.Join(dir, dev)
	os.MkdirAll(d, 0o755)
	var b strings.Builder
	keys := make([]string, 0, len(cmds))
	for k := range cmds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		fmt.Fprintf(&b, "===== %s · %s =====\n%s\n", at.Add(time.Duration(i)*time.Second).Format("2006-01-02T15:04:05Z"), k, cmds[k])
	}
	name := fmt.Sprintf("r%03d_%s.txt", n, at.Format("20060102-150405"))
	if err := os.WriteFile(filepath.Join(d, name), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func srcText(s string) *v1.LogSource { return &v1.LogSource{Text: s} }

func mensajes(host, msg string, t0 time.Time, n int, step time.Duration) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s %s:514 <187>%s\n", t0.Add(time.Duration(i)*step).Format(time.RFC3339Nano), host, msg)
	}
	return b.String()
}

func TestLogPatternsPorTextoYAuditoria(t *testing.T) {
	s, sd := nuevo(t)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	in := mensajes("192.0.2.1", "%LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down", t0, 6, time.Second)
	r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: srcText(in)})
	if err != nil || !strings.Contains(r.Report.Text, "[RÁFAGA] x6") || !strings.Contains(r.Report.Text, "Fuente: texto pegado") {
		t.Fatalf("%v %v", r, err)
	}
	var out struct {
		Patterns []struct{ Burst bool }
		Source   string
	}
	if json.Unmarshal([]byte(r.Report.Json), &out) != nil || len(out.Patterns) != 1 || !out.Patterns[0].Burst || out.Source != "texto pegado" {
		t.Fatalf("json %s", r.Report.Json)
	}
	// El umbral se puede subir: 6 mensajes ya no son ráfaga con N=7.
	if r, err = s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: srcText(in), BurstCount: 7}); err != nil || strings.Contains(r.Report.Text, "[RÁFAGA]") {
		t.Fatalf("N=7: %v %v", r, err)
	}
	if !strings.Contains(sd.AuditText(), `"action":"forensic.patterns"`) {
		t.Fatal("sin auditoría")
	}
}

func TestLogPatternsFuentes(t *testing.T) {
	s, sd := nuevo(t)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	// Una sola fuente a la vez.
	for name, src := range map[string]*v1.LogSource{
		"ninguna": {}, "dos": {Text: "a", Capture: true}, "tres": {Text: "a", Path: "/x", Job: "j"}, "nulo": nil,
	} {
		if _, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: src}); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Archivo.
	p := filepath.Join(t.TempDir(), "log.txt")
	os.WriteFile(p, []byte(mensajes("192.0.2.1", "%PM-4-ERR_DISABLE: bpduguard error detected on Fa0/1", t0, 2, time.Second)), 0o600)
	if r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Path: p}}); err != nil || !strings.Contains(r.Report.Text, "x2") || !strings.Contains(r.Report.Text, "Fuente: "+p) {
		t.Fatalf("archivo: %v %v", r, err)
	}
	// Captura del receptor.
	if r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Capture: true}}); err != nil || !strings.Contains(r.Report.Text, "no hay capturas") {
		t.Fatalf("captura vacía: %v %v", r, err)
	}
	dir := filepath.Join(sd.Out, "syslog")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "syslog_20261106-100000.log"), []byte(mensajes("192.0.2.1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", t0, 3, time.Second)), 0o600)
	os.WriteFile(filepath.Join(dir, "syslog_20261106-110000.log"), []byte(mensajes("192.0.2.2", "%LINK-3-UPDOWN: Interface Gi0/9, changed state to down", t0, 2, time.Second)), 0o600)
	if r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Capture: true}}); err != nil || !strings.Contains(r.Report.Text, "x5") {
		t.Fatalf("captura: %v %v", r, err)
	}
}

func TestLogPatternsDeUnTrabajoSinRepetirElBufer(t *testing.T) {
	sd := servicetest.New(t)
	dir := t.TempDir()
	s := &forensicSvc{d: jobDeps{sd, dir}}
	log1 := "*Nov  6 10:00:01.100: %LINK-3-UPDOWN: Interface Gi0/3, changed state to down\n*Nov  6 10:00:02.200: %LINK-3-UPDOWN: Interface Gi0/3, changed state to up"
	log2 := log1 + "\n*Nov  6 11:00:05.000: %LINK-3-UPDOWN: Interface Gi0/3, changed state to down" // la ronda 2 arrastra el búfer
	ronda(t, dir, "SW1_192.0.2.1", 1, map[string]string{"show logging": log1, "show version": "x"})
	ronda(t, dir, "SW1_192.0.2.1", 2, map[string]string{"show logging": log2})
	ronda(t, dir, "SW2_192.0.2.2", 1, map[string]string{"show logging": "*Nov  6 10:00:03.000: %LINK-3-UPDOWN: Interface Gi0/4, changed state to down"})
	r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "4 mensaje(s) en 2 patrón(es)") || !strings.Contains(r.Report.Text, "x3  ") || !strings.Contains(r.Report.Text, "equipos (2)") {
		t.Fatalf("%v %v", r, err)
	}
	if r, err = s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1", Device: "sw2"}}); err != nil || !strings.Contains(r.Report.Text, "x1") {
		t.Fatalf("filtro por equipo: %v %v", r, err)
	}
	// Por ruta absoluta de la carpeta.
	if r, err = (&forensicSvc{d: sd}).LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Job: dir}}); err != nil || !strings.Contains(r.Report.Text, "4 mensaje(s)") {
		t.Fatalf("ruta: %v %v", r, err)
	}
}

func ifaz(resets, lost int) string {
	return fmt.Sprintf("GigabitEthernet0/3 is up, line protocol is up (connected)\n     0 output errors, 0 collisions, %d interface resets\n     %d lost carrier, 0 no carrier, 0 pause output\n", resets, lost)
}

func TestFlappingPorTextoYPorTrabajo(t *testing.T) {
	s, sd := nuevo(t)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteString(mensajes("192.0.2.1", "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down", t0.Add(time.Duration(i)*time.Second), 1, 0))
	}
	r, err := s.Flapping(context.Background(), &v1.FlappingRequest{Source: srcText(b.String())})
	if err != nil || !strings.Contains(r.Report.Text, "[FLAPPING] 192.0.2.1 Gi0/3") {
		t.Fatalf("%v %v", r, err)
	}
	var out struct {
		Flaps        []struct{ Interface string }
		CounterJumps []struct{} `json:"counter_jumps"`
	}
	if json.Unmarshal([]byte(r.Report.Json), &out) != nil || len(out.Flaps) != 1 || out.CounterJumps == nil || strings.Contains(r.Report.Json, `"counter_jumps":null`) {
		t.Fatalf("json %s", r.Report.Json)
	}
	if r, err = s.Flapping(context.Background(), &v1.FlappingRequest{Source: srcText(b.String()), Count: 5}); err != nil || !strings.Contains(r.Report.Text, "Ninguna interfaz con flapping") {
		t.Fatalf("N=5: %v %v", r, err)
	}
	if !strings.Contains(sd.AuditText(), `"action":"forensic.flapping"`) {
		t.Fatal("sin auditoría")
	}

	// Un trabajo: contadores de show interfaces entre tres rondas.
	dir := t.TempDir()
	sj := &forensicSvc{d: jobDeps{sd, dir}}
	ronda(t, dir, "SW1_192.0.2.1", 1, map[string]string{"show interfaces": ifaz(1, 0), "show logging": ""})
	ronda(t, dir, "SW1_192.0.2.1", 2, map[string]string{"show interfaces": ifaz(2, 0)})
	ronda(t, dir, "SW1_192.0.2.1", 3, map[string]string{"show interfaces": ifaz(9, 5)})
	r, err = sj.Flapping(context.Background(), &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "interface resets subió de 2 a 9 (+7) entre las rondas 2 y 3") || !strings.Contains(r.Report.Text, "lost carrier subió de 0 a 5") {
		t.Fatalf("%v %v", r, err)
	}
	if strings.Contains(r.Report.Text, "de 1 a 2") {
		t.Fatalf("+1 no es un salto con el umbral por defecto:\n%s", r.Report.Text)
	}
	if r, err = sj.Flapping(context.Background(), &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}, MinDelta: 8}); err != nil || strings.Contains(r.Report.Text, "[SALTO]") {
		t.Fatalf("umbral 8: %v %v", r, err)
	}
	// Sin show interfaces el trabajo avisa en vez de callar.
	dir2 := t.TempDir()
	ronda(t, dir2, "SW1_192.0.2.1", 1, map[string]string{"show logging": "*Nov  6 10:00:01.100: %LINK-3-UPDOWN: Interface Gi0/3, changed state to down"})
	r, err = (&forensicSvc{d: jobDeps{sd, dir2}}).Flapping(context.Background(), &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "el trabajo no tiene show interfaces") {
		t.Fatalf("%v %v", r, err)
	}

	// Un contador que la ronda anterior no imprimía no se compara con cero; show interfaces status no es show interfaces.
	dir3 := t.TempDir()
	ronda(t, dir3, "SW1_192.0.2.1", 1, map[string]string{"show interfaces": "GigabitEthernet0/3 is up, line protocol is up\n     0 output errors, 0 collisions, 1 interface resets\n", "show interfaces status": "Port Name Status\nGi0/3 connected"})
	ronda(t, dir3, "SW1_192.0.2.1", 2, map[string]string{"show interfaces": ifaz(1, 5)})
	r, err = (&forensicSvc{d: jobDeps{sd, dir3}}).Flapping(context.Background(), &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || strings.Contains(r.Report.Text, "[SALTO]") || strings.Contains(r.Report.Text, "no se reconoce") {
		t.Fatalf("%v %v", r, err)
	}
}

func TestDebugFilter(t *testing.T) {
	s, sd := nuevo(t)
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("*Nov  6 10:00:01.000: OSPF-1 ADJ   Gi0/1: Rcv hello from 10.0.0.2 area 0 10.0.12.2\n")
	}
	b.WriteString("*Nov  6 10:00:02.000: CDP-PA: Packet received from sw1\n*Nov  6 10:00:03.000: OSPF-1 ADJ   Gi0/1: Mismatched hello parameters from 10.0.12.2\n")
	r, err := s.DebugFilter(context.Background(), &v1.DebugFilterRequest{Text: b.String(), Noise: []string{"CDP-PA"}})
	if err != nil || !strings.Contains(r.Report.Text, "1 líneas ocultas por ruido") || !strings.Contains(r.Report.Text, "línea 32 [rara dentro de una familia frecuente") {
		t.Fatalf("%v %v", r, err)
	}
	p := filepath.Join(t.TempDir(), "debug.txt")
	os.WriteFile(p, []byte(b.String()), 0o600)
	if r, err = s.DebugFilter(context.Background(), &v1.DebugFilterRequest{Path: p, FamilyMin: 100}); err != nil || strings.Contains(r.Report.Text, "rara dentro") || !strings.Contains(r.Report.Text, "palabra de alarma") {
		t.Fatalf("umbral propio: %v %v", r, err)
	}
	if r, err = s.DebugFilter(context.Background(), &v1.DebugFilterRequest{Text: b.String(), Top: 1}); err != nil || strings.Count(r.Report.Json, `"example"`) != 1 {
		t.Fatalf("top: %v %v", r, err)
	}
	for name, req := range map[string]*v1.DebugFilterRequest{
		"vacío": {}, "los dos": {Text: "a", Path: "/x"}, "relativa": {Path: "x"}, "ruido de más": {Text: "a", Noise: make([]string, 51)},
	} {
		if _, err := s.DebugFilter(context.Background(), req); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !strings.Contains(sd.AuditText(), `"action":"forensic.debugs"`) {
		t.Fatal("sin auditoría")
	}
}

func procMem(holdingBGP, holdingIP int) string {
	return fmt.Sprintf("Processor Pool Total:   25834496 Used:   21246812 Free:    4587684\n\n PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process\n   0   0   17240512    2461460   13590116          0          0 *Init*\n 312   0   45678912    1234567   %d          0          0 BGP Router\n 184   0     972312      56920   %d          0          0 IP Input\n", holdingBGP, holdingIP)
}

func TestMemLeaks(t *testing.T) {
	sd := servicetest.New(t)
	dir := t.TempDir()
	s := &forensicSvc{d: jobDeps{sd, dir}}
	const m = 1 << 20
	for i, bgp := range []int{10 * m, 12 * m, 15 * m} {
		ronda(t, dir, "SW1_192.0.2.1", i+1, map[string]string{"show processes memory sorted": procMem(bgp, 5*m)})
		ronda(t, dir, "SW2_192.0.2.2", i+1, map[string]string{"show processes memory": procMem(10*m, 5*m)})
	}
	r, err := s.MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1"})
	if err != nil || !strings.Contains(r.Report.Text, "[FUGA POSIBLE] SW1_192.0.2.1 BGP Router (pid 312): +5.0 MiB") || strings.Contains(r.Report.Text, "SW2_192.0.2.2 BGP") || strings.Contains(r.Report.Text, "*Init*") {
		t.Fatalf("%v %v", r, err)
	}
	if r, err = s.MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1", MinGrowthKib: 6 * 1024}); err != nil || strings.Contains(r.Report.Text, "[FUGA POSIBLE]") {
		t.Fatalf("umbral 6 MiB: %v %v", r, err)
	}
	if r, err = s.MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1", MinRounds: 4}); err != nil || strings.Contains(r.Report.Text, "[FUGA POSIBLE]") || !strings.Contains(r.Report.Text, "hacen falta 4") {
		t.Fatalf("4 rondas: %v %v", r, err)
	}
	if r, err = s.MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1", Device: "sw2"}); err != nil || strings.Contains(r.Report.Text, "[FUGA POSIBLE]") || !strings.Contains(r.Report.Text, "2 proceso(s) analizado(s)") {
		t.Fatalf("filtro: %v %v", r, err)
	}
	if _, err = s.MemLeaks(context.Background(), &v1.MemLeaksRequest{}); code(err) != codes.InvalidArgument {
		t.Fatalf("sin trabajo: %v", err)
	}
	// La variante platform y los formatos ajenos avisan, no se tragan.
	dir2 := t.TempDir()
	ronda(t, dir2, "SW1_192.0.2.1", 1, map[string]string{"show processes memory platform sorted": "Pid Text Data Stack Dynamic RefCnt Name\n 1 1 1 1 1 1 init", "show processes memory": "texto raro"})
	r, err = (&forensicSvc{d: jobDeps{sd, dir2}}).MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1"})
	if err != nil || strings.Count(r.Report.Text, "formato que no se reconoce") != 1 {
		t.Fatalf("%v %v", r, err)
	}
	dir4 := t.TempDir()
	ronda(t, dir4, "SW1_192.0.2.1", 1, map[string]string{"show processes memory platform sorted": "Pid Text Data Stack Dynamic RefCnt Name\n 1 1 1 1 1 1 init"})
	if r, err = (&forensicSvc{d: jobDeps{sd, dir4}}).MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1"}); err != nil || strings.Contains(r.Report.Text, "formato") || !strings.Contains(r.Report.Text, "no hay show processes memory") {
		t.Fatalf("solo platform: %v %v", r, err)
	}
	// Dos comandos de memoria en la misma ronda no duplican los puntos de la serie.
	dir3 := t.TempDir()
	for i, bgp := range []int{10 * m, 12 * m, 15 * m} {
		ronda(t, dir3, "SW1_192.0.2.1", i+1, map[string]string{"show processes memory": procMem(bgp, 5*m), "show processes memory sorted": procMem(bgp, 5*m)})
	}
	if r, err = (&forensicSvc{d: jobDeps{sd, dir3}}).MemLeaks(context.Background(), &v1.MemLeaksRequest{Job: "j1"}); err != nil || !strings.Contains(r.Report.Text, "[FUGA POSIBLE]") {
		t.Fatalf("duplicados: %v %v", r, err)
	}
	if !strings.Contains(sd.AuditText(), `"action":"forensic.memleaks"`) {
		t.Fatal("sin auditoría")
	}
}

// Una FIFO no tiene escritor: abrirla sin O_NONBLOCK bloquearía la RPC para siempre.
func TestRutaFIFONoCuelga(t *testing.T) {
	s, _ := nuevo(t)
	p := filepath.Join(t.TempDir(), "tubo")
	if err := sys.Mkfifo(p); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 2)
	go func() { _, err := s.Crashinfo(context.Background(), &v1.CrashinfoRequest{Path: p}); done <- err }()
	go func() {
		_, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Path: p}})
		done <- err
	}()
	for range 2 {
		select {
		case err := <-done:
			if code(err) != codes.InvalidArgument {
				t.Fatalf("una FIFO debe rechazarse: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("la RPC se colgó con una FIFO")
		}
	}
}

// Con un archivo de captura más grande que el tope se conserva lo más reciente (el final) y
// no se lee el archivo entero.
func TestCapturaMasGrandeQueElTopeConservaElFinal(t *testing.T) {
	s, sd := nuevo(t)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	viejo := mensajes("192.0.2.1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", t0, 40, time.Second)
	nuevoTxt := mensajes("192.0.2.1", "%PM-4-ERR_DISABLE: bpduguard error detected on Fa0/1", t0.Add(time.Hour), 10, time.Second)
	dir := filepath.Join(sd.Out, "syslog")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "syslog_20261106-100000.log"), []byte(viejo+nuevoTxt), 0o600)
	s.logCap = int64(len(nuevoTxt)) + 30 // el final y un pedazo de línea del viejo
	r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Capture: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Report.Text, "x10") || !strings.Contains(r.Report.Text, "ERR_DISABLE") {
		t.Fatalf("faltan los mensajes recientes:\n%s", r.Report.Text)
	}
	if strings.Contains(r.Report.Text, "LINK-3-UPDOWN") {
		t.Fatalf("se leyó el principio del archivo:\n%s", r.Report.Text)
	}
	if !strings.Contains(r.Report.Text, "final") {
		t.Fatalf("falta el aviso de recorte:\n%s", r.Report.Text)
	}
}

// Un informe que pasaría del tope se recorta (se pierde la cola, ya ordenada por importancia) y
// lo avisa; el JSON y el texto quedan dentro del tope.
func TestInformeGrandeSeRecortaConAviso(t *testing.T) {
	s, _ := nuevo(t)
	s.repCap = 20 << 10
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var txt strings.Builder
	for i := range 300 {
		fmt.Fprintf(&txt, "%s 192.0.2.1:514 <187>%%FAC-5-NOMBRE%c%c%c: %s\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), 'A'+i%26, 'A'+i/26%26, 'A'+i/676, strings.Repeat("palabra ", 25))
	}
	r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: srcText(txt.String())})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Report.Json) > 20<<10 || len(r.Report.Text) > 20<<10 {
		t.Fatalf("json %d texto %d: pasa del tope", len(r.Report.Json), len(r.Report.Text))
	}
	if !strings.Contains(r.Report.Text, "informe recortado") || !strings.Contains(r.Report.Json, "informe recortado") {
		t.Fatalf("sin aviso de recorte:\n%.600s", r.Report.Text)
	}
	if !strings.Contains(r.Report.Text, "mensaje(s)") || !strings.Contains(r.Report.Text, "NOMBREA") {
		t.Fatalf("se perdió el principio:\n%.600s", r.Report.Text)
	}
}

// max_kib acota cuánto se relee de la captura (modo en vivo): solo el final.
func TestCapturaMaxKiBLeeSoloElFinal(t *testing.T) {
	s, sd := nuevo(t)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	dir := filepath.Join(sd.Out, "syslog")
	os.MkdirAll(dir, 0o700)
	viejo := mensajes("192.0.2.1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", t0, 100, time.Second)
	nuevoTxt := mensajes("192.0.2.1", "%PM-4-ERR_DISABLE: bpduguard error detected on Fa0/1", t0.Add(time.Hour), 5, time.Second)
	os.WriteFile(filepath.Join(dir, "syslog_20261106-100000.log"), []byte(viejo+nuevoTxt), 0o600)
	r, err := s.LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Capture: true, MaxKib: 1}})
	if err != nil || !strings.Contains(r.Report.Text, "ERR_DISABLE") || strings.Contains(r.Report.Text, "x100") {
		t.Fatalf("%v\n%s", err, r.GetReport().GetText())
	}
}

// Una ronda del 1 de enero con marcas sin año: el 31 de diciembre es del año anterior, no del
// siguiente (quedaría en el futuro y el flapping se partiría en dos años).
func TestTrabajoCambioDeAnoDetectaFlapping(t *testing.T) {
	sd := servicetest.New(t)
	dir := t.TempDir()
	log := "*Dec 31 23:59:50.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n" +
		"*Dec 31 23:59:55.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up\n" +
		"*Jan  1 00:00:05.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n" +
		"*Jan  1 00:00:10.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up"
	rondaAt(t, dir, "SW1_192.0.2.1", 1, time.Date(2027, 1, 1, 0, 0, 30, 0, time.UTC), map[string]string{"show logging": log})
	r, err := (&forensicSvc{d: jobDeps{sd, dir}}).Flapping(context.Background(), &v1.FlappingRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "[FLAPPING]") || !strings.Contains(r.Report.Text, "de 2026-12-31T23:59:50") {
		t.Fatalf("%v\n%s", err, r.GetReport().GetText())
	}
}

// Los mensajes sin hora no se pueden deduplicar por hora: el búfer que se arrastra entre rondas
// se reconoce por el solape entre el final de una ronda y el principio de la siguiente, y un
// mensaje que de verdad se repite no se pierde.
func TestTrabajoSinHoraDeduplicaPorSolape(t *testing.T) {
	sd := servicetest.New(t)
	dir := t.TempDir()
	a := "%LINK-3-UPDOWN: Interface Gi0/3, changed state to down"
	b := "%PM-4-ERR_DISABLE: bpduguard error detected on Fa0/1"
	ronda(t, dir, "SW1_192.0.2.1", 1, map[string]string{"show logging": a + "\n" + a})
	ronda(t, dir, "SW1_192.0.2.1", 2, map[string]string{"show logging": a + "\n" + a + "\n" + a + "\n" + b}) // arrastra 2 y suma 2
	r, err := (&forensicSvc{d: jobDeps{sd, dir}}).LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "4 mensaje(s) en 2 patrón(es)") || !strings.Contains(r.Report.Text, "x3  ") {
		t.Fatalf("%v\n%s", err, r.GetReport().GetText())
	}
}

// La hora de show logging es la del equipo: con show clock detail del mismo trabajo se pasa a UTC;
// sin él se avisa.
func TestTrabajoZonaHorariaConShowClock(t *testing.T) {
	sd := servicetest.New(t)
	dir := t.TempDir()
	msgs := "*Nov  6 05:00:01.100: %LINK-3-UPDOWN: Interface Gi0/3, changed state to down\n*Nov  6 05:00:02.200: %LINK-3-UPDOWN: Interface Gi0/3, changed state to up"
	at := time.Date(2026, 11, 6, 11, 0, 0, 0, time.UTC)
	rondaAt(t, dir, "SW1_192.0.2.1", 1, at, map[string]string{"show clock detail": "05:00:00.123 CST Fri Nov 6 2026\nTime source is NTP", "show logging": msgs})
	r, err := (&forensicSvc{d: jobDeps{sd, dir}}).LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "de 2026-11-06T11:00:01Z") || strings.Contains(r.Report.Text, "sin zona") {
		t.Fatalf("con show clock: %v\n%s", err, r.GetReport().GetText())
	}
	dir2 := t.TempDir()
	rondaAt(t, dir2, "SW1_192.0.2.1", 1, at, map[string]string{"show logging": msgs})
	r, err = (&forensicSvc{d: jobDeps{sd, dir2}}).LogPatterns(context.Background(), &v1.LogPatternsRequest{Source: &v1.LogSource{Job: "j1"}})
	if err != nil || !strings.Contains(r.Report.Text, "hora sin zona, se asume la del equipo") {
		t.Fatalf("sin show clock: %v\n%s", err, r.GetReport().GetText())
	}
}

func TestOverlap(t *testing.T) {
	for name, c := range map[string]struct {
		prev, cur string
		want      int
	}{
		"vacío":              {"", "a b", 0},
		"sin solape":         {"a", "b", 0},
		"todo el anterior":   {"a a", "a a a b", 2},
		"cola del anterior":  {"x a b", "a b c", 2},
		"iguales":            {"a b", "a b", 2},
		"con retroceso":      {"a b a b a", "a b a c", 3},
		"anterior repetido":  {"a a a", "a a", 2},
		"solape corto mayor": {"b a b", "b a b b", 3},
	} {
		if got := overlap(strings.Fields(c.prev), strings.Fields(c.cur)); got != c.want {
			t.Errorf("%s: %d, quería %d", name, got, c.want)
		}
	}
}
