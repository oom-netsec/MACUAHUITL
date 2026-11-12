package visibility

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/syslogd/syslogdtest"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// stream hace de cliente gRPC de SnmpTraps o Flows: guarda lo recibido y, con stuck, se atasca tras el primer
// envío (el de la dirección), como un Send sin ventana de flujo.
type stream[M any] struct {
	ctx     context.Context
	mu      sync.Mutex
	got     []M
	stuck   chan struct{} // nil = no se atasca
	first   chan M
	started bool
}

func (s *stream[M]) Context() context.Context { return s.ctx }
func (s *stream[M]) Send(m M) error {
	s.mu.Lock()
	first := !s.started
	s.started = true
	if !first && s.stuck == nil {
		s.got = append(s.got, m)
	}
	s.mu.Unlock()
	if first {
		s.first <- m
		return nil
	}
	if s.stuck != nil {
		<-s.stuck
	}
	return nil
}

type (
	trapStream struct {
		v1.VisibilityService_SnmpTrapsServer
		*stream[*v1.SnmpTrapsResponse]
	}
	flowStream struct {
		v1.VisibilityService_FlowsServer
		*stream[*v1.FlowsResponse]
	}
)

func (s trapStream) Context() context.Context           { return s.stream.Context() }
func (s trapStream) Send(m *v1.SnmpTrapsResponse) error { return s.stream.Send(m) }
func (s flowStream) Context() context.Context           { return s.stream.Context() }
func (s flowStream) Send(m *v1.FlowsResponse) error     { return s.stream.Send(m) }

func newTrapStream(stuck bool) trapStream {
	st := &stream[*v1.SnmpTrapsResponse]{ctx: context.Background(), first: make(chan *v1.SnmpTrapsResponse, 1)}
	if stuck {
		st.stuck = make(chan struct{})
	}
	return trapStream{stream: st}
}

func newFlowStream(stuck bool) flowStream {
	st := &stream[*v1.FlowsResponse]{ctx: context.Background(), first: make(chan *v1.FlowsResponse, 1)}
	if stuck {
		st.stuck = make(chan struct{})
	}
	return flowStream{stream: st}
}

func sendTraps(t *testing.T, addr string, n int) {
	t.Helper()
	i := strings.LastIndex(addr, ":")
	h, p := addr[:i], addr[i+1:]
	port, _ := strconv.Atoi(p)
	x := &gosnmp.GoSNMP{Target: h, Port: uint16(port), Version: gosnmp.Version2c, Community: "public", Timeout: time.Second}
	if err := x.Connect(); err != nil {
		t.Fatal(err)
	}
	defer x.Conn.Close()
	for range n {
		if _, err := x.SendTrap(gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(500)},
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
		}}); err != nil {
			t.Fatal(err)
		}
	}
}

// netflowV5 es un datagrama NetFlow v5 con un registro (formato de la documentación de Cisco; sin validar en laboratorio).
func netflowV5() []byte {
	var b bytes.Buffer
	w := func(v any) { binary.Write(&b, binary.BigEndian, v) }
	w(uint16(5))
	w(uint16(1))
	w([4]uint32{1000, 1_700_000_000, 0, 1})
	w(uint32(0)) // motor y muestreo
	b.Write([]byte{10, 0, 0, 1, 10, 0, 0, 2, 0, 0, 0, 0})
	w([2]uint16{1, 2})
	w([4]uint32{10, 1500, 0, 0})
	w([2]uint16{51000, 443})
	b.Write([]byte{0, 0x18, 6, 0})
	w([2]uint16{0, 0})
	b.Write([]byte{24, 24, 0, 0})
	return b.Bytes()
}

func files(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		out[e.Name()] = string(b)
	}
	return out
}

func TestTrapsAndFlowsRejectOutOfRange(t *testing.T) {
	d := servicetest.New(t)
	s := &visibilitySvc{d: d}
	for name, o := range map[string]struct {
		rate, queue, mb, mins, max int32
		tpl, format                string
	}{
		"tasa": {rate: 10001}, "cola": {queue: 63}, "mb": {mb: 1025}, "minutos": {mins: 10081}, "archivos": {max: 1001},
		"plantilla": {tpl: "../x"}, "sin fecha": {tpl: "solo"}, "formato": {format: "xml"},
	} {
		tr := newTrapStream(false)
		err := s.SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, RatePerSource: o.rate, QueueSize: o.queue, RotateMb: o.mb, RotateMinutes: o.mins, MaxFiles: o.max, NameTemplate: o.tpl, Format: o.format}, tr)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("traps %s: err = %v", name, err)
		}
		fl := newFlowStream(false)
		err = s.Flows(&v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, RatePerSource: o.rate, QueueSize: o.queue, RotateMb: o.mb, RotateMinutes: o.mins, MaxFiles: o.max, NameTemplate: o.tpl, Format: o.format}, fl)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("flows %s: err = %v", name, err)
		}
	}
	if es, _ := os.ReadDir(d.Outputs()); len(es) != 0 {
		t.Fatalf("una petición rechazada no debía crear carpetas: %v", es)
	}
}

// Traps: la carpeta es output_path, se avisa cada archivo nuevo, se audita la config, cada borrado por retención
// y el resumen con los descartes; la retención no toca archivos ajenos.
func TestSnmpTrapsAuditsConfigRetentionAndDrops(t *testing.T) {
	d := servicetest.New(t)
	dir := filepath.Join(d.Outputs(), "snmp-traps")
	os.MkdirAll(dir, 0o700)
	old := time.Now().Add(-time.Hour)
	for _, n := range []string{"traps_20260101_000000.log", "traps_20260102_000000.log", "traps_20260103_000000.log", "notas.log"} {
		os.WriteFile(filepath.Join(dir, n), []byte("viejo"), 0o600)
		os.Chtimes(filepath.Join(dir, n), old, old)
	}
	st := newTrapStream(false)
	done := make(chan error, 1)
	go func() {
		done <- (&visibilitySvc{d: d}).SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 2, Save: true, Format: "crudo", MaxFiles: 2, RatePerSource: 1, BurstPerSource: 1}, st)
	}()
	first := <-st.stream.first
	if first.OutputPath != dir {
		t.Fatalf("output_path = %q, quería la carpeta %q", first.OutputPath, dir)
	}
	sendTraps(t, first.Listening, 20)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var rotated, drops int
	var lastDrops *v1.SyslogDrops
	for _, m := range st.stream.got {
		if m.RotatedPath != "" {
			rotated++
		}
		if m.Drops != nil {
			drops++
			lastDrops = m.Drops
		}
	}
	if rotated != 1 || lastDrops == nil || lastDrops.PorOrigen < 15 || lastDrops.Top[0].Source != "127.0.0.1" {
		t.Fatalf("archivos nuevos=%d drops=%+v", rotated, lastDrops)
	}
	fs := files(t, dir)
	if len(fs) != 3 || fs["notas.log"] != "viejo" {
		t.Fatalf("archivos = %v", fs)
	}
	a := d.AuditText()
	for _, want := range []string{`"action":"visibility.traps"`, "rate_per_origin=1 burst_per_origin=1", "max_files=2 format=crudo", "output=" + dir,
		`"action":"visibility.traps.retencion"`, "traps_20260101_000000.log", "traps_20260102_000000.log", `"action":"visibility.traps.done"`, "per_origin="} {
		if !strings.Contains(a, want) {
			t.Errorf("la auditoría no trae %q:\n%s", want, a)
		}
	}
	if strings.Contains(a, "notas.log") || strings.Contains(a, "traps_20260103") {
		t.Errorf("se auditó un borrado que no debía ocurrir:\n%s", a)
	}
}

func TestFlowsAuditsConfigRetentionAndDrops(t *testing.T) {
	d := servicetest.New(t)
	dir := filepath.Join(d.Outputs(), "flows")
	os.MkdirAll(dir, 0o700)
	old := time.Now().Add(-time.Hour)
	for _, n := range []string{"flujos_20260101_000000.jsonl", "flujos_20260102_000000.jsonl", "otro.jsonl"} {
		os.WriteFile(filepath.Join(dir, n), []byte("viejo"), 0o600)
		os.Chtimes(filepath.Join(dir, n), old, old)
	}
	st := newFlowStream(false)
	done := make(chan error, 1)
	go func() {
		done <- (&visibilitySvc{d: d}).Flows(&v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 2, Save: true, Format: "jsonl", MaxFiles: 1, RatePerSource: 1, BurstPerSource: 1}, st)
	}()
	first := <-st.stream.first
	if first.OutputPath != dir {
		t.Fatalf("output_path = %q, quería la carpeta %q", first.OutputPath, dir)
	}
	_ = syslogdtest.SendUDP(first.Listening, string(netflowV5()), 20)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var rotated int
	var lastDrops *v1.SyslogDrops
	var final bool
	for _, m := range st.stream.got {
		if m.RotatedPath != "" {
			rotated++
		}
		if m.Drops != nil {
			lastDrops = m.Drops
		}
		final = final || m.Final
	}
	if rotated != 1 || !final || lastDrops == nil || lastDrops.PorOrigen < 15 {
		t.Fatalf("archivos nuevos=%d final=%v drops=%+v", rotated, final, lastDrops)
	}
	fs := files(t, dir)
	if len(fs) != 2 || fs["otro.jsonl"] != "viejo" {
		t.Fatalf("archivos = %v", fs)
	}
	a := d.AuditText()
	for _, want := range []string{`"action":"visibility.flows"`, "max_files=1 format=jsonl", `"action":"visibility.flows.retencion"`,
		"flujos_20260101_000000.jsonl", "flujos_20260102_000000.jsonl", `"action":"visibility.flows.done"`, "per_origin="} {
		if !strings.Contains(a, want) {
			t.Errorf("la auditoría no trae %q:\n%s", want, a)
		}
	}
}

// Un cliente atascado no cuelga el cierre y el archivo guarda todo (como en syslog).
func TestSnmpTrapsStuckClientDoesNotHangCloseAndFileKeepsEverything(t *testing.T) {
	oldGrace, oldQ := closeGrace, outQueue
	closeGrace, outQueue = 200*time.Millisecond, 8
	t.Cleanup(func() { closeGrace, outQueue = oldGrace, oldQ })
	d := servicetest.New(t)
	st := newTrapStream(true)
	t.Cleanup(func() { close(st.stream.stuck) })
	done := make(chan error, 1)
	go func() {
		done <- (&visibilitySvc{d: d}).SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, Format: "crudo"}, st)
	}()
	sendTraps(t, (<-st.stream.first).Listening, 50)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el RPC no terminó con el cliente atascado")
	}
	var all string
	for _, c := range files(t, filepath.Join(d.Outputs(), "snmp-traps")) {
		all += c
	}
	n := 0
	for _, l := range strings.Split(all, "\n") {
		if strings.HasPrefix(l, "v2c linkDown ") {
			n++
		}
	}
	if got := n; got != 50 {
		t.Fatalf("el archivo trae %d de 50 traps:\n%s", got, all)
	}
	if a := d.AuditText(); !strings.Contains(a, "lost_on_interface=") || strings.Contains(a, "lost_on_interface=0") {
		t.Fatalf("lo que no cupo hacia el cliente debía auditarse:\n%s", a)
	}
}

func TestFlowsStuckClientDoesNotHangCloseAndFileKeepsEverything(t *testing.T) {
	oldGrace, oldQ := closeGrace, outQueue
	closeGrace, outQueue = 200*time.Millisecond, 8
	t.Cleanup(func() { closeGrace, outQueue = oldGrace, oldQ })
	d := servicetest.New(t)
	st := newFlowStream(true)
	t.Cleanup(func() { close(st.stream.stuck) })
	done := make(chan error, 1)
	go func() {
		done <- (&visibilitySvc{d: d}).Flows(&v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, Format: "crudo", EverySeconds: 1}, st)
	}()
	_ = syslogdtest.SendUDP((<-st.stream.first).Listening, string(netflowV5()), 50)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el RPC no terminó con el cliente atascado")
	}
	var all string
	for _, c := range files(t, filepath.Join(d.Outputs(), "flows")) {
		all += c
	}
	if got := strings.Count(all, "tcp 10.0.0.1:51000 -> 10.0.0.2:443 bytes=1500 packets=10 exp=127.0.0.1\n"); got != 50 {
		t.Fatalf("el archivo trae %d de 50 flujos:\n%s", got, all)
	}
	if a := d.AuditText(); !strings.Contains(a, "lost_on_interface=") {
		t.Fatalf("falta el conteo de lo perdido hacia el cliente:\n%s", a)
	}
}

// Una carpeta de salida que no se puede crear es un fallo interno, no una petición inválida; una dirección mala sí lo es.
func TestTrapsAndFlowsOutputDirFailureIsInternal(t *testing.T) {
	d := servicetest.New(t)
	os.MkdirAll(d.Outputs(), 0o700)
	for _, kind := range []string{"snmp-traps", "flows"} {
		os.WriteFile(filepath.Join(d.Outputs(), kind), []byte("soy un archivo"), 0o600) // MkdirAll no puede crear la carpeta
	}
	s := &visibilitySvc{d: d}
	if err := s.SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true}, newTrapStream(false)); status.Code(err) != codes.Internal {
		t.Errorf("traps: err = %v", err)
	}
	if err := s.Flows(&v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true}, newFlowStream(false)); status.Code(err) != codes.Internal {
		t.Errorf("flows: err = %v", err)
	}
	if err := s.SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:162", DurationSeconds: 1}, newTrapStream(false)); status.Code(err) != codes.InvalidArgument {
		t.Errorf("traps con puerto privilegiado: err = %v", err)
	}
	if err := s.Flows(&v1.FlowsRequest{Addr: "127.0.0.1:162", DurationSeconds: 1}, newFlowStream(false)); status.Code(err) != codes.InvalidArgument {
		t.Errorf("flows con puerto privilegiado: err = %v", err)
	}
}

// Con save los defaults de flujos son 1000 datagramas/s por exportador y 5000 global; sin save no hay tope.
func TestFlowsRateDefaultsAndNoLimitWithoutSave(t *testing.T) {
	d := servicetest.New(t)
	run := func(save bool) string {
		st := newFlowStream(false)
		done := make(chan error, 1)
		go func() {
			done <- (&visibilitySvc{d: d}).Flows(&v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: save}, st)
		}()
		_ = syslogdtest.SendUDP((<-st.stream.first).Listening, string(netflowV5()), 1)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return d.AuditText()
	}
	a := run(true)
	if !strings.Contains(a, "rate_per_origin=1000 burst_per_origin=2000 rate_global=5000 burst_global=10000") {
		t.Errorf("defaults de flujos:\n%s", a)
	}
	if a = run(false); !strings.Contains(a, "sin tope de tasa (sin archivo)") {
		t.Errorf("sin save:\n%s", a)
	}
}

// Un trap v3 que no se decodifica no deja el paquete (con el usuario USM y la autenticación) en eventos, archivo ni auditoría.
func TestSnmpTrapsV3UndecodedLeavesNoPacketAnywhere(t *testing.T) {
	const user = "usuario-usm-secreto"
	d := servicetest.New(t)
	st := newTrapStream(false)
	done := make(chan error, 1)
	go func() {
		done <- (&visibilitySvc{d: d}).SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, Format: "jsonl"}, st)
	}()
	first := <-st.stream.first
	h, p := first.Listening[:strings.LastIndex(first.Listening, ":")], first.Listening[strings.LastIndex(first.Listening, ":")+1:]
	port, _ := strconv.Atoi(p)
	x := &gosnmp.GoSNMP{Target: h, Port: uint16(port), Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, Timeout: time.Second,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: user, AuthoritativeEngineID: "\x80\x00\x00\x09\x03\x00\x11\x22\x33\x44\x55", AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 50,
			AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "otra-clave-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "otra-clave-2"}}
	if err := x.Connect(); err != nil {
		t.Fatal(err)
	}
	x.SendTrap(gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(500)}}})
	x.Conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var all string
	for _, m := range st.stream.got {
		all += m.Json
	}
	for _, c := range files(t, filepath.Join(d.Outputs(), "snmp-traps")) {
		all += c
	}
	all += d.AuditText()
	if strings.Contains(all, user) || strings.Contains(all, "7573756172696f2d75736d") || !strings.Contains(all, "v3 sin decodificar (") || strings.Contains(all, `"Raw"`) {
		t.Fatalf("se filtró el paquete v3 o falta el aviso:\n%s", all)
	}
}

// Traps y flujos sin opciones de archivo usan los defaults de las preferencias del núcleo; lo explícito manda.
func TestTrapsYFlowsUsanPreferenciasDelNucleo(t *testing.T) {
	d := servicetest.New(t)
	d.S.Apply("", service.IngestDefaults{RotateMB: 7, MaxFiles: 9, Format: "jsonl"})
	corre := func(tr bool, maxFiles int32) {
		done := make(chan error, 1)
		if tr {
			st := newTrapStream(false)
			go func() {
				done <- (&visibilitySvc{d: d}).SnmpTraps(&v1.SnmpTrapsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, MaxFiles: maxFiles}, st)
			}()
			<-st.stream.first
		} else {
			st := newFlowStream(false)
			go func() {
				done <- (&visibilitySvc{d: d}).Flows(&v1.FlowsRequest{Addr: "127.0.0.1:0", DurationSeconds: 1, Save: true, MaxFiles: maxFiles}, st)
			}()
			<-st.stream.first
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	corre(true, 0)
	corre(false, 0)
	corre(true, 3)
	a := d.AuditText()
	for _, want := range []string{`"action":"visibility.traps"`, `"action":"visibility.flows"`} {
		if strings.Count(a, want) < 1 {
			t.Fatalf("falta %s:\n%s", want, a)
		}
	}
	if n := strings.Count(a, "rotate_mb=7 "); n != 3 {
		t.Fatalf("rotate_mb=7 debía estar en las 3 escuchas, está en %d:\n%s", n, a)
	}
	if n := strings.Count(a, "max_files=9 format=jsonl"); n != 2 {
		t.Fatalf("las 2 escuchas sin opciones usan las preferencias, salieron %d:\n%s", n, a)
	}
	if !strings.Contains(a, "max_files=3 format=jsonl") {
		t.Fatalf("lo explícito (max_files=3) debía ganar:\n%s", a)
	}
}
