package main

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"

	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const gi1 = "GigabitEthernet1/0/1"

// portsRig levanta el núcleo, una credencial y un equipo simulado con un puerto de acceso.
func portsRig(t *testing.T, errs map[string]string) (args []string, rec *simulator.Recorder) {
	t.Helper()
	r := portsRigFull(t, errs)
	return r.args, r.rec
}

type portsEnv struct {
	args           []string
	rec            *simulator.Recorder
	addr, cred, fp string
}

func portsRigFull(t *testing.T, errs map[string]string, mods ...func(*simulator.Config)) portsEnv {
	t.Helper()
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "pw-lab\nen-lab\n", "cred", "add", "--label", "lab", "--user", "admin"))
	_, f, _, _ := runtime.Caller(0)
	rec := &simulator.Recorder{}
	cfg := simulator.Config{Hostname: "SW1", Username: "admin", Password: "pw-lab", Enable: "en-lab",
		Transcripts:  filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", "ios-xe"),
		Interfaces:   map[string][]string{gi1: {"description Impresora", "switchport access vlan 10", "switchport mode access"}},
		Vlans:        []int{1, 10, 20},
		ConfigErrors: errs, Recorder: rec}
	for _, m := range mods {
		m(&cfg)
	}
	addr, hk := simulator.Start(t, cfg)
	fp := transport.Fingerprint(hk)
	return portsEnv{args: []string{"ports", "set", addr, gi1, "--cred", cred, "--accept", fp}, rec: rec, addr: addr, cred: cred, fp: fp}
}

func TestPortsSetWithoutAsistidoOnlyPrintsPlan(t *testing.T) {
	args, rec := portsRig(t, nil)
	out := must(t, "", append(args, "--vlan", "20", "--desc", "Telefono")...)
	for _, w := range []string{"REVERSA", "switchport access vlan 20", "switchport access vlan 10", "description Impresora", "no se cambió nada"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if len(rec.Lines()) != 0 {
		t.Fatalf("sin --asistido llegó configuración al equipo: %q", rec.Lines())
	}
	if _, err := mctl(t, "", append(args, "--vlan", "20", "--shut", "--no-shut")...); err == nil {
		t.Fatal("--shut y --no-shut juntos")
	}
}

func TestPortsSetAsistidoAsksPerStep(t *testing.T) {
	args, rec := portsRig(t, nil)
	// Respuesta vacía o "n": aborta y no se aplica nada.
	for _, in := range []string{"", "n\n", "quizá\n"} {
		if out, err := mctl(t, in, append(args, "--vlan", "20", "--asistido")...); err == nil || len(rec.Lines()) != 0 {
			t.Fatalf("stdin %q: err=%v lines=%q\n%s", in, err, rec.Lines(), out)
		}
	}
	out := must(t, "s\ns\n", append(args, "--vlan", "20", "--asistido")...)
	if !strings.Contains(out, "MODO ASISTIDO ACTIVO") || !strings.Contains(out, "se enviarán estas líneas") || !strings.Contains(out, "Listo") || !strings.Contains(out, "Terminar sin guardar [close]") {
		t.Fatalf("salida:\n%s", out)
	}
	if got := strings.Join(rec.Lines(), "|"); got != "interface "+gi1+"|switchport access vlan 20|end" {
		t.Fatalf("el equipo recibió %q", got)
	}
}

// En el cierre sin write memory, una respuesta vacía o rara se vuelve a preguntar (no aborta) y «r» revierte.
func TestPortsSetCloseAsksAgainAndRollsBack(t *testing.T) {
	args, rec := portsRig(t, nil)
	out, err := mctl(t, "s\n\nquizá\nr\ns\n", append(args, "--vlan", "20", "--asistido")...)
	if strings.Count(out, "¿Dejas el cambio solo en ejecución?") != 3 || !strings.Contains(out, "REVERSA") {
		t.Fatalf("err=%v salida:\n%s", err, out)
	}
	if got := strings.Join(rec.Lines(), "|"); !strings.HasPrefix(got, "interface "+gi1+"|switchport access vlan 20|end|interface "+gi1) {
		t.Fatalf("el equipo recibió %q", got)
	}
}

// Segunda revisión C: Ctrl-C mientras corre un apply que luego falla no deja la ejecución viva hasta el tope.
func TestPortsSetCtrlCDuringFailingApplyAborts(t *testing.T) {
	const bad = "switchport access vlan 20"
	r := portsRigFull(t, map[string]string{bad: "% Invalid input detected at '^' marker."}, func(c *simulator.Config) {
		c.SlowConfigLine, c.SlowDelay = bad, 700*time.Millisecond
	})
	sigs := fakeInterrupt(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	out, done := mctlAsync(pr, append(r.args, "--vlan", "20", "--asistido")...)
	waitOut(t, out, "¿Confirmas?", 1)
	io.WriteString(pw, "s\n")
	for end := time.Now().Add(5 * time.Second); !strings.Contains(strings.Join(r.rec.Lines(), "|"), bad) && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	sigs <- os.Interrupt // el apply sigue en curso: el equipo tarda en contestar y luego rechaza la línea
	if err := waitErr(t, done); err == nil {
		t.Fatal("Ctrl-C debe terminar con error")
	}
	if o := out.String(); !strings.Contains(o, "[aborted]") || !strings.Contains(o, "quedó cambiado") {
		t.Fatalf("salida:\n%s", o)
	}
	if l := must(t, "", "ports", "runs", "--activas"); !strings.Contains(l, "No hay ejecuciones") {
		t.Fatalf("la ejecución quedó viva:\n%s", l)
	}
}

// Un segundo Ctrl-C sale del proceso sin esperar al núcleo.
func TestPortsSetSecondCtrlCExits(t *testing.T) {
	args, _ := portsRig(t, nil)
	sigs := fakeInterrupt(t)
	code := make(chan int, 1)
	old := cli.Exit
	cli.Exit = func(c int) { code <- c }
	t.Cleanup(func() { cli.Exit = old })
	pr, pw := io.Pipe()
	defer pw.Close()
	out, done := mctlAsync(pr, append(args, "--vlan", "20", "--asistido")...)
	waitOut(t, out, "¿Confirmas?", 1)
	sigs <- os.Interrupt
	sigs <- os.Interrupt
	select {
	case c := <-code:
		if c != 130 {
			t.Fatalf("código de salida %d", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el segundo Ctrl-C no salió del proceso")
	}
	waitErr(t, done)
}

func TestPortsSetFailureOffersRollback(t *testing.T) {
	args, rec := portsRig(t, map[string]string{"description Telefono": "% Invalid input detected at '^' marker."})
	out, err := mctl(t, "s\ns\ns\n", append(args, "--vlan", "20", "--desc", "Telefono", "--asistido")...)
	if err == nil || !strings.Contains(out, "SE DETUVO") || !strings.Contains(out, "Aplicar la REVERSA") || !strings.Contains(out, "[rolled-back]") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	if !strings.Contains(strings.Join(rec.Lines(), "|"), "switchport access vlan 10") {
		t.Fatalf("no se aplicó la reversa: %q", rec.Lines())
	}
}

// mctlAsync corre mctl con una entrada que la prueba controla (una tubería) y devuelve su salida y su resultado.
func mctlAsync(stdin io.Reader, args ...string) (*syncBuf, <-chan error) {
	out, done := &syncBuf{}, make(chan error, 1)
	go func() { done <- run(args, stdin, out) }()
	return out, done
}

func waitOut(t *testing.T, out *syncBuf, want string, n int) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if strings.Count(out.String(), want) >= n {
			return
		}
	}
	t.Fatalf("no apareció %q x%d:\n%s", want, n, out.String())
}

func waitErr(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("mctl no terminó")
		return nil
	}
}

func fakeInterrupt(t *testing.T) chan os.Signal {
	sigs := make(chan os.Signal, 1)
	old := cli.Interrupts
	cli.Interrupts = func() (<-chan os.Signal, func()) { return sigs, func() {} }
	t.Cleanup(func() { cli.Interrupts = old })
	return sigs
}

// Hallazgo 6: Ctrl-C en la confirmación aborta la ejecución (no la deja colgada) y no aplica nada.
func TestPortsSetCtrlCAbortsRun(t *testing.T) {
	args, rec := portsRig(t, nil)
	sigs := fakeInterrupt(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	out, done := mctlAsync(pr, append(args, "--vlan", "20", "--asistido")...)
	waitOut(t, out, "¿Confirmas?", 1)
	sigs <- os.Interrupt
	if err := waitErr(t, done); err == nil {
		t.Fatal("Ctrl-C debe terminar con error")
	}
	if o := out.String(); !strings.Contains(o, "Ctrl-C") || !strings.Contains(o, "[aborted]") || strings.Contains(o, "quedó cambiado") {
		t.Fatalf("salida:\n%s", o)
	}
	if len(rec.Lines()) != 0 {
		t.Fatalf("Ctrl-C aplicó algo: %q", rec.Lines())
	}
	if l := must(t, "", "ports", "runs", "--activas"); !strings.Contains(l, "No hay ejecuciones") {
		t.Fatalf("la ejecución quedó colgada:\n%s", l)
	}
}

// Hallazgo 8: abortar con un equipo ya cambiado lo dice, en la CLI.
func TestPortsSetCtrlCAfterApplyWarnsChangedDevice(t *testing.T) {
	args, rec := portsRig(t, nil)
	sigs := fakeInterrupt(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	out, done := mctlAsync(pr, append(args, "--vlan", "20", "--write-memory", "--asistido")...)
	waitOut(t, out, "¿Confirmas?", 1)
	io.WriteString(pw, "s\n")
	waitOut(t, out, "¿Confirmas?", 2) // ahora espera save-1, con el equipo ya cambiado
	if o := out.String(); !strings.Contains(o, "r = revertir") {
		t.Fatalf("con un equipo cambiado debe ofrecer la reversa:\n%s", o)
	}
	sigs <- os.Interrupt
	waitErr(t, done)
	o := out.String()
	if !strings.Contains(o, "ATENCIÓN") || !strings.Contains(o, "quedó cambiado") {
		t.Fatalf("no avisó del equipo cambiado:\n%s", o)
	}
	if got := strings.Join(rec.Lines(), "|"); strings.Contains(got, "!write memory") || !strings.Contains(got, "switchport access vlan 20") {
		t.Fatalf("el equipo recibió %q", got)
	}
}

// Sin equipos cambiados la primera pregunta no ofrece revertir.
func TestPortsSetFirstPromptDoesNotOfferRollbackWithoutChanges(t *testing.T) {
	args, _ := portsRig(t, nil)
	out, _ := mctl(t, "n\n", append(args, "--vlan", "20", "--asistido")...)
	if strings.Contains(out, "r = revertir") {
		t.Fatalf("ofreció revertir sin equipos cambiados:\n%s", out)
	}
}

func TestPortsSetRejectsVlanOutOfRange(t *testing.T) {
	args, rec := portsRig(t, nil)
	for _, v := range []string{"-1", "4095", "99999999999"} {
		if _, err := mctl(t, "", append(args, "--vlan", v)...); err == nil {
			t.Errorf("--vlan %s aceptada", v)
		}
	}
	if _, err := mctl(t, "", append(args, "--voice", "-1")...); err == nil {
		t.Error("--voice -1 aceptada")
	}
	if len(rec.Lines()) != 0 {
		t.Fatalf("llegó %q", rec.Lines())
	}
}

// Hallazgo 6: una ejecución viva que nadie vigila se lista y se retoma desde otra mctl.
func TestPortsRunsListsAndResumeTakesOverLiveRun(t *testing.T) {
	r := portsRigFull(t, nil)
	conn, err := ipc.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := v1.NewAssistServiceClient(conn)
	ap := netip.MustParseAddrPort(r.addr)
	plan, err := cl.PlanPorts(context.Background(), &v1.PlanPortsRequest{
		Target:     &v1.AssistTarget{Name: "SW1", Address: ap.Addr().String(), Port: uint32(ap.Port()), CredentialId: r.cred},
		Interfaces: []string{gi1}, Vlan: 20, WriteMemory: true, AcceptedHostKeyFingerprints: []string{r.fp}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := cl.StartRun(context.Background(), &v1.StartRunRequest{PlanId: plan.PlanId, Assisted: true})
	if err != nil {
		t.Fatal(err)
	}
	var cur *v1.AssistRunState
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		g, _ := cl.GetAssistRun(context.Background(), &v1.GetAssistRunRequest{RunId: st.RunId})
		if cur = g.GetRun(); cur.GetPending() != nil {
			break
		}
	}
	list := must(t, "", "ports", "runs", "--activas")
	if !strings.Contains(list, st.RunId) || !strings.Contains(list, "waiting-confirm") || !strings.Contains(list, "(viva)") {
		t.Fatalf("runs:\n%s", list)
	}
	out := must(t, "s\ns\n", "ports", "resume", st.RunId)
	for _, w := range []string{"Retomando", "apply-1", "save-1", "[done]", "Listo"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if got := strings.Join(r.rec.Lines(), "|"); got != "interface "+gi1+"|switchport access vlan 20|end|!write memory" {
		t.Fatalf("el equipo recibió %q", got)
	}
	if _, err := mctl(t, "", "ports", "resume", st.RunId); err == nil || !strings.Contains(err.Error(), "ya terminó") {
		t.Fatalf("retomar una terminada: %v", err)
	}
	if l := must(t, "", "ports", "runs", "--activas"); !strings.Contains(l, "No hay ejecuciones") {
		t.Fatalf("runs:\n%s", l)
	}
	if l := must(t, "", "ports", "runs"); !strings.Contains(l, st.RunId) || !strings.Contains(l, "done") {
		t.Fatalf("runs:\n%s", l)
	}
}
