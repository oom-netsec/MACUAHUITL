package metrics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// livePass es una contraseña reconocible: la bitácora no debe contenerla.
const livePass = "pw-secreta-0451"

func fixture(t *testing.T, name string) string {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(f), "..", "..", "parse", "iosxe", "testdata", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func portsJob(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	body := "===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\n" + fixture(t, "ios152_show-interfaces-status") +
		"===== ronda 1 · 2026-11-06T10:00:01Z · show interfaces trunk =====\n" + fixture(t, "ios152_show-interfaces-trunk") +
		"===== ronda 1 · 2026-11-06T10:00:02Z · show etherchannel summary =====\n" + fixture(t, "iosxe_show-etherchannel-summary")
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(body), 0o600)
	return dir
}

func TestGetPortStatusDeUnTrabajo(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: jobDeps{d, portsJob(t)}}
	r, err := s.GetPortStatus(context.Background(), &v1.GetPortStatusRequest{JobId: "trabajo1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "job" || r.Address != "10.0.0.1" || r.Hostname != "SW1" || len(r.Ports) != 9 || len(r.Channels) != 2 || r.AtMs == 0 || len(r.Warnings) != 0 {
		t.Fatalf("r = %v", r)
	}
	p := r.Ports[0]
	if p.Name != "Gi1/0/1" || p.Module != 1 || p.Stack != 0 || p.Number != 1 || !p.Trunk || p.Channel != "Po1" || p.SpeedMbps != 1000 || !p.AutoNegotiated || p.Type != "10/100/1000BaseTX" {
		t.Fatalf("Gi1/0/1 = %v", p)
	}
	if !strings.Contains(d.AuditText(), `"action":"metrics.ports"`) {
		t.Fatal("falta la auditoría")
	}
	if _, err := s.GetPortStatus(context.Background(), &v1.GetPortStatusRequest{JobId: "trabajo1", Device: "otro"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("equipo que no está: %v", err)
	}
}

type liveRig struct {
	svc  *svc
	d    *servicetest.Deps
	cred string
	addr string
	fp   string
	host string
	port uint32
}

func newLive(t *testing.T, cmds map[string]string) *liveRig {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	d := servicetest.New(t)
	v := d.CreateVault()
	pw, en := secret.New([]byte(livePass)), secret.New([]byte("en"))
	id, err := v.Put(vault.Credential{Label: "lab", Username: "admin", Password: pw, Enable: en})
	if err != nil {
		t.Fatal(err)
	}
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "SW1", Username: "admin", Password: livePass, Enable: "en",
		Transcripts: filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", "ios-xe"), Commands: cmds})
	h, p, _ := strings.Cut(addr, ":")
	var port uint32
	for _, c := range p {
		port = port*10 + uint32(c-'0')
	}
	return &liveRig{svc: &svc{d: d}, d: d, cred: id, addr: addr, fp: transport.Fingerprint(hk), host: h, port: port}
}

func TestGetPortStatusEnVivo(t *testing.T) {
	g := newLive(t, map[string]string{
		"show interfaces status":    fixture(t, "ios152_show-interfaces-status"),
		"show interfaces trunk":     fixture(t, "ios152_show-interfaces-trunk"),
		"show etherchannel summary": fixture(t, "iosxe_show-etherchannel-summary"),
	})
	req := &v1.GetPortStatusRequest{Device: g.host, Port: g.port, CredentialId: g.cred}
	// llave de host nueva: no entra hasta que el usuario acepta la huella
	if _, err := g.svc.GetPortStatus(context.Background(), req); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("llave nueva: %v", err)
	}
	req.AcceptedHostKeyFingerprints = []string{g.fp}
	r, err := g.svc.GetPortStatus(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != "live" || r.Hostname != "SW1" || len(r.Ports) != 9 || len(r.Channels) != 2 || len(r.Warnings) != 0 || r.AtMs == 0 {
		t.Fatalf("r = %v", r)
	}
	a := g.d.AuditText()
	for _, want := range []string{"metrics.ports.live.start", `"action":"metrics.ports.live"`, "guard=revocado", "hostkey.accepted"} {
		if !strings.Contains(a, want) {
			t.Errorf("falta %q en la auditoría", want)
		}
	}
	if strings.Contains(a, livePass) {
		t.Fatal("contraseña en la auditoría")
	}
	// el guard queda revocado: la ejecución de la consulta ya no puede marcar a ningún lado
	m := regexp.MustCompile(`run=(ports-\w+)`).FindStringSubmatch(a)
	if m == nil {
		t.Fatalf("la bitácora no dice la ejecución:\n%s", a)
	}
	if _, err := g.d.Guard().DialerFor(m[1])(context.Background(), "tcp", g.host, uint16(g.port)); !errors.Is(err, transport.ErrEgressDenied) {
		t.Fatalf("tras la consulta el guard sigue abierto: %v", err)
	}
}

func TestGetPortStatusEnVivoComandoFaltante(t *testing.T) {
	// el equipo no tiene etherchannel: el simulador contesta como IOS ante un comando que no entiende
	g := newLive(t, map[string]string{"show interfaces status": fixture(t, "ios152_show-interfaces-status")})
	r, err := g.svc.GetPortStatus(context.Background(), &v1.GetPortStatusRequest{Device: g.host, Port: g.port, CredentialId: g.cred, AcceptedHostKeyFingerprints: []string{g.fp}})
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(r.Warnings, "|")
	if len(r.Ports) != 9 || !strings.Contains(w, "show interfaces trunk") || !strings.Contains(w, "show etherchannel summary") {
		t.Fatalf("ports=%d avisos=%v", len(r.Ports), r.Warnings)
	}
}

func TestGetPortStatusEnVivoValidacion(t *testing.T) {
	g := newLive(t, nil)
	for name, req := range map[string]*v1.GetPortStatusRequest{
		"sin equipo":        {CredentialId: g.cred},
		"equipo con opción": {Device: "-oProxyCommand=x", CredentialId: g.cred},
		"equipo con ruta":   {Device: "10.0.0.1/24", CredentialId: g.cred},
		"sin credencial":    {Device: g.host},
		"puerto absurdo":    {Device: g.host, CredentialId: g.cred, Port: 70000},
	} {
		if _, err := g.svc.GetPortStatus(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := g.svc.GetPortStatus(context.Background(), &v1.GetPortStatusRequest{Device: g.host, Port: g.port, CredentialId: "no-existe"}); status.Code(err) != codes.NotFound {
		t.Errorf("credencial inexistente: %v", err)
	}
	bad, _ := g.d.V.Put(vault.Credential{Label: "mala", Username: "admin", Password: secret.New([]byte("no"))})
	if _, err := g.svc.GetPortStatus(context.Background(), &v1.GetPortStatusRequest{Device: g.host, Port: g.port, CredentialId: bad, AcceptedHostKeyFingerprints: []string{g.fp}}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("contraseña mala: %v", err)
	}
}

func TestGetPortStatusEnVivoConLaBovedaCerrada(t *testing.T) {
	g := newLive(t, nil)
	g.d.V.LockAll()
	if _, err := g.svc.GetPortStatus(context.Background(), &v1.GetPortStatusRequest{Device: g.host, Port: g.port, CredentialId: g.cred, AcceptedHostKeyFingerprints: []string{g.fp}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
}
