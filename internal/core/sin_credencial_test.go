package core

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// TestSinCredencialSoloTerminal: con credential_id vacío (el modo tecleado) solo la terminal puede marcar al equipo.
// Todo RPC que usa una credencial guardada debe rechazarlo con un error del catálogo y sin abrir una sola conexión.
func TestSinCredencialSoloTerminal(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	conns := new(atomic.Int32)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-01", Username: "admin", Password: "MARKER-PW", Conns: conns, Transcripts: transcripts()})
	ap := netip.MustParseAddrPort(addr)
	tg := &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw1"}
	spec := h.spec("")
	spec.Targets = []*v1.Target{tg}
	at := &v1.AssistTarget{Address: tg.Address, Port: tg.Port}
	// Cada caso exige su motivo: un rechazo por otra validación (trabajo o plan inexistente, carpeta) no prueba nada.
	// LoginTest no va: un trabajo sin credencial no se puede crear (CreateJob lo cubre) y LoginTest solo recibe un job_id.
	casos := []struct {
		n, reason string
		do        func() error
	}{
		{"CreateJob", "patrol.field.no_credential", func() error {
			_, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: spec})
			return err
		}},
		{"StartBackup", "patrol.field.no_credential", func() error {
			_, err := v1.NewBackupServiceClient(h.conn).StartBackup(ctx(t), &v1.StartBackupRequest{Targets: []*v1.Target{tg}})
			return err
		}},
		{"StartAdhoc", "patrol.field.no_credential", func() error {
			_, err := v1.NewAdhocServiceClient(h.conn).StartAdhoc(ctx(t), &v1.StartAdhocRequest{Targets: []*v1.Target{tg}, Commands: "show version"})
			return err
		}},
		{"CreateChange", "patrol.field.no_credential", func() error {
			_, err := v1.NewChangeServiceClient(h.conn).CreateChange(ctx(t), &v1.CreateChangeRequest{Spec: spec})
			return err
		}},
		{"assist PlanPorts", "assist.svc.indica_el_equipo_direccion_y", func() error {
			_, err := v1.NewAssistServiceClient(h.conn).PlanPorts(ctx(t), &v1.PlanPortsRequest{
				Target: at, Interfaces: []string{"GigabitEthernet1/0/1"}, Vlan: 10})
			return err
		}},
		{"assist PlanSnippet", "assist.svc.indica_el_equipo_direccion_y", func() error {
			_, err := v1.NewAssistServiceClient(h.conn).PlanSnippet(ctx(t), &v1.PlanSnippetRequest{
				Target: at, Snippet: &v1.PlanSnippetRequest_Vlan{Vlan: &v1.VlanSnippet{Id: 20, Name: "LAB"}}})
			return err
		}},
		{"assist PlanCredRotate", "assist.svc.indica_el_equipo_direccion_y", func() error {
			_, err := v1.NewAssistServiceClient(h.conn).PlanCredRotate(ctx(t), &v1.PlanCredRotateRequest{Target: at, User: "tech"})
			return err
		}},
		{"assist PlanRestore", "assist.svc.indica_el_equipo_direccion_y", func() error {
			_, err := v1.NewAssistServiceClient(h.conn).PlanRestore(ctx(t), &v1.PlanRestoreRequest{Target: at, BackupId: "sw1/20261118T000000Z-running"})
			return err
		}},
		{"transfer Get scp", "transfer.svc.need_cred", func() error {
			_, err := v1.NewTransferServiceClient(h.conn).Get(ctx(t), &v1.GetRequest{Url: "scp://" + addr + "/flash/x.bin", DestDir: t.TempDir()})
			return err
		}},
		{"transfer Browse sftp", "transfer.svc.need_cred", func() error { // Put, GetMany y los streams comparten el mismo open()
			_, err := v1.NewTransferServiceClient(h.conn).Browse(ctx(t), &v1.BrowseRequest{Url: "sftp://" + addr + "/"})
			return err
		}},
		{"métricas de puertos", "metrics.svc.live_cred", func() error {
			_, err := v1.NewMetricsServiceClient(h.conn).GetPortStatus(ctx(t), &v1.GetPortStatusRequest{Device: tg.Address, Port: tg.Port})
			return err
		}},
	}
	for _, c := range casos {
		t.Run(c.n, func(t *testing.T) {
			antes := conns.Load()
			err := c.do()
			if r, _ := reasonOf(err); r != c.reason {
				t.Fatalf("motivo %q, se esperaba %q: %v", r, c.reason, err)
			}
			if n := conns.Load() - antes; n != 0 {
				t.Fatalf("marcó al equipo %d veces", n)
			}
		})
	}
	// Control: con la credencial guardada el mismo RPC sí marca, así que Conns cuenta de verdad.
	antes := conns.Load()
	if _, err := v1.NewMetricsServiceClient(h.conn).GetPortStatus(ctx(t), &v1.GetPortStatusRequest{Device: tg.Address, Port: tg.Port, CredentialId: cred}); err != nil && status.Code(err) == codes.InvalidArgument {
		t.Fatalf("el control no llegó a marcar: %v", err)
	}
	if conns.Load() == antes {
		t.Fatal("el control con credencial no marcó: Conns no cuenta")
	}
}
