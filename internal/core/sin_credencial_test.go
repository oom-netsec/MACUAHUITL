package core

import (
	"io"
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
	h.ready(t)
	conns := new(atomic.Int32)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-01", Username: "admin", Password: "MARKER-PW", Conns: conns, Transcripts: transcripts()})
	ap := netip.MustParseAddrPort(addr)
	tg := &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw1"}
	spec := h.spec("")
	spec.Targets = []*v1.Target{tg}
	// drena lee hasta el final de un stream: el rechazo puede llegar en el primer Recv y ningún mensaje cuenta como éxito.
	drena := func(recv func() error) error {
		for {
			if err := recv(); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
	casos := []struct {
		n  string
		do func() error
	}{
		{"CreateJob", func() error {
			_, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: spec})
			return err
		}},
		{"LoginTest", func() error {
			s, err := h.patrol.LoginTest(ctx(t), &v1.LoginTestRequest{JobId: "job-que-no-existe"})
			if err != nil {
				return err
			}
			return drena(func() error { _, err := s.Recv(); return err })
		}},
		{"StartBackup", func() error {
			_, err := v1.NewBackupServiceClient(h.conn).StartBackup(ctx(t), &v1.StartBackupRequest{Targets: []*v1.Target{tg}})
			return err
		}},
		{"StartAdhoc", func() error {
			_, err := v1.NewAdhocServiceClient(h.conn).StartAdhoc(ctx(t), &v1.StartAdhocRequest{Targets: []*v1.Target{tg}, Commands: "show version"})
			return err
		}},
		{"CreateChange", func() error {
			_, err := v1.NewChangeServiceClient(h.conn).CreateChange(ctx(t), &v1.CreateChangeRequest{Spec: spec})
			return err
		}},
		{"assist PlanPorts", func() error {
			_, err := v1.NewAssistServiceClient(h.conn).PlanPorts(ctx(t), &v1.PlanPortsRequest{
				Target: &v1.AssistTarget{Address: tg.Address, Port: tg.Port}, Interfaces: []string{"GigabitEthernet1/0/1"}, Vlan: 10})
			return err
		}},
		{"assist StartRun", func() error {
			_, err := v1.NewAssistServiceClient(h.conn).StartRun(ctx(t), &v1.StartRunRequest{PlanId: "plan-que-no-existe", Assisted: true})
			return err
		}},
		{"transfer Get scp", func() error {
			_, err := v1.NewTransferServiceClient(h.conn).Get(ctx(t), &v1.GetRequest{Url: "scp://" + addr + "/flash/x.bin", DestDir: t.TempDir()})
			return err
		}},
		{"métricas de puertos", func() error {
			_, err := v1.NewMetricsServiceClient(h.conn).GetPortStatus(ctx(t), &v1.GetPortStatusRequest{Device: tg.Address, Port: tg.Port})
			return err
		}},
	}
	for _, c := range casos {
		t.Run(c.n, func(t *testing.T) {
			err := c.do()
			switch status.Code(err) {
			case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound:
			default:
				t.Fatalf("debía rechazar con un error del catálogo: %v", err)
			}
			if n := conns.Load(); n != 0 {
				t.Fatalf("marcó al equipo %d veces", n)
			}
		})
	}
}
