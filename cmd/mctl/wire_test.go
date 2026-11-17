package main

import (
	"context"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// fakeCore es un núcleo anterior: solo entiende los valores de cable históricos y registra lo que le llega.
type fakeCore struct {
	v1.UnimplementedInventoryServiceServer
	v1.UnimplementedVisibilityServiceServer
	decisions []*v1.ImportHostDecision
	profiles  []string
}

func (f *fakeCore) PreviewImportHosts(context.Context, *v1.PreviewImportHostsRequest) (*v1.PreviewImportHostsResponse, error) {
	return &v1.PreviewImportHostsResponse{Token: "t", Items: []*v1.ImportHostItem{{Host: &v1.Device{}, Key: "10.0.0.1:22", State: "conflicto"}}}, nil
}

func (f *fakeCore) ApplyImportHosts(_ context.Context, r *v1.ApplyImportHostsRequest) (*v1.ApplyImportHostsResponse, error) {
	f.decisions = r.Decisions
	return &v1.ApplyImportHostsResponse{}, nil
}

func (f *fakeCore) SnmpPoll(r *v1.SnmpPollRequest, _ v1.VisibilityService_SnmpPollServer) error {
	f.profiles = r.Profiles
	return nil
}

func startFake(t *testing.T) *fakeCore {
	t.Helper()
	rt, _ := os.MkdirTemp("", "mctl")
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)
	ipctest.Isolate(t)
	sock, _ := ipc.SocketPath()
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCore{}
	s := ipc.NewServer() // mismo servidor que el núcleo; mctl no importa grpc (noegress)
	v1.RegisterInventoryServiceServer(s, f)
	v1.RegisterVisibilityServiceServer(s, f)
	go s.Serve(l)
	t.Cleanup(s.Stop)
	return f
}

// El cable lleva el valor histórico en español: un mctl nuevo con un núcleo anterior no puede mandar «rename».
func TestDecisionViajaEnEspanolPorElCable(t *testing.T) {
	csv := filepath.Join(t.TempDir(), "h.csv")
	os.WriteFile(csv, []byte("name,address,port\nuno,10.0.0.1,22\n"), 0o600)
	for _, args := range [][]string{{"--decision", "10.0.0.1:22=rename"}, {"--decision", "10.0.0.1:22=renombrar"}, {"--all=rename"}} {
		f := startFake(t)
		mustRaw(t, "", append([]string{"hosts", "import", csv}, args...)...)
		if len(f.decisions) != 1 || f.decisions[0].Action != "renombrar" {
			t.Fatalf("%v: decisiones %v", args, f.decisions)
		}
	}
}

func TestPerfilSNMPViajaEnEspanolPorElCable(t *testing.T) {
	f := startFake(t)
	mustRaw(t, "", "snmp", "poll", "127.0.0.1", "--cred", "x", "--count", "1", "--profile", "system", "--profile", "memory", "--profile", "cpu")
	if !slices.Equal(f.profiles, []string{"sistema", "memoria", "cpu"}) {
		t.Fatalf("perfiles = %v", f.profiles)
	}
}
