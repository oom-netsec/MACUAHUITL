//go:build !windows

package ipc

import (
	"context"
	"os"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

type peerVault struct {
	v1.UnimplementedVaultServiceServer
	got chan PeerInfo
}

func (p peerVault) Status(ctx context.Context, _ *v1.StatusRequest) (*v1.StatusResponse, error) {
	pi, _ := PeerFromContext(ctx)
	p.got <- pi
	return &v1.StatusResponse{}, nil
}

func TestPeerFromContextDaPIDyUID(t *testing.T) {
	l, err := Listen(sockPath(t))
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer()
	sv := peerVault{got: make(chan PeerInfo, 1)}
	v1.RegisterVaultServiceServer(s, sv)
	go s.Serve(l)
	t.Cleanup(s.Stop)
	if err := call(t, l.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if pi := <-sv.got; pi.PID != os.Getpid() || pi.UID != os.Getuid() {
		t.Fatalf("PeerInfo = %+v, quería pid %d uid %d", pi, os.Getpid(), os.Getuid())
	}
}
