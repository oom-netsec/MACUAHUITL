package service

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestHostKeyAccepts(t *testing.T) {
	ctx := context.Background()
	one, two := []string{"10.0.0.1:22"}, []string{"10.0.0.1:22", "10.0.0.2:22"}
	m, err := HostKeyAccepts(ctx, one, []string{"SHA256:a"}, []*v1.AcceptedHostKey{{Host: "SW2.lab", Fingerprint: "SHA256:b"}})
	if err != nil || !m["10.0.0.1:22"]["SHA256:a"] || !m["sw2.lab:22"]["SHA256:b"] {
		t.Fatalf("m = %v, err = %v", m, err)
	}
	if m, err = HostKeyAccepts(ctx, two, nil, []*v1.AcceptedHostKey{{Host: "10.0.0.2", Fingerprint: "SHA256:b"}}); err != nil || !m["10.0.0.2:22"]["SHA256:b"] {
		t.Fatalf("campo nuevo con varios destinos: %v %v", m, err)
	}
	if _, err = HostKeyAccepts(ctx, two, []string{"SHA256:a"}, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("campo viejo con varios destinos: %v", err)
	}
	if _, err = HostKeyAccepts(ctx, one, nil, []*v1.AcceptedHostKey{{Host: "", Fingerprint: "x"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("host vacío: %v", err)
	}
}
