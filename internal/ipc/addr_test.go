package ipc

import (
	"context"
	"net"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func serve(t *testing.T, l net.Listener) {
	s := NewServer()
	v1.RegisterVaultServiceServer(s, v1.UnimplementedVaultServiceServer{})
	go s.Serve(l)
	t.Cleanup(s.Stop)
}

func call(t *testing.T, path string) error {
	conn, err := DialPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = v1.NewVaultServiceClient(conn).Status(ctx, &v1.StatusRequest{})
	return err
}
