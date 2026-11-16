package ipc

import (
	"context"
	"slices"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

type blockEvents struct {
	v1.UnimplementedEventServiceServer
	in chan struct{}
}

func (b blockEvents) Subscribe(_ *v1.SubscribeRequest, s v1.EventService_SubscribeServer) error {
	b.in <- struct{}{}
	<-s.Context().Done()
	return nil
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("la condición no se cumplió")
}

func TestLiveCuentaStreamsAbiertos(t *testing.T) {
	for _, c := range []struct {
		name   string
		ignore []string
		want   []string
	}{
		{"cuenta", nil, []string{"EventService/Subscribe x2"}},
		{"ignora", []string{"EventService/Subscribe"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			live := NewLive(c.ignore...)
			l, err := Listen(sockPath(t))
			if err != nil {
				t.Fatal(err)
			}
			s := NewServer(live.Options()...)
			b := blockEvents{in: make(chan struct{}, 2)}
			v1.RegisterEventServiceServer(s, b)
			go s.Serve(l)
			t.Cleanup(s.Stop)
			conn, err := DialPath(l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if len(live.Active()) != 0 {
				t.Fatalf("sin streams, Active = %v", live.Active())
			}
			ctx, cancel := context.WithCancel(context.Background())
			for i := 0; i < 2; i++ {
				if _, err := v1.NewEventServiceClient(conn).Subscribe(ctx, &v1.SubscribeRequest{}); err != nil {
					t.Fatal(err)
				}
				<-b.in
			}
			if got := live.Active(); !slices.Equal(got, c.want) {
				t.Fatalf("Active = %v, quería %v", got, c.want)
			}
			cancel()
			eventually(t, func() bool { return len(live.Active()) == 0 })
		})
	}
}
