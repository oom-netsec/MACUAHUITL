package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeVault struct {
	v1.UnimplementedVaultServiceServer
}

func (fakeVault) Status(context.Context, *v1.StatusRequest) (*v1.StatusResponse, error) {
	return &v1.StatusResponse{State: v1.VaultState_VAULT_STATE_UNLOCKED}, nil
}

func (fakeVault) ListCredentials(context.Context, *v1.ListCredentialsRequest) (*v1.ListCredentialsResponse, error) {
	return &v1.ListCredentialsResponse{Credentials: []*v1.CredentialInfo{{Id: "c1", Label: "lab", Username: "admin", HasEnableSecret: true}}}, nil
}

func startFake(t *testing.T, path string) context.CancelFunc {
	t.Helper()
	l, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterVaultServiceServer(r, fakeVault{}) })
	return cancel
}

type recorder struct {
	mu  sync.Mutex
	evs []string
}

func (r *recorder) emit(name string, data any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(data)
	r.evs = append(r.evs, name+" "+string(b))
}

func (r *recorder) waitFor(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, e := range r.evs {
			if e == want {
				r.mu.Unlock()
				return
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("event %q never emitted; got %v", want, r.evs)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.evs = nil
	r.mu.Unlock()
}

func TestBridgeReconnects(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	stop := startFake(t, sock)
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	b.Interval = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Start(ctx, b)
	rec.waitFor(t, `core:status "connected"`)
	stop()
	rec.reset()
	rec.waitFor(t, `core:status "disconnected"`)
	os.Remove(sock)
	defer startFake(t, sock)()
	rec.waitFor(t, `core:status "connected"`)
}

func TestBridgeNeverReturnsSecrets(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	defer startFake(t, sock)()
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	creds, err := b.ListCredentials()
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(creds)
	for _, banned := range []string{"password", "secret\"", "private"} {
		if strings.Contains(strings.ToLower(string(j)), banned) {
			t.Fatalf("credential DTO exposes %q: %s", banned, j)
		}
	}
	if !strings.Contains(string(j), `"hasEnable":true`) {
		t.Fatalf("dto = %s", j)
	}
}
