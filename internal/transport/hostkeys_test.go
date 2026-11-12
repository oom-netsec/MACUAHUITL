package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
)

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var remote = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}

const hp = "10.0.0.1:22"

func openKH(t *testing.T) (*KnownHosts, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	k, err := OpenKnownHosts(p)
	if err != nil {
		t.Fatal(err)
	}
	return k, p
}

func TestUnknownReturnsFingerprint(t *testing.T) {
	kh, _ := openKH(t)
	key := newKey(t)
	err := kh.Callback(HostKeyPolicy{}, nil)(hp, remote, key)
	var he *HostKeyError
	if !errors.As(err, &he) || he.Status != HostKeyUnknown || he.Fingerprint != Fingerprint(key) {
		t.Fatalf("err = %v", err)
	}
}

func TestAcceptedFingerprintAdds(t *testing.T) {
	kh, p := openKH(t)
	key := newKey(t)
	pol := HostKeyPolicy{Accepted: map[string]bool{Fingerprint(key): true}}
	if err := kh.Callback(pol, nil)(hp, remote, key); err != nil {
		t.Fatal(err)
	}
	if s, _ := kh.Check(hp, key); s != HostKeyKnown {
		t.Fatalf("status = %v", s)
	}
	again, err := OpenKnownHosts(p)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := again.Check(hp, key); s != HostKeyKnown {
		t.Fatalf("after reopen status = %v", s)
	}
}

func TestChangedRejectedByDefault(t *testing.T) {
	kh, _ := openKH(t)
	k1, k2 := newKey(t), newKey(t)
	kh.Add(hp, k1)
	if s, _ := kh.Check(hp, k2); s != HostKeyChanged {
		t.Fatalf("status = %v", s)
	}
	var he *HostKeyError
	if err := kh.Callback(HostKeyPolicy{}, nil)(hp, remote, k2); !errors.As(err, &he) || he.Status != HostKeyChanged {
		t.Fatalf("err = %v", err)
	}
}

func TestChangedAcceptedWhenAllowed(t *testing.T) {
	kh, p := openKH(t)
	k1, k2 := newKey(t), newKey(t)
	kh.Add(hp, k1)
	var ev []audit.Entry
	if err := kh.Callback(HostKeyPolicy{AcceptChanged: true}, func(e audit.Entry) { ev = append(ev, e) })(hp, remote, k2); err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Action != "hostkey.accepted_changed" || !strings.Contains(ev[0].Detail, Fingerprint(k1)) || !strings.Contains(ev[0].Detail, Fingerprint(k2)) {
		t.Fatalf("events = %+v", ev)
	}
	if s, _ := kh.Check(hp, k2); s != HostKeyKnown {
		t.Fatalf("new key status = %v", s)
	}
	if s, _ := kh.Check(hp, k1); s != HostKeyChanged {
		t.Fatalf("old key should be gone, status = %v", s)
	}
	b, _ := os.ReadFile(p)
	if n := strings.Count(string(b), "\n"); n != 1 {
		t.Fatalf("file has %d lines, want 1:\n%s", n, b)
	}
}

func TestKnownHostsPerms(t *testing.T) {
	_, p := openKH(t)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o", fi.Mode().Perm())
	}
}
