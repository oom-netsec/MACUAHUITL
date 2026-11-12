package transport

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
	"golang.org/x/crypto/ssh"
)

func TestKnownHostsIPv6AndPorts(t *testing.T) {
	kh, p := openKH(t)
	k6, k4 := newKey(t), newKey(t)
	if err := kh.Add("[fe80::1]:22", k6); err != nil {
		t.Fatal(err)
	}
	if err := kh.Add("10.0.0.1:2222", k4); err != nil {
		t.Fatal(err)
	}
	again, _ := OpenKnownHosts(p)
	for hp, k := range map[string]ssh.PublicKey{"[fe80::1]:22": k6, "10.0.0.1:2222": k4} {
		if s, err := again.Check(hp, k); err != nil || s != HostKeyKnown {
			t.Errorf("%s: %v %v", hp, s, err)
		}
	}
	// Un equipo IPv6 no debe afectar a los demás.
	if s, err := again.Check(hp, newKey(t)); err != nil || s != HostKeyUnknown {
		t.Errorf("unrelated host: %v %v", s, err)
	}
}

func TestKnownHostsCaseInsensitive(t *testing.T) {
	kh, _ := openKH(t)
	k := newKey(t)
	kh.Add("SW1.EXAMPLE:22", k)
	if s, err := kh.Check("sw1.example:22", k); err != nil || s != HostKeyKnown {
		t.Fatalf("%v %v", s, err)
	}
}

func TestKnownHostsCorruptIsError(t *testing.T) {
	kh, p := openKH(t)
	k := newKey(t)
	kh.Add(hp, k)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte("basura sin sentido\n")...), 0o600)
	if _, err := kh.Check(hp, k); err == nil {
		t.Fatal("corrupt file not reported")
	}
	err := kh.Callback(HostKeyPolicy{}, nil)(hp, remote, k)
	var he *HostKeyError
	if err == nil || (errors.As(err, &he) && he.Status == HostKeyUnknown) {
		t.Fatalf("corrupt file must not look like an unknown key: %v", err)
	}
}

func TestAcceptedChangedKeepsOldFingerprint(t *testing.T) {
	kh, _ := openKH(t)
	k1, k2 := newKey(t), newKey(t)
	kh.Add(hp, k1)
	var ev []audit.Entry
	kh.Callback(HostKeyPolicy{Accepted: map[string]bool{Fingerprint(k2): true}}, func(e audit.Entry) { ev = append(ev, e) })(hp, remote, k2)
	if len(ev) != 1 || ev[0].Action != "hostkey.accepted_changed" || !strings.Contains(ev[0].Detail, Fingerprint(k1)) {
		t.Fatalf("events = %+v", ev)
	}
}

func kiSim(t *testing.T, attempts *atomic.Int32) (*Guard, string, uint16, ssh.PublicKey) {
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "SW1", Username: "admin", Password: "pw", Enable: "en", Transcripts: iosxeDir(), KeyboardInteractive: true, Attempts: attempts})
	ap := netip.MustParseAddrPort(addr)
	g := NewGuard(nil, nil)
	g.Allow(context.Background(), "j", []string{ap.Addr().String()})
	return g, ap.Addr().String(), ap.Port(), hk
}

func TestOpenSSHSingleAuthAttempt(t *testing.T) {
	var n atomic.Int32
	g, host, port, hk := kiSim(t, &n)
	if _, err := OpenSSH(context.Background(), g, "j", host, port, testCred("mala"), ssh.FixedHostKey(hk), SSHOptions{}); !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("password sent %d times, want 1", n.Load())
	}
}

func TestOpenSSHGoodPasswordWithKI(t *testing.T) {
	var n atomic.Int32
	g, host, port, hk := kiSim(t, &n)
	s, err := OpenSSH(context.Background(), g, "j", host, port, testCred("pw"), ssh.FixedHostKey(hk), SSHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestKeepaliveTimeoutCloses(t *testing.T) {
	closed := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go keepaliveLoop(20*time.Millisecond, func() error { select {} }, func() { close(closed) }, stop)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("hung keepalive never closed the session")
	}
}

func TestLegacyAlgorithmsReported(t *testing.T) {
	g, host, port, hk := startSim(t)
	var got string
	s, err := OpenSSH(context.Background(), g, "j", host, port, testCred("pw"), ssh.FixedHostKey(hk), SSHOptions{AllowLegacy: true, OnLegacy: func(a string) { got = a }})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if !strings.Contains(got, "kex=") || !strings.Contains(got, "cipher=") {
		t.Fatalf("negotiated algorithms not reported: %q", got)
	}
	for _, c := range legacyCiphers {
		if c == "aes256-cbc" {
			t.Fatal("aes256-cbc is not implemented by x/crypto and must not be listed")
		}
	}
}

func TestAllowRejectsHostBits(t *testing.T) {
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{"10.0.0.1/8"}); err == nil {
		t.Fatal("10.0.0.1/8 silently widened to 10.0.0.0/8")
	}
}
