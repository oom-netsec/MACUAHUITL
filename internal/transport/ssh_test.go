package transport

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func iosxeDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", "ios-xe")
}

func startSim(t *testing.T) (*Guard, string, uint16, ssh.PublicKey) {
	t.Helper()
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "SW1", Username: "admin", Password: "pw", Enable: "en", Transcripts: iosxeDir()})
	ap := netip.MustParseAddrPort(addr)
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	return g, ap.Addr().String(), ap.Port(), hk
}

func testCred(pw string) vault.Credential {
	return vault.Credential{Username: "admin", Password: secret.New([]byte(pw)), Enable: secret.New([]byte("en"))}
}

func TestOpenSSHAuthOK(t *testing.T) {
	g, host, port, hk := startSim(t)
	s, err := OpenSSH(context.Background(), g, "j", host, port, testCred("pw"), ssh.FixedHostKey(hk), SSHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := s.Shell(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSSHWrongPassword(t *testing.T) {
	g, host, port, hk := startSim(t)
	_, err := OpenSSH(context.Background(), g, "j", host, port, testCred("mala"), ssh.FixedHostKey(hk), SSHOptions{})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenSSHDeniedByGuard(t *testing.T) {
	_, host, port, hk := startSim(t)
	_, err := OpenSSH(context.Background(), NewGuard(nil, nil), "j", host, port, testCred("pw"), ssh.FixedHostKey(hk), SSHOptions{})
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenSSHHostKeyRejected(t *testing.T) {
	g, host, port, _ := startSim(t)
	kh, _ := OpenKnownHosts(filepath.Join(t.TempDir(), "kh"))
	_, err := OpenSSH(context.Background(), g, "j", host, port, testCred("pw"), kh.Callback(HostKeyPolicy{}, nil), SSHOptions{})
	var he *HostKeyError
	if !errors.As(err, &he) || he.Status != HostKeyUnknown {
		t.Fatalf("err = %v", err)
	}
}

func TestCredentialDestroyed(t *testing.T) {
	g, host, port, hk := startSim(t)
	for _, pw := range []string{"pw", "mala"} {
		c := testCred(pw)
		s, _ := OpenSSH(context.Background(), g, "j", host, port, c, ssh.FixedHostKey(hk), SSHOptions{})
		if s != nil {
			s.Close()
		}
		if c.Password.Bytes() != nil {
			t.Errorf("%s: password not destroyed", pw)
		}
		if c.Enable.Bytes() == nil {
			t.Errorf("%s: enable must survive for the driver", pw)
		}
	}
}
