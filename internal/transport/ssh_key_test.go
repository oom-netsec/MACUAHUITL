package transport

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// keySim levanta un simulador solo-llave y devuelve la credencial `key` (una fresca por llamada) autorizada en él.
type keySim struct {
	g        *Guard
	host     string
	port     uint16
	hk       ssh.PublicKey
	log      *[]string
	attempts *atomic.Int32
	cred     func() vault.Credential
}

func newKeySim(t *testing.T, noPassword bool) keySim {
	t.Helper()
	vault.MinMemoryKiB = 8192
	v, err := vault.Create(filepath.Join(t.TempDir(), "v.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	id, pub, err := v.GenerateKey("pi", "pi")
	if err != nil {
		t.Fatal(err)
	}
	var log []string
	var attempts atomic.Int32
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "pi", Username: "pi", Password: "pw", Transcripts: iosxeDir(),
		AuthorizedKeys: []ssh.PublicKey{simulator.ParseAuthorizedKey(t, pub.AuthorizedKey())}, NoPassword: noPassword, AuthLog: &log, Attempts: &attempts})
	ap := netip.MustParseAddrPort(addr)
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	return keySim{g, ap.Addr().String(), ap.Port(), hk, &log, &attempts, func() vault.Credential {
		c, err := v.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}}
}

func TestOpenSSHKeyGenericHost(t *testing.T) {
	k := newKeySim(t, false) // el simulador también acepta password: la llave no debe caer a ella
	s, err := OpenSSH(context.Background(), k.g, "j", k.host, k.port, k.cred(), ssh.FixedHostKey(k.hk), SSHOptions{GenericHost: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, m := range *k.log {
		if m != "none" && m != "publickey" {
			t.Fatalf("método ofrecido: %q (log %v)", m, *k.log)
		}
	}
	if !slices.Contains(*k.log, "publickey") || k.attempts.Load() != 0 {
		t.Fatalf("log %v, contraseñas %d", *k.log, k.attempts.Load())
	}
}

func TestOpenSSHKeyWithoutGenericHost(t *testing.T) {
	k := newKeySim(t, false)
	_, err := OpenSSH(context.Background(), k.g, "j", k.host, k.port, k.cred(), ssh.FixedHostKey(k.hk), SSHOptions{})
	if !errors.Is(err, ErrKeyCredential) {
		t.Fatalf("err = %v", err)
	}
	if len(*k.log) != 0 {
		t.Fatalf("conectó al simulador: %v", *k.log)
	}
}

func TestOpenSSHPasswordPlusKeyWithoutGenericHost(t *testing.T) {
	k := newKeySim(t, false)
	c := k.cred()
	c.Password = secret.New([]byte("pw"))
	s, err := OpenSSH(context.Background(), k.g, "j", k.host, k.port, c, ssh.FixedHostKey(k.hk), SSHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestOpenSSHKeyAgainstPasswordOnlyHost(t *testing.T) {
	var attempts atomic.Int32
	var log []string
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "SW1", Username: "admin", Password: "pw", Transcripts: iosxeDir(), Attempts: &attempts, KeyboardInteractive: true, AuthLog: &log})
	ap := netip.MustParseAddrPort(addr)
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	k := newKeySim(t, false)
	_, err := OpenSSH(context.Background(), g, "j", ap.Addr().String(), ap.Port(), k.cred(), ssh.FixedHostKey(hk), SSHOptions{GenericHost: true})
	if !errors.Is(err, ErrAuth) || attempts.Load() != 0 || slices.Contains(log, "password") || slices.Contains(log, "keyboard-interactive") {
		t.Fatalf("err = %v, contraseñas %d, log %v", err, attempts.Load(), log)
	}
}
