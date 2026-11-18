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
	"github.com/oom-netsec/MACUAHUITL/internal/sys/systest"
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
	p := filepath.Join(systest.TempDir(t), "known_hosts")
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
	pol := HostKeyPolicy{Accepted: acc(hp, key)}
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
	systest.Inherited(t, p, 0o600)
}

// acc arma Accepted para un host y las llaves dadas.
func acc(host string, keys ...ssh.PublicKey) map[string]map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[Fingerprint(k)] = true
	}
	return map[string]map[string]bool{host: m}
}

func TestHostKeyIDNormaliza(t *testing.T) {
	cases := []struct {
		host string
		port uint16
		want string
	}{
		{"SW1.Lab", 22, "sw1.lab:22"},
		{"sw1.lab", 0, "sw1.lab:22"},
		{"10.0.0.1", 22, "10.0.0.1:22"},
		{"10.0.0.1", 2222, "10.0.0.1:2222"},
		{"2001:DB8::1", 22, "[2001:db8::1]:22"},
		{"2001:db8::1", 0, "[2001:db8::1]:22"},
	}
	for _, c := range cases {
		if got := HostKeyID(c.host, c.port); got != c.want {
			t.Errorf("HostKeyID(%q,%d) = %q, quiero %q", c.host, c.port, got, c.want)
		}
	}
}

func TestParseHostKeyID(t *testing.T) {
	ok := map[string]string{
		"SW1.lab":           "sw1.lab:22",
		"sw1.lab:2222":      "sw1.lab:2222",
		"10.0.0.1":          "10.0.0.1:22",
		"10.0.0.1:22":       "10.0.0.1:22",
		"[2001:DB8::1]:830": "[2001:db8::1]:830",
		"[2001:db8::1]":     "[2001:db8::1]:22",
		"2001:db8::1":       "[2001:db8::1]:22",
	}
	for in, want := range ok {
		if got, err := ParseHostKeyID(in); err != nil || got != want {
			t.Errorf("ParseHostKeyID(%q) = %q, %v; quiero %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", "sw1:abc", "sw1:99999", ":22"} {
		if _, err := ParseHostKeyID(bad); err == nil {
			t.Errorf("ParseHostKeyID(%q) debía fallar", bad)
		}
	}
}

// La clave que usa el callback es la misma que usa known_hosts al marcar (ssh.go arma JoinHostPort).
func TestHostKeyIDCoincideConKnownHosts(t *testing.T) {
	kh, p := openKH(t)
	key := newKey(t)
	dial := net.JoinHostPort("2001:DB8::1", "22")
	if err := kh.Callback(HostKeyPolicy{Accepted: acc(HostKeyID("2001:db8::1", 22), key)}, nil)(dial, remote, key); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), HostKeyID("2001:db8::1", 22)+" ") {
		t.Fatalf("known_hosts = %q", b)
	}
}

// A es nuevo y presenta K; B ya era conocido y ahora también presenta K. Aceptar K para A no admite el cambio de B.
func TestAceptarParaANoAdmiteCambioDeB(t *testing.T) {
	kh, _ := openKH(t)
	kb, k := newKey(t), newKey(t)
	const a, b = "10.0.0.1:22", "10.0.0.2:22"
	kh.Add(b, kb)
	cb := kh.Callback(HostKeyPolicy{Accepted: acc(a, k)}, nil)
	var he *HostKeyError
	if err := cb(b, remote, k); !errors.As(err, &he) || he.Status != HostKeyChanged {
		t.Fatalf("B debía fallar con changed: %v", err)
	}
	if s, _ := kh.Check(b, kb); s != HostKeyKnown {
		t.Fatalf("la llave de B no debía cambiar: %v", s)
	}
	if err := cb(a, remote, k); err != nil {
		t.Fatalf("A debía entrar: %v", err)
	}
}

func TestLlaveCompartidaEntreDosNuevos(t *testing.T) {
	kh, _ := openKH(t)
	k := newKey(t)
	cb := kh.Callback(HostKeyPolicy{Accepted: acc("10.0.0.1:22", k)}, nil)
	var he *HostKeyError
	if err := cb("10.0.0.2:22", remote, k); !errors.As(err, &he) || he.Status != HostKeyUnknown {
		t.Fatalf("B nuevo no debía entrar: %v", err)
	}
	if err := cb("10.0.0.1:22", remote, k); err != nil {
		t.Fatal(err)
	}
}

func TestHuellaDeUnPuertoNoCubreOtro(t *testing.T) {
	kh, _ := openKH(t)
	k := newKey(t)
	cb := kh.Callback(HostKeyPolicy{Accepted: acc("10.0.0.1:22", k)}, nil)
	if err := cb("10.0.0.1:2222", remote, k); err == nil {
		t.Fatal("otro puerto del mismo host no debía entrar")
	}
	// Con nombre en mayúsculas el marcado sigue dando la misma clave.
	cb = kh.Callback(HostKeyPolicy{Accepted: acc("sw1.lab:22", k)}, nil)
	if err := cb("SW1.Lab:22", remote, k); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyUnknownSoloCubreUnknown(t *testing.T) {
	kh, _ := openKH(t)
	kb, k := newKey(t), newKey(t)
	kh.Add("10.0.0.2:22", kb)
	cb := kh.Callback(HostKeyPolicy{LegacyUnknown: map[string]bool{Fingerprint(k): true}}, nil)
	var he *HostKeyError
	if err := cb("10.0.0.2:22", remote, k); !errors.As(err, &he) || he.Status != HostKeyChanged {
		t.Fatalf("LegacyUnknown no cubre changed: %v", err)
	}
	if err := cb("10.0.0.1:22", remote, k); err != nil {
		t.Fatalf("LegacyUnknown cubre unknown de cualquier host: %v", err)
	}
}
