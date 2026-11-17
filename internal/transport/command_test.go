package transport

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func execSim(t *testing.T, terms *[]string) (host string, port uint16, hk ssh.PublicKey, rec *simulator.Recorder) {
	t.Helper()
	rec = &simulator.Recorder{}
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "pi", Username: "pi", Password: "pw", Transcripts: iosxeDir(), Recorder: rec,
		Exec: func(cmd string) string { return "salida:" + cmd + "\n" }, OnPty: func(term string) { *terms = append(*terms, term) }})
	ap := netip.MustParseAddrPort(addr)
	return ap.Addr().String(), ap.Port(), hk, rec
}

func openPW(t *testing.T, host string, port uint16, hk ssh.PublicKey) *Session {
	t.Helper()
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{host}); err != nil {
		t.Fatal(err)
	}
	s, err := OpenSSH(context.Background(), g, "j", host, port, vault.Credential{Username: "pi", Password: secret.New([]byte("pw"))}, ssh.FixedHostKey(hk), SSHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCommandSizeExecConPty(t *testing.T) {
	var terms []string
	host, port, hk, rec := execSim(t, &terms)
	s := openPW(t, host, port, hk)
	r, _, err := s.CommandSize("xterm-256color", 30, 100, "wsl -d Ubuntu --cd ~")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "salida:wsl -d Ubuntu --cd ~") {
		t.Fatalf("salida %q", out)
	}
	if got := rec.Lines(); len(got) != 1 || got[0] != "!exec pty=true wsl -d Ubuntu --cd ~" {
		t.Fatalf("recorder %v", got)
	}
	if len(terms) != 1 || terms[0] != "xterm-256color" {
		t.Fatalf("term %v", terms)
	}
}

func TestShellSizePasaElTerm(t *testing.T) {
	var terms []string
	host, port, hk, _ := execSim(t, &terms)
	s := openPW(t, host, port, hk)
	if _, _, err := s.ShellSize("xterm-256color", 24, 80); err != nil {
		t.Fatal(err)
	}
	s2 := openPW(t, host, port, hk)
	if _, _, err := s2.Shell(); err != nil {
		t.Fatal(err)
	}
	if len(terms) != 2 || terms[0] != "xterm-256color" || terms[1] != "vt100" {
		t.Fatalf("term %v", terms)
	}
}

func TestHostKeyErrorLlevaKeyType(t *testing.T) {
	var terms []string
	host, port, _, _ := execSim(t, &terms)
	kh, err := OpenKnownHosts(filepath.Join(t.TempDir(), "kh"))
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(nil, func(audit.Entry) {})
	if err := g.Allow(context.Background(), "j", []string{host}); err != nil {
		t.Fatal(err)
	}
	_, err = OpenSSH(context.Background(), g, "j", host, port, vault.Credential{Username: "pi", Password: secret.New([]byte("pw"))}, kh.Callback(HostKeyPolicy{}, nil), SSHOptions{})
	var he *HostKeyError
	if !errors.As(err, &he) {
		t.Fatalf("err = %v", err)
	}
	if he.KeyType != "ssh-ed25519" || he.Metadata()["key_type"] != "ssh-ed25519" {
		t.Fatalf("key_type %q, meta %v", he.KeyType, he.Metadata())
	}
}
