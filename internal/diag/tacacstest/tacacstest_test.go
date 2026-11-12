package tacacstest

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func direct(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// RFC 8907 §4.5: pad = MD5(session_id ‖ key ‖ version ‖ seq_no) ‖ MD5(… ‖ pad anterior) ….
func TestObfuscationPad(t *testing.T) {
	h := header{Version: 0xc0, Type: typeAuthen, Seq: 1, Session: 0x01020304}
	key := []byte("tackey")
	body := bytes.Repeat([]byte{0}, 40)
	got := append([]byte(nil), body...)
	obfuscate(h, key, got)
	base := append(append([]byte{1, 2, 3, 4}, key...), 0xc0, 1)
	p1 := md5.Sum(base)
	p2 := md5.Sum(append(append([]byte(nil), base...), p1[:]...))
	p3 := md5.Sum(append(append([]byte(nil), base...), p2[:]...))
	want := append(append(p1[:], p2[:]...), p3[:8]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("pad\n%x\n%x", got, want)
	}
	obfuscate(h, key, got)
	if !bytes.Equal(got, body) {
		t.Fatal("XOR no es involutivo")
	}
}

func fake(t *testing.T, cfg FakeConfig) (string, uint16) {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = "tac-secret"
	}
	if cfg.Users == nil {
		cfg.Users = map[string]string{"admin": "pw-admin"}
	}
	if cfg.Permit == nil {
		cfg.Permit = map[string][]string{"show": {"priv-lvl=15"}}
	}
	f, err := StartFake(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	h, p, _ := net.SplitHostPort(f.Addr())
	port, _ := strconv.Atoi(p)
	return h, uint16(port)
}

func base(h string, p uint16) Config {
	return Config{Host: h, Port: p, Secret: []byte("tac-secret"), Username: "admin", Password: []byte("pw-admin"),
		Command: "show running-config", Accounting: true, Timeout: time.Second}
}

func TestFullRunASCIIAndPAP(t *testing.T) {
	h, p := fake(t, FakeConfig{})
	for _, typ := range []string{"ascii", "pap"} {
		c := base(h, p)
		c.AuthenType = typ
		r, err := Run(context.Background(), direct, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Steps) != 4 {
			t.Fatalf("%s: steps = %+v", typ, r.Steps)
		}
		want := []string{"PASS", "PASS_ADD", "SUCCESS", "SUCCESS"}
		for i, s := range r.Steps {
			if s.Status != want[i] || s.Error != "" {
				t.Errorf("%s paso %d: %+v", typ, i, s)
			}
		}
		if got := strings.Join(r.Steps[1].AVPairs, ","); got != "priv-lvl=15" {
			t.Errorf("AV = %q", got)
		}
		if typ == "ascii" && !strings.Contains(strings.Join(r.Steps[0].Prompts, "|"), "Password") {
			t.Errorf("prompts = %v", r.Steps[0].Prompts)
		}
	}
}

func TestWrongPasswordAndDeniedCommand(t *testing.T) {
	h, p := fake(t, FakeConfig{})
	c := base(h, p)
	c.Password = []byte("MARCA-mala-77")
	c.Command = "configure terminal"
	r, _ := Run(context.Background(), direct, c)
	if r.Steps[0].Status != "FAIL" || r.Steps[1].Status != "FAIL" {
		t.Fatalf("%+v", r.Steps)
	}
	b, _ := json.Marshal(r)
	if s := string(b) + r.Text(); strings.Contains(s, "MARCA-mala") || strings.Contains(s, "tac-secret") {
		t.Fatal("secretos en el reporte")
	}
}

func TestWrongSecretIsDiagnosed(t *testing.T) {
	h, p := fake(t, FakeConfig{})
	c := base(h, p)
	c.Secret = []byte("otro")
	r, _ := Run(context.Background(), direct, c)
	if !strings.Contains(r.Steps[0].Error, "secreto") {
		t.Fatalf("%+v", r.Steps[0])
	}
	found := false
	for _, f := range r.Findings {
		found = found || f.Code == "secret"
	}
	if !found {
		t.Fatalf("hallazgos: %+v", r.Findings)
	}
}

func TestUnreachable(t *testing.T) {
	c := base("127.0.0.1", 1)
	r, err := Run(context.Background(), direct, c)
	if err != nil || r.Steps[0].Error == "" || len(r.Findings) == 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestValidation(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"sin secreto": func(c *Config) { c.Secret = nil },
		"sin usuario": func(c *Config) { c.Username = "" },
		"tipo":        func(c *Config) { c.AuthenType = "chap" },
		"usuario 256": func(c *Config) { c.Username = strings.Repeat("u", 256) },
	} {
		c := base("127.0.0.1", 49)
		mut(&c)
		if _, err := Run(context.Background(), direct, c); err == nil {
			t.Errorf("%s: aceptado", name)
		}
	}
}

func TestCommandArgs(t *testing.T) {
	if got := strings.Join(commandArgs("show  running-config"), ","); got != "service=shell,cmd=show,cmd-arg=running-config,cmd-arg=<cr>" {
		t.Fatal(got)
	}
}

func TestMalformedBodiesDoNotCrash(t *testing.T) {
	for _, b := range [][]byte{nil, {1}, {1, 0, 0xff, 0xff, 0, 0}, {1, 3, 0, 0, 0, 0, 200, 200, 200}, {0, 0xff, 0, 0}} {
		parseAuthenReply(b)
		parseAuthorResponse(b)
		parseAcctReply(b)
	}
}

// Revisión: cmd=<comando> <cr> del accounting también cabe en 255 bytes o se rechaza antes de enviar.
func TestLongAccountingCommandRejected(t *testing.T) {
	c := base("127.0.0.1", 49)
	c.Command = "show " + strings.Repeat("a", 200) + " " + strings.Repeat("b", 60)
	if _, err := Run(context.Background(), direct, c); err == nil || !strings.Contains(err.Error(), "255") {
		t.Fatalf("err = %v", err)
	}
}
