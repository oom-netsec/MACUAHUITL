package syslogd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type sink struct {
	mu   sync.Mutex
	msgs []Message
	buf  bytes.Buffer
}

func (s *sink) on(m Message) { s.mu.Lock(); s.msgs = append(s.msgs, m); s.mu.Unlock() }
func (s *sink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}
func (s *sink) wait(t *testing.T, n int) []Message {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.msgs) >= n {
			out := append([]Message(nil), s.msgs...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("got %d messages, want %d", len(s.msgs), n)
	return nil
}

func start(t *testing.T, proto string) (string, *sink) {
	t.Helper()
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := make(chan string, 1)
	go Listen(ctx, Config{Addr: "127.0.0.1:0", Proto: proto, Out: s, OnMessage: s.on, OnListening: func(a string) { addr <- a }})
	select {
	case a := <-addr:
		return a, s
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not start")
	}
	return "", nil
}

func TestUDPFormats(t *testing.T) {
	addr, s := start(t, "udp")
	c, _ := net.Dial("udp", addr)
	defer c.Close()
	for _, m := range []string{
		"<189>123: *Nov  4 10:00:00.123: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down",
		"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
		"<165>1 2026-11-04T10:00:00.003Z sw1.lab evntslog - ID47 [exampleSDID@32473 iut=\"3\"] BOM'An application event",
	} {
		c.Write([]byte(m))
	}
	got := s.wait(t, 3)
	if got[0].Facility != 23 || got[0].Severity != 5 || got[0].Mnemonic != "LINK-3-UPDOWN" || !strings.HasPrefix(got[0].From, "127.0.0.1:") {
		t.Errorf("cisco: %+v", got[0])
	}
	if got[1].Facility != 4 || got[1].Severity != 2 || got[1].Host != "mymachine" || got[1].Format != "rfc3164" {
		t.Errorf("3164: %+v", got[1])
	}
	if got[2].Format != "rfc5424" || got[2].Host != "sw1.lab" || got[2].App != "evntslog" || got[2].Severity != 5 {
		t.Errorf("5424: %+v", got[2])
	}
	if !strings.Contains(s.buf.String(), "LINK-3-UPDOWN") {
		t.Error("message not written to output")
	}
}

func TestTCPFramings(t *testing.T) {
	addr, s := start(t, "tcp")
	c, _ := net.Dial("tcp", addr)
	m1 := "<189>1: %SYS-5-CONFIG_I: Configured from console"
	fmt.Fprintf(c, "%d %s", len(m1), m1)                       // octet counting (RFC 6587)
	fmt.Fprintf(c, "<190>2: %%SEC-6-IPACCESSLOGP: list 101\n") // newline
	c.Close()
	got := s.wait(t, 2)
	if got[0].Mnemonic != "SYS-5-CONFIG_I" || got[1].Mnemonic != "SEC-6-IPACCESSLOGP" {
		t.Fatalf("%+v", got)
	}
}

func TestHugeAndBinaryMessagesDoNotKillReceiver(t *testing.T) {
	addr, s := start(t, "udp")
	c, _ := net.Dial("udp", addr)
	defer c.Close()
	c.Write(bytes.Repeat([]byte("A"), 60000))
	c.Write([]byte{0x00, 0xff, 0xfe, '<', '1', '>', 0x07, 0x1b, '[', '2', 'J'})
	c.Write([]byte("<14>sigue vivo"))
	got := s.wait(t, 3)
	if len(got[0].Raw) > MaxMessage || !got[0].Truncated {
		t.Errorf("huge message not truncated: len=%d", len(got[0].Raw))
	}
	if strings.ContainsAny(got[1].Raw, "\x00\x07\x1b") {
		t.Errorf("control chars kept: %q", got[1].Raw)
	}
	if got[2].Raw != "<14>sigue vivo" {
		t.Errorf("receiver did not keep working: %+v", got[2])
	}
}

func TestStopsOnContext(t *testing.T) {
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Listen(ctx, Config{Addr: "127.0.0.1:0", Proto: "udp", Out: s, OnMessage: s.on}) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not stop")
	}
}

func TestValidateAddr(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:5514": true, "192.0.2.10:5514": true, "0.0.0.0:5514": false, "[::]:5514": false, ":5514": false, "127.0.0.1:514": false, "127.0.0.1:x": false} {
		if err := ValidateAddr(addr, false); (err == nil) != ok {
			t.Errorf("ValidateAddr(%q) = %v", addr, err)
		}
	}
	if err := ValidateAddr("0.0.0.0:5514", true); err != nil {
		t.Errorf("explicit any rejected: %v", err)
	}
}

// Un solo origen no acapara las conexiones: pasado su tope se le cierran y otro equipo sigue entrando.
func TestTCPTopePorOrigen(t *testing.T) {
	addr, s := start(t, "tcp")
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for range maxPerSource {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("la conexión de más no se cerró: %v", err)
	}
	other := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}} // otro equipo sigue entrando
	oc, err := other.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(oc, "<14>otro origen\n")
	oc.Close()
	s.wait(t, 1)
	held[0].Close() // al liberar una, el mismo origen vuelve a entrar
	held = held[1:]
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "<14>de vuelta\n")
		c.Close()
		if s.count() > 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("el origen no volvió a entrar tras liberar una conexión")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *sink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.msgs) }

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestSourceKeyAgrupaIPv6Por64(t *testing.T) {
	a, b := sourceKey("[2001:db8:1:2::10]:514"), sourceKey("[2001:db8:1:2:ffff::1]:514")
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("%q %q", a, b)
	}
	if k := sourceKey("10.0.0.1:514"); k != "10.0.0.1" {
		t.Fatalf("%q", k)
	}
	if k := sourceKey("[::ffff:10.0.0.1]:514"); k == "::/64" {
		t.Fatalf("IPv4 mapeada agrupada como IPv6: %q", k)
	}
}
