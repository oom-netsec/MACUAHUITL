package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp/snmptest"
)

type trapSink struct {
	mu    sync.Mutex
	traps []Trap
}

func (s *trapSink) add(t Trap) {
	s.mu.Lock()
	s.traps = append(s.traps, t)
	s.mu.Unlock()
}

func (s *trapSink) wait(t *testing.T, n int) []Trap {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.traps) >= n {
			out := append([]Trap(nil), s.traps...)
			s.mu.Unlock()
			return out
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("esperaba %d traps, llegaron %d", n, len(s.traps))
	return nil
}

func startTraps(t *testing.T, cfg TrapConfig) (string, *trapSink) {
	t.Helper()
	sink := &trapSink{}
	ready := make(chan string, 1)
	cfg.Addr = "127.0.0.1:0"
	cfg.OnTrap = sink.add
	cfg.OnListening = func(a string) { ready <- a }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ListenTraps(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ListenTraps: %v", err)
		}
	})
	select {
	case a := <-ready:
		return a, sink
	case err := <-done:
		t.Fatal(err)
	}
	return "", nil
}

func sender(t *testing.T, addr string, v gosnmp.SnmpVersion, setup ...func(*gosnmp.GoSNMP)) *gosnmp.GoSNMP {
	h, p, _ := net.SplitHostPort(addr)
	var port uint16
	for _, c := range p {
		port = port*10 + uint16(c-'0')
	}
	x := &gosnmp.GoSNMP{Target: h, Port: port, Version: v, Community: "public", Timeout: time.Second, Retries: 0}
	for _, f := range setup {
		f(x)
	}
	if err := x.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Conn.Close() })
	return x
}

var linkDown = []gosnmp.SnmpPDU{
	{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(500)},
	{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
	{Name: ".1.3.6.1.2.1.2.2.1.1.7", Type: gosnmp.Integer, Value: 7},
	{Name: ".1.3.6.1.2.1.2.2.1.2.7", Type: gosnmp.OctetString, Value: []byte("GigabitEthernet1/0/7")},
	{Name: ".1.3.6.1.2.1.2.2.1.8.7", Type: gosnmp.Integer, Value: 2},
	{Name: ".1.3.6.1.4.1.9.2.2.1.1.20.7", Type: gosnmp.OctetString, Value: []byte("administratively down")},
}

func TestTrapsV2cV1EInform(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	addr, sink := startTraps(t, TrapConfig{Out: lockedWriter{&mu, &out}})
	if _, err := sender(t, addr, gosnmp.Version2c).SendTrap(gosnmp.SnmpTrap{Variables: linkDown}); err != nil {
		t.Fatal(err)
	}
	if _, err := sender(t, addr, gosnmp.Version1).SendTrap(gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.9", AgentAddress: "10.0.0.1", GenericTrap: 0, Timestamp: 10}); err != nil {
		t.Fatal(err)
	}
	unknown := []gosnmp.SnmpPDU{linkDown[0], {Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9.9.41.2.0.1"},
		{Name: ".1.3.6.1.4.1.9.9.41.1.2.3.1.5.1", Type: gosnmp.OctetString, Value: []byte("Interface down")}}
	// Inform: si el receptor no responde, SendTrap espera la respuesta y falla.
	if _, err := sender(t, addr, gosnmp.Version2c).SendTrap(gosnmp.SnmpTrap{Variables: unknown, IsInform: true}); err != nil {
		t.Fatalf("inform sin respuesta: %v", err)
	}
	ts := sink.wait(t, 3)
	if ts[0].Name != "linkDown" || ts[0].Version != "2c" || !strings.Contains(ts[0].Summary, "GigabitEthernet1/0/7") || !strings.Contains(ts[0].Summary, "administratively down") {
		t.Fatalf("linkDown = %+v", ts[0])
	}
	if ts[1].Name != "coldStart" || ts[1].Version != "1" {
		t.Fatalf("v1 = %+v", ts[1])
	}
	if !ts[2].Inform || ts[2].Name != ".1.3.6.1.4.1.9.9.41.2.0.1" || len(ts[2].Vars) != 3 {
		t.Fatalf("crudo = %+v", ts[2])
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Count(out.String(), "\n") != 3 || strings.Contains(out.String(), "public") {
		t.Fatalf("archivo = %q", out.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestTrapV3AuthPriv(t *testing.T) {
	cred := &Target{User: "noc", AuthProto: "SHA", AuthPass: "authpass123", PrivProto: "AES", PrivPass: "privpass123"}
	addr, sink := startTraps(t, TrapConfig{V3: cred})
	x := sender(t, addr, gosnmp.Version3, func(x *gosnmp.GoSNMP) {
		x.SecurityModel, x.MsgFlags = gosnmp.UserSecurityModel, gosnmp.AuthPriv
		x.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: "noc", AuthoritativeEngineID: snmptest.EngineID, AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 50,
			AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "authpass123", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123"}
	})
	if _, err := x.SendTrap(gosnmp.SnmpTrap{Variables: linkDown}); err != nil {
		t.Fatal(err)
	}
	ts := sink.wait(t, 1)
	if ts[0].Version != "3" || ts[0].Name != "linkDown" || ts[0].Error != "" {
		t.Fatalf("v3 = %+v", ts[0])
	}
}

func TestTrapBasuraNoTumbaElReceptor(t *testing.T) {
	addr, sink := startTraps(t, TrapConfig{})
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, b := range [][]byte{{0x30, 0x82, 0xff, 0xff, 0x02}, bytes.Repeat([]byte{0x30}, 60000), {}, []byte("hola")} {
		c.Write(b)
	}
	if _, err := sender(t, addr, gosnmp.Version2c).SendTrap(gosnmp.SnmpTrap{Variables: linkDown}); err != nil {
		t.Fatal(err)
	}
	ts := sink.wait(t, 5)
	var bad, good int
	for _, tr := range ts {
		if tr.Error != "" {
			bad++
			if len(tr.Raw) > 2*MaxRawTrap {
				t.Fatalf("crudo sin recortar: %d", len(tr.Raw))
			}
		} else if tr.Name == "linkDown" {
			good++
		}
	}
	if bad < 3 || good != 1 {
		t.Fatalf("malos=%d buenos=%d %+v", bad, good, ts)
	}
}

func TestTrapAddrPrivilegiado(t *testing.T) {
	if err := ListenTraps(context.Background(), TrapConfig{Addr: "127.0.0.1:162"}); err == nil || !strings.Contains(err.Error(), "privilegiado") {
		t.Fatalf("err = %v", err)
	}
	if err := ListenTraps(context.Background(), TrapConfig{Addr: "0.0.0.0:1162"}); err == nil {
		t.Fatal("0.0.0.0 sin pedirlo")
	}
}

// Revisión: un trap v1/v2c que no decodifica no puede dejar la comunidad en Raw (evento, UI y archivo).
func TestTrapCrudoSinComunidad(t *testing.T) {
	var out bytes.Buffer
	var mu sync.Mutex
	addr, sink := startTraps(t, TrapConfig{Out: lockedWriter{&mu, &out}})
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "COMUNIDAD-SECRETA"}
	pkt, err := x.SnmpEncodePacket(gosnmp.SNMPv2Trap, linkDown, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(pkt[:len(pkt)-6])
	tr := sink.wait(t, 1)[0]
	if tr.Error == "" {
		t.Fatalf("el trap truncado decodificó: %+v", tr)
	}
	b, _ := json.Marshal(tr)
	secret := hex.EncodeToString([]byte("COMUNIDAD-SECRETA"))
	mu.Lock()
	defer mu.Unlock()
	for _, s := range []string{string(b), out.String()} {
		if strings.Contains(s, secret) || strings.Contains(s, "COMUNIDAD-SECRETA") {
			t.Fatalf("comunidad expuesta: %s", s)
		}
	}
	if tr.Raw == "" {
		t.Fatal("se perdió el crudo cegado")
	}
}

func TestBlindCommunity(t *testing.T) {
	x := &gosnmp.GoSNMP{Version: gosnmp.Version1, Community: "abc"}
	pkt, _ := x.SnmpEncodePacket(gosnmp.GetRequest, []gosnmp.SnmpPDU{{Name: ".1.3.6.1", Type: gosnmp.Null}}, 0, 0)
	b, ok := blindCommunity(pkt)
	if !ok || bytes.Contains(b, []byte("abc")) || len(b) != len(pkt) || bytes.Contains(pkt, []byte("***")) {
		t.Fatalf("%x %t", b, ok)
	}
	v3 := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "noc"}}
	pkt3, err := v3.SnmpEncodePacket(gosnmp.GetRequest, []gosnmp.SnmpPDU{{Name: ".1.3.6.1", Type: gosnmp.Null}}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := blindCommunity(pkt3); ok {
		t.Error("un paquete v3 (con usuario USM) no se conserva")
	}
	for _, bad := range [][]byte{nil, {0x30}, {0x30, 0x05, 0x02, 0x01}, []byte("hola"), {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01, 0x04, 0x7f, 'a'}} {
		if _, ok := blindCommunity(bad); ok {
			t.Errorf("%x aceptado", bad)
		}
	}
}
