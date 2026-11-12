package pcapan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

const ms = time.Millisecond

// scenario arma una captura con un poco de todo lo que un caso TAC trae.
func scenario(t *testing.T) string {
	c := newCapture(t)
	// SSH sano: handshake con RTT de 5 ms, datos, una retransmisión y cierre con RST.
	c.tcp(0, "10.0.0.1", 40000, "10.0.0.2", 22, 100, "S", 64240, nil)
	c.tcp(5*ms, "10.0.0.2", 22, "10.0.0.1", 40000, 900, "SA", 64240, nil)
	c.tcp(6*ms, "10.0.0.1", 40000, "10.0.0.2", 22, 101, "A", 64240, nil)
	c.tcp(10*ms, "10.0.0.1", 40000, "10.0.0.2", 22, 101, "PA", 64240, []byte("SSH-2.0-cliente\r\n"))
	c.tcp(210*ms, "10.0.0.1", 40000, "10.0.0.2", 22, 101, "PA", 64240, []byte("SSH-2.0-cliente\r\n")) // retransmisión
	c.tcp(300*ms, "10.0.0.2", 22, "10.0.0.1", 40000, 901, "A", 0, nil)                                // ventana cero
	c.tcp(400*ms, "10.0.0.2", 22, "10.0.0.1", 40000, 901, "R", 0, nil)
	// HTTPS que nunca contesta: dos SYN.
	c.tcp(20*ms, "10.0.0.1", 40001, "10.0.0.3", 443, 500, "S", 64240, nil)
	c.tcp(1020*ms, "10.0.0.1", 40001, "10.0.0.3", 443, 500, "S", 64240, nil)
	// TLS con SNI.
	c.tcp(30*ms, "10.0.0.1", 40002, "10.0.0.4", 443, 700, "S", 64240, nil)
	c.tcp(32*ms, "10.0.0.4", 443, "10.0.0.1", 40002, 1700, "SA", 64240, nil)
	c.tcp(33*ms, "10.0.0.1", 40002, "10.0.0.4", 443, 701, "PA", 64240, clientHello("ise.example.com"))
	// DNS: una rápida, una NXDOMAIN, una lenta y una sin respuesta.
	c.dns(40*ms, "10.0.0.1", 50001, "10.0.0.53", 53, query(1, "ok.example.com"))
	c.dns(45*ms, "10.0.0.53", 53, "10.0.0.1", 50001, answer(1, "ok.example.com", layers.DNSResponseCodeNoErr))
	c.dns(50*ms, "10.0.0.1", 50002, "10.0.0.53", 53, query(2, "nada.example.com"))
	c.dns(52*ms, "10.0.0.53", 53, "10.0.0.1", 50002, answer(2, "nada.example.com", layers.DNSResponseCodeNXDomain))
	c.dns(60*ms, "10.0.0.1", 50003, "10.0.0.53", 53, query(3, "lento.example.com"))
	c.dns(760*ms, "10.0.0.53", 53, "10.0.0.1", 50003, answer(3, "lento.example.com", layers.DNSResponseCodeNoErr))
	c.dns(70*ms, "10.0.0.1", 50004, "10.0.0.53", 53, query(4, "mudo.example.com"))
	// Respuesta falsa: mismo puerto pero ID que nadie preguntó; no debe contar como respuesta.
	c.dns(71*ms, "10.0.0.53", 53, "10.0.0.1", 50004, answer(99, "mudo.example.com", layers.DNSResponseCodeNoErr))
	// ICMP: un router dice que 10.0.0.9 es inalcanzable.
	inner := ip4("10.0.0.1", "10.0.0.9", layers.IPProtocolUDP)
	innerUDP := &layers.UDP{SrcPort: 1, DstPort: 2}
	innerUDP.SetNetworkLayerForChecksum(inner)
	c.add(80*ms, eth(macB, macA, layers.EthernetTypeIPv4), ip4("10.0.0.254", "10.0.0.1", layers.IPProtocolICMPv4),
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 1)}, inner, innerUDP)
	// CDP y LLDP del switch al que estoy conectado.
	c.raw(90*ms, cdpFrame("SW-ACCESO-01", "GigabitEthernet1/0/7", "cisco C9300-24P", 10, "192.0.2.5"))
	c.add(95*ms, &layers.Ethernet{SrcMAC: macC, DstMAC: []byte{0x01, 0x80, 0xc2, 0, 0, 0x0e}, EthernetType: layers.EthernetTypeLinkLayerDiscovery},
		&layers.LinkLayerDiscovery{
			ChassisID: layers.LLDPChassisID{Subtype: layers.LLDPChassisIDSubTypeMACAddr, ID: macC},
			PortID:    layers.LLDPPortID{Subtype: layers.LLDPPortIDSubtypeIfaceName, ID: []byte("Gi1/0/7")},
			TTL:       120,
			Values:    []layers.LinkLayerDiscoveryValue{{Type: layers.LLDPTLVSysName, Value: []byte("SW-ACCESO-01"), Length: 12}},
		})
	// ARP: la misma IP anunciada por dos MAC (conflicto).
	for i, mac := range [][]byte{macA, macC} {
		c.add(time.Duration(100+i)*ms, eth(mac, macB, layers.EthernetTypeARP), &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
			HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPReply, SourceHwAddress: mac, SourceProtAddress: v4("10.0.0.50"),
			DstHwAddress: macB, DstProtAddress: v4("10.0.0.1")})
	}
	// Un fragmento IP.
	frag := ip4("10.0.0.1", "10.0.0.2", layers.IPProtocolUDP)
	frag.Flags = layers.IPv4MoreFragments
	fu := &layers.UDP{SrcPort: 5000, DstPort: 6000}
	fu.SetNetworkLayerForChecksum(frag)
	c.add(110*ms, eth(macA, macB, layers.EthernetTypeIPv4), frag, fu, gopacket_payload(1200))
	return c.write("caso.pcap")
}

func TestAnalyzeScenario(t *testing.T) {
	r, err := Analyze(context.Background(), scenario(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Packets != 26 || r.Duration != 1020*ms { // 12 TCP + 8 DNS + ICMP + CDP + LLDP + 2 ARP + fragmento
		t.Fatalf("packets=%d duration=%v", r.Packets, r.Duration)
	}
	// TCP
	if r.TCP.Handshakes != 2 || len(r.TCP.FailedHandshakes) != 1 || r.TCP.FailedHandshakes[0].Server != "10.0.0.3:443" || r.TCP.FailedHandshakes[0].Attempts != 2 {
		t.Errorf("handshakes: %+v", r.TCP)
	}
	if r.TCP.Retransmissions != 1 || r.TCP.ZeroWindow != 1 || len(r.TCP.Resets) != 1 || r.TCP.Resets[0].Count != 1 {
		t.Errorf("tcp: %+v", r.TCP)
	}
	if r.TCP.HandshakeRTT.Max != 5*ms {
		t.Errorf("rtt: %+v", r.TCP.HandshakeRTT)
	}
	// DNS
	if r.DNS.Queries != 4 || r.DNS.Responses != 3 || len(r.DNS.Unanswered) != 1 || r.DNS.Unanswered[0].Name != "mudo.example.com" {
		t.Errorf("dns: %+v", r.DNS)
	}
	if len(r.DNS.Errors) != 1 || r.DNS.Errors[0].RCode != "NXDOMAIN" || len(r.DNS.Slow) != 1 || r.DNS.Slow[0].Latency != 700*ms {
		t.Errorf("dns errors/slow: %+v %+v", r.DNS.Errors, r.DNS.Slow)
	}
	// TLS, ICMP, vecinos, ARP, fragmentos
	if len(r.TLS) != 1 || r.TLS[0].SNI != "ise.example.com" || r.TLS[0].Server != "10.0.0.4:443" {
		t.Errorf("tls: %+v", r.TLS)
	}
	if len(r.ICMP.Unreachable) != 1 || r.ICMP.Unreachable[0].Target != "10.0.0.9" || r.ICMP.Unreachable[0].From != "10.0.0.254" {
		t.Errorf("icmp: %+v", r.ICMP)
	}
	var cdp, lldp *Neighbor
	for i := range r.Neighbors {
		switch r.Neighbors[i].Protocol {
		case "cdp":
			cdp = &r.Neighbors[i]
		case "lldp":
			lldp = &r.Neighbors[i]
		}
	}
	if cdp == nil || cdp.DeviceID != "SW-ACCESO-01" || cdp.Port != "GigabitEthernet1/0/7" || cdp.Platform != "cisco C9300-24P" || cdp.NativeVLAN != 10 || cdp.MgmtIP != "192.0.2.5" {
		t.Errorf("cdp: %+v", cdp)
	}
	if lldp == nil || lldp.DeviceID != "SW-ACCESO-01" || lldp.Port != "Gi1/0/7" {
		t.Errorf("lldp: %+v", lldp)
	}
	if len(r.ARPConflicts) != 1 || r.ARPConflicts[0].IP != "10.0.0.50" || len(r.ARPConflicts[0].MACs) != 2 {
		t.Errorf("arp: %+v", r.ARPConflicts)
	}
	if r.Fragments != 1 {
		t.Errorf("fragments = %d", r.Fragments)
	}
	if len(r.Conversations) == 0 || len(r.Talkers) == 0 || r.Talkers[0].IP != "10.0.0.1" {
		t.Errorf("conversations/talkers: %+v %+v", r.Conversations, r.Talkers)
	}
	txt := r.Text()
	for _, want := range []string{"SW-ACCESO-01", "10.0.0.3:443", "mudo.example.com", "ise.example.com", "10.0.0.50"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text summary lacks %q", want)
		}
	}
}

func TestTruncatedFileGivesPartialReport(t *testing.T) {
	p := scenario(t)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, b[:len(b)-30], 0o600)
	r, err := Analyze(context.Background(), p, Options{})
	if err != nil || r.Packets == 0 || len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "truncad") {
		t.Fatalf("r=%+v err=%v", r.Warnings, err)
	}
}

func TestGarbageFileIsError(t *testing.T) {
	p := t.TempDir() + "/x.pcap"
	os.WriteFile(p, []byte("esto no es un pcap"), 0o600)
	if _, err := Analyze(context.Background(), p, Options{}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestPcapngSupported(t *testing.T) {
	r, err := Analyze(context.Background(), scenarioNg(t), Options{})
	if err != nil || r.Packets != 2 || r.TCP.Handshakes != 1 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestTopLimit(t *testing.T) {
	c := newCapture(t)
	for i := 0; i < 50; i++ {
		c.tcp(time.Duration(i)*ms, "10.0.1.1", uint16(41000+i), "10.0.2.2", 80, 1, "S", 1000, nil)
	}
	r, err := Analyze(context.Background(), c.write("muchos.pcap"), Options{Top: 5})
	if err != nil || len(r.Conversations) != 5 || len(r.TCP.FailedHandshakes) != 5 || r.TCP.FailedHandshakesTotal != 50 {
		t.Fatalf("conv=%d failed=%d total=%d err=%v", len(r.Conversations), len(r.TCP.FailedHandshakes), r.TCP.FailedHandshakesTotal, err)
	}
}

// Revisión final: una captura con millones de flujos no puede agotar la memoria del núcleo.
func TestStateIsBounded(t *testing.T) {
	c := newCapture(t)
	for i := 0; i < 50; i++ {
		c.tcp(time.Duration(i)*ms, "10.0.1.1", uint16(41000+i), "10.0.2.2", 80, 1, "S", 1000, nil)
		c.dns(time.Duration(i)*ms, "10.0.1.1", uint16(50000+i), "10.0.0.53", 53, query(uint16(i), fmt.Sprintf("h%d.lab.", i)))
	}
	r, err := Analyze(context.Background(), c.write("scan.pcap"), Options{MaxFlows: 10})
	if err != nil || r.Packets != 100 || r.TCP.FailedHandshakesTotal > 10 || len(r.DNS.Unanswered) > 10 {
		t.Fatalf("failed=%d unanswered=%d err=%v", r.TCP.FailedHandshakesTotal, len(r.DNS.Unanswered), err)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "límite") {
		t.Fatalf("no warning about the limit: %v", r.Warnings)
	}
}

func TestAnalyzeHonorsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, scenario(t), Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// La línea de tiempo (Fase 9) necesita la hora de cada RST y retransmisión.
func TestTCPEventsCarryTime(t *testing.T) {
	r, err := Analyze(context.Background(), scenario(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	want := []TCPEvent{
		{At: base.Add(210 * ms), Kind: "retransmision", Client: "10.0.0.1:40000", Server: "10.0.0.2:22"},
		{At: base.Add(400 * ms), Kind: "rst", Client: "10.0.0.1:40000", Server: "10.0.0.2:22"},
	}
	if len(r.TCP.Events) != len(want) {
		t.Fatalf("events = %+v", r.TCP.Events)
	}
	for i := range want {
		if !r.TCP.Events[i].At.Equal(want[i].At) || r.TCP.Events[i].Kind != want[i].Kind || r.TCP.Events[i].Client != want[i].Client || r.TCP.Events[i].Server != want[i].Server {
			t.Errorf("event %d = %+v, want %+v", i, r.TCP.Events[i], want[i])
		}
	}
}
