package flows

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type buf struct{ bytes.Buffer }

func (b *buf) u8(v uint8)   { b.WriteByte(v) }
func (b *buf) u16(v uint16) { binary.Write(b, binary.BigEndian, v) }
func (b *buf) u32(v uint32) { binary.Write(b, binary.BigEndian, v) }
func (b *buf) ip(s string)  { b.Write(net.ParseIP(s).To4()) }

func netflowV5(recs int) []byte {
	var b buf
	b.u16(5)
	b.u16(uint16(recs))
	b.u32(1000)
	b.u32(1_700_000_000)
	b.u32(0)
	b.u32(1)
	b.u8(0)
	b.u8(0)
	b.u16(0)
	for i := 0; i < recs; i++ {
		b.ip("10.0.0.1")
		b.ip("10.0.0.2")
		b.ip("0.0.0.0")
		b.u16(1)
		b.u16(2)
		b.u32(10)   // paquetes
		b.u32(1500) // bytes
		b.u32(0)
		b.u32(0)
		b.u16(51000)
		b.u16(443)
		b.u8(0)
		b.u8(0x18)
		b.u8(6)
		b.u8(0)
		b.u16(0)
		b.u16(0)
		b.u8(24)
		b.u8(24)
		b.u16(0)
	}
	return b.Bytes()
}

// Plantilla 256: IN_BYTES(4) IN_PKTS(4) PROTOCOL(1) L4_SRC_PORT(2) IPV4_SRC_ADDR(4) L4_DST_PORT(2) IPV4_DST_ADDR(4) = 21 bytes.
var tmplFields = [][2]uint16{{1, 4}, {2, 4}, {4, 1}, {7, 2}, {8, 4}, {11, 2}, {12, 4}}

func record(b *buf, src, dst string, sport, dport uint16, proto uint8, bytes_, pkts uint32) {
	b.u32(bytes_)
	b.u32(pkts)
	b.u8(proto)
	b.u16(sport)
	b.ip(src)
	b.u16(dport)
	b.ip(dst)
}

func netflowV9(withTemplate bool, sourceID uint32) []byte {
	var sets buf
	if withTemplate {
		sets.u16(0)
		sets.u16(uint16(4 + 4 + 4*len(tmplFields)))
		sets.u16(256)
		sets.u16(uint16(len(tmplFields)))
		for _, f := range tmplFields {
			sets.u16(f[0])
			sets.u16(f[1])
		}
	}
	var data buf
	record(&data, "192.168.1.10", "8.8.8.8", 40000, 53, 17, 120, 2)
	record(&data, "192.168.1.11", "1.1.1.1", 40001, 443, 6, 9000, 9)
	data.Write([]byte{0, 0}) // relleno al final del flowset
	sets.u16(256)
	sets.u16(uint16(4 + data.Len()))
	sets.Write(data.Bytes())
	var b buf
	b.u16(9)
	b.u16(2)
	b.u32(1000)
	b.u32(1_700_000_000)
	b.u32(7)
	b.u32(sourceID)
	b.Write(sets.Bytes())
	return b.Bytes()
}

// IPFIX con un campo de enterprise y uno de largo variable que hay que saltar.
func ipfix() []byte {
	var sets buf
	var t buf
	t.u16(300)
	t.u16(9)
	for _, f := range tmplFields {
		t.u16(f[0])
		t.u16(f[1])
	}
	t.u16(0x8000 | 100) // campo de enterprise
	t.u16(2)
	t.u32(9)  // Cisco
	t.u16(82) // interfaceName, largo variable
	t.u16(65535)
	sets.u16(2)
	sets.u16(uint16(4 + t.Len()))
	sets.Write(t.Bytes())
	var d buf
	record(&d, "10.1.1.1", "10.2.2.2", 33000, 22, 6, 5000, 50)
	d.u16(0xbeef)
	d.u8(6)
	d.Write([]byte("Gi1/0/1"[:6]))
	sets.u16(300)
	sets.u16(uint16(4 + d.Len()))
	sets.Write(d.Bytes())
	var b buf
	b.u16(10)
	b.u16(uint16(16 + sets.Len()))
	b.u32(1_700_000_000)
	b.u32(1)
	b.u32(42)
	b.Write(sets.Bytes())
	return b.Bytes()
}

func sflow() []byte {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("172.16.0.5"), DstIP: net.ParseIP("172.16.0.9")}
	tcp := &layers.TCP{SrcPort: 50500, DstPort: 179}
	tcp.SetNetworkLayerForChecksum(ip)
	sb := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(sb, gopacket.SerializeOptions{FixLengths: true}, eth, ip, tcp)
	hdr := sb.Bytes()
	var rec buf
	rec.u32(1) // ethernet
	rec.u32(1000)
	rec.u32(4)
	rec.u32(uint32(len(hdr)))
	rec.Write(hdr)
	for rec.Len()%4 != 0 {
		rec.u8(0)
	}
	var smp buf
	smp.u32(1)    // seq
	smp.u32(3)    // source id
	smp.u32(512)  // sampling rate
	smp.u32(1000) // pool
	smp.u32(0)
	smp.u32(1)
	smp.u32(2)
	smp.u32(1) // registros
	smp.u32(1) // raw packet header
	smp.u32(uint32(rec.Len()))
	smp.Write(rec.Bytes())
	var b buf
	b.u32(5)
	b.u32(1)
	b.ip("10.0.0.254")
	b.u32(0)
	b.u32(1)
	b.u32(1000)
	b.u32(2) // muestras
	b.u32(2) // muestra de contadores: se salta
	b.u32(4)
	b.u32(0)
	b.u32(1) // muestra de flujo
	b.u32(uint32(smp.Len()))
	b.Write(smp.Bytes())
	return b.Bytes()
}

func TestNetflowV5(t *testing.T) {
	d := NewDecoder()
	fs, err := d.Decode("10.0.0.254:2055", netflowV5(2))
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v %v", fs, err)
	}
	if f := fs[0]; f.Src != "10.0.0.1" || f.Dst != "10.0.0.2" || f.SrcPort != 51000 || f.DstPort != 443 || f.Proto != 6 || f.Bytes != 1500 || f.Packets != 10 || f.Exporter != "10.0.0.254" {
		t.Fatalf("flujo = %+v", f)
	}
	if _, err := d.Decode("x", netflowV5(2)[:60]); err == nil {
		t.Fatal("v5 truncado aceptado")
	}
}

func TestNetflowV9Plantillas(t *testing.T) {
	d := NewDecoder()
	fs, err := d.Decode("10.0.0.254:2055", netflowV9(false, 1))
	if err == nil || len(fs) != 0 {
		t.Fatalf("datos sin plantilla: %v %v", fs, err)
	}
	if fs, err = d.Decode("10.0.0.254:2055", netflowV9(true, 1)); err != nil || len(fs) != 2 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[1].Dst != "1.1.1.1" || fs[1].DstPort != 443 || fs[1].Bytes != 9000 || fs[1].Proto != 6 {
		t.Fatalf("flujo = %+v", fs[1])
	}
	// La plantilla es por exportador y source ID.
	if fs, _ = d.Decode("10.0.0.254:2055", netflowV9(false, 1)); len(fs) != 2 {
		t.Fatalf("plantilla no recordada: %v", fs)
	}
	if fs, _ = d.Decode("10.0.0.253:2055", netflowV9(false, 1)); len(fs) != 0 {
		t.Fatal("plantilla de otro exportador usada")
	}
}

func TestLimitePlantillas(t *testing.T) {
	d := NewDecoder()
	d.MaxTemplates = 2
	for id := uint32(1); id <= 3; id++ {
		d.Decode("10.0.0.254:2055", netflowV9(true, id))
	}
	if n := d.Templates("10.0.0.254"); n != 2 {
		t.Fatalf("plantillas = %d", n)
	}
	d.MaxExporters = 1
	if _, err := d.Decode("10.9.9.9:2055", netflowV9(true, 1)); err == nil || !strings.Contains(err.Error(), "exportadores") {
		t.Fatalf("err = %v", err)
	}
}

func TestIPFIX(t *testing.T) {
	fs, err := NewDecoder().Decode("10.0.0.254:4739", ipfix())
	if err != nil || len(fs) != 1 || fs[0].Src != "10.1.1.1" || fs[0].DstPort != 22 || fs[0].Packets != 50 {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestSFlow(t *testing.T) {
	fs, err := NewDecoder().Decode("10.0.0.254:6343", sflow())
	if err != nil || len(fs) != 1 {
		t.Fatalf("%+v %v", fs, err)
	}
	if f := fs[0]; f.Exporter != "10.0.0.254" || f.Src != "172.16.0.5" || f.DstPort != 179 || f.Bytes != 1000*512 || f.Packets != 512 || f.Proto != 6 {
		t.Fatalf("flujo = %+v", f)
	}
}

func TestBasuraYTruncados(t *testing.T) {
	d := NewDecoder()
	for _, p := range [][]byte{nil, {0}, {0, 9}, {0, 10, 0, 4}, {0, 0, 0, 5, 0, 0, 0, 9}, ipfix()[:30], sflow()[:50], netflowV9(true, 1)[:27],
		bytes.Repeat([]byte{0xff}, 2000)} {
		d.Decode("10.0.0.1:1", p) // no debe entrar en pánico ni ciclar
	}
	// Plantilla con 0 campos o flowset con largo 0 no puede ciclar.
	var b buf
	b.u16(9)
	b.u16(1)
	b.u32(0)
	b.u32(0)
	b.u32(0)
	b.u32(1)
	b.u16(0)
	b.u16(0)
	if _, err := d.Decode("10.0.0.1:1", b.Bytes()); err == nil {
		t.Fatal("flowset de largo 0 aceptado")
	}
}

func TestAgregador(t *testing.T) {
	a := NewAggregator(3)
	a.Add(Flow{Exporter: "e1", Src: "10.0.0.1", Dst: "10.0.0.2", SrcPort: 51000, DstPort: 443, Proto: 6, Bytes: 1000, Packets: 1})
	a.Add(Flow{Exporter: "e1", Src: "10.0.0.2", Dst: "10.0.0.1", SrcPort: 443, DstPort: 51000, Proto: 6, Bytes: 5000, Packets: 4})
	a.Add(Flow{Exporter: "e2", Src: "10.0.0.3", Dst: "10.0.0.4", SrcPort: 5353, DstPort: 53, Proto: 17, Bytes: 100, Packets: 1})
	a.Add(Flow{Exporter: "e2", Src: "10.0.0.5", Dst: "10.0.0.6", Proto: 1, Bytes: 10, Packets: 1})
	a.Add(Flow{Exporter: "e2", Src: "10.0.0.7", Dst: "10.0.0.8", Proto: 1, Bytes: 10, Packets: 1}) // supera el límite de claves
	s := a.Snapshot(10)
	if s.Flows != 5 || s.Bytes != 6120 {
		t.Fatalf("totales = %+v", s)
	}
	if c := s.Conversations[0]; c.Key != "10.0.0.1 ↔ 10.0.0.2 tcp" || c.Bytes != 6000 || c.Flows != 2 {
		t.Fatalf("conversación = %+v", c)
	}
	if p := s.Ports[0]; p.Key != "tcp/443" || p.Bytes != 6000 {
		t.Fatalf("puerto = %+v", p)
	}
	if s.Talkers[0].Key != "10.0.0.1" && s.Talkers[0].Key != "10.0.0.2" {
		t.Fatalf("talkers = %+v", s.Talkers)
	}
	found := false
	for _, c := range s.Conversations {
		found = found || c.Key == Other
	}
	if !found || len(s.Exporters) != 2 || s.Protocols[0].Key != "tcp" {
		t.Fatalf("snapshot = %+v", s)
	}
}

func TestListen(t *testing.T) {
	var mu sync.Mutex
	var snaps []Snapshot
	var out bytes.Buffer
	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Snapshot, 1)
	go func() {
		s, err := Listen(ctx, Config{Addr: "127.0.0.1:0", Every: 50 * time.Millisecond, Top: 5, Out: &out,
			OnListening: func(a string) { ready <- a },
			OnSnapshot:  func(s Snapshot) { mu.Lock(); snaps = append(snaps, s); mu.Unlock() }})
		if err != nil {
			t.Error(err)
		}
		done <- s
	}()
	addr := <-ready
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Write(netflowV5(3))
	c.Write([]byte("basura"))
	c.Write(sflow())
	time.Sleep(200 * time.Millisecond)
	cancel()
	s := <-done
	if s.Flows != 4 || s.Errors == 0 {
		t.Fatalf("final = %+v", s)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(snaps) == 0 || strings.Count(out.String(), "\n") != 4 {
		t.Fatalf("snapshots=%d archivo=%q", len(snaps), out.String())
	}
	if err := (func() error { _, err := Listen(context.Background(), Config{Addr: "127.0.0.1:2"}); return err })(); err == nil {
		t.Fatal("puerto privilegiado aceptado")
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range [][]byte{netflowV5(1), netflowV9(true, 1), ipfix(), sflow()} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		NewDecoder().Decode("10.0.0.1:2055", b)
	})
}

// Revisión: con orígenes falsificados la memoria de plantillas queda acotada.
func TestLimitesDeMemoriaDePlantillas(t *testing.T) {
	d := NewDecoder()
	if d.MaxTemplates != 128 || d.MaxTotal != 16384 || maxFields != 64 {
		t.Fatalf("límites = %d %d %d", d.MaxTemplates, d.MaxTotal, maxFields)
	}
	// Plantilla con 65 campos: se rechaza.
	var b buf
	b.u16(9)
	b.u16(1)
	b.u32(0)
	b.u32(0)
	b.u32(0)
	b.u32(1)
	b.u16(0)
	b.u16(uint16(4 + 4 + 4*65))
	b.u16(256)
	b.u16(65)
	for i := 0; i < 65; i++ {
		b.u16(1)
		b.u16(4)
	}
	if _, err := d.Decode("10.0.0.1:2055", b.Bytes()); err == nil {
		t.Fatal("plantilla de 65 campos aceptada")
	}
	d.MaxTotal = 3
	for i := 1; i <= 3; i++ {
		d.Decode(fmt.Sprintf("10.0.0.%d:2055", i), netflowV9(true, 1))
	}
	if _, err := d.Decode("10.0.0.9:2055", netflowV9(true, 1)); err == nil || !strings.Contains(err.Error(), "global") {
		t.Fatalf("tope global: %v", err)
	}
}

// Revisión: tras retornar Listen no puede quedar un OnSnapshot en curso; el
// núcleo hace su Send final y gRPC prohíbe Send concurrente.
func TestListenNoDejaResumenEnCurso(t *testing.T) {
	for i := 0; i < 5; i++ {
		var returned atomic.Bool
		var inCall int // sin sincronizar a propósito: -race marca si se cruza con la lectura final
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		_, err := Listen(ctx, Config{Addr: "127.0.0.1:0", Every: time.Millisecond, OnSnapshot: func(Snapshot) {
			inCall++
			time.Sleep(15 * time.Millisecond)
			if returned.Load() {
				t.Error("OnSnapshot siguió después de que Listen retornó")
			}
		}})
		returned.Store(true)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		_ = inCall
		time.Sleep(20 * time.Millisecond)
	}
}
