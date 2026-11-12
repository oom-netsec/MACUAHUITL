package pcapan

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// capture arma un pcap en memoria: cada paquete con su marca de tiempo.
type capture struct {
	t    *testing.T
	pkts [][]byte
	ts   []time.Time
	base time.Time
}

func newCapture(t *testing.T) *capture {
	return &capture{t: t, base: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)}
}

var (
	macA = []byte{0, 0x11, 0x22, 0x33, 0x44, 0x01}
	macB = []byte{0, 0x11, 0x22, 0x33, 0x44, 0x02}
	macC = []byte{0, 0x11, 0x22, 0x33, 0x44, 0x03}
)

func (c *capture) add(at time.Duration, ls ...gopacket.SerializableLayer) {
	c.t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		c.t.Fatal(err)
	}
	c.raw(at, buf.Bytes())
}

func (c *capture) raw(at time.Duration, b []byte) {
	c.pkts = append(c.pkts, append([]byte(nil), b...))
	c.ts = append(c.ts, c.base.Add(at))
}

func eth(src, dst []byte, t layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: t}
}

func ip4(src, dst string, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: v4(src), DstIP: v4(dst)}
}

func (c *capture) tcp(at time.Duration, src string, sport uint16, dst string, dport uint16, seq uint32, flags string, win uint16, payload []byte) {
	ip := ip4(src, dst, layers.IPProtocolTCP)
	tc := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Seq: seq, Window: win}
	for _, f := range flags {
		switch f {
		case 'S':
			tc.SYN = true
		case 'A':
			tc.ACK = true
		case 'R':
			tc.RST = true
		case 'F':
			tc.FIN = true
		case 'P':
			tc.PSH = true
		}
	}
	tc.SetNetworkLayerForChecksum(ip)
	c.add(at, eth(macA, macB, layers.EthernetTypeIPv4), ip, tc, gopacket.Payload(payload))
}

func (c *capture) dns(at time.Duration, src string, sport uint16, dst string, dport uint16, d *layers.DNS) {
	ip := ip4(src, dst, layers.IPProtocolUDP)
	u := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	u.SetNetworkLayerForChecksum(ip)
	c.add(at, eth(macA, macB, layers.EthernetTypeIPv4), ip, u, d)
}

func query(id uint16, name string) *layers.DNS {
	return &layers.DNS{ID: id, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
}

func answer(id uint16, name string, rcode layers.DNSResponseCode) *layers.DNS {
	d := query(id, name)
	d.QR, d.RA, d.ResponseCode = true, true, rcode
	if rcode == layers.DNSResponseCodeNoErr {
		d.ANCount = 1
		d.Answers = []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: v4("192.0.2.80")}}
	}
	return d
}

// clientHello arma un ClientHello TLS 1.2 mínimo con la extensión server_name.
func clientHello(sni string) []byte {
	ext := []byte{}
	name := []byte(sni)
	sn := append([]byte{0}, u16(len(name))...)
	sn = append(sn, name...)
	list := append(u16(len(sn)), sn...)
	ext = append(ext, 0, 0) // tipo server_name
	ext = append(ext, u16(len(list))...)
	ext = append(ext, list...)
	body := []byte{3, 3}                     // client_version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id vacío
	body = append(body, 0, 2, 0x13, 1)       // un cipher suite
	body = append(body, 1, 0)                // compresión nula
	body = append(body, u16(len(ext))...)
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1}, u16(len(hs))...)
	return append(rec, hs...)
}

// v4 devuelve los 4 bytes de una IPv4 sin importar net (noegress).
func v4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }

func u16(n int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(n)); return b }

// cdpFrame arma una trama CDPv2 sobre 802.3/LLC/SNAP.
func cdpFrame(deviceID, port, platform string, vlan uint16, mgmt string) []byte {
	tlv := func(t uint16, v []byte) []byte { return append(append(u16(int(t)), u16(len(v)+4)...), v...) }
	addr := []byte{0, 0, 0, 1, 1, 1, 0xcc, 0, 4}
	addr = append(addr, v4(mgmt)...)
	cdp := []byte{2, 180, 0, 0} // versión, TTL, checksum
	cdp = append(cdp, tlv(0x0001, []byte(deviceID))...)
	cdp = append(cdp, tlv(0x0003, []byte(port))...)
	cdp = append(cdp, tlv(0x0006, []byte(platform))...)
	cdp = append(cdp, tlv(0x000a, u16(int(vlan)))...)
	cdp = append(cdp, tlv(0x0016, addr)...)
	llc := append([]byte{0xaa, 0xaa, 0x03, 0, 0, 0x0c, 0x20, 0x00}, cdp...)
	frame := append([]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}, macC...)
	frame = append(frame, u16(len(llc))...)
	return append(frame, llc...)
}

func (c *capture) write(name string) string {
	c.t.Helper()
	p := filepath.Join(c.t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		c.t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	for i, b := range c.pkts {
		w.WritePacket(gopacket.CaptureInfo{Timestamp: c.ts[i], CaptureLength: len(b), Length: len(b)}, b)
	}
	return p
}

func gopacket_payload(n int) gopacket.Payload { return gopacket.Payload(make([]byte, n)) }

func scenarioNg(t *testing.T) string {
	c := newCapture(t)
	c.tcp(0, "10.0.0.1", 40000, "10.0.0.2", 22, 1, "S", 1000, nil)
	c.tcp(3*time.Millisecond, "10.0.0.2", 22, "10.0.0.1", 40000, 9, "SA", 1000, nil)
	p := filepath.Join(t.TempDir(), "caso.pcapng")
	f, _ := os.Create(p)
	defer f.Close()
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range c.pkts {
		w.WritePacket(gopacket.CaptureInfo{Timestamp: c.ts[i], CaptureLength: len(b), Length: len(b), InterfaceIndex: 0}, b)
	}
	w.Flush()
	return p
}
