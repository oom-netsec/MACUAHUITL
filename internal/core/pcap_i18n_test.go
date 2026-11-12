package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// writePcap arma una captura con un handshake TCP, una consulta DNS sin respuesta y un SYN sin respuesta.
func writePcap(t *testing.T, truncate bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "caso.pcap")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	at := time.Date(2026, 11, 6, 18, 0, 0, 0, time.UTC)
	macA, macB := net.HardwareAddr{0, 1, 2, 3, 4, 5}, net.HardwareAddr{0, 1, 2, 3, 4, 6}
	send := func(d time.Duration, src, dst string, l4 gopacket.SerializableLayer, extra ...gopacket.SerializableLayer) {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
		switch x := l4.(type) {
		case *layers.TCP:
			ip.Protocol = layers.IPProtocolTCP
			x.SetNetworkLayerForChecksum(ip)
		case *layers.UDP:
			ip.Protocol = layers.IPProtocolUDP
			x.SetNetworkLayerForChecksum(ip)
		}
		buf := gopacket.NewSerializeBuffer()
		ls := append([]gopacket.SerializableLayer{&layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ip, l4}, extra...)
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
			t.Fatal(err)
		}
		w.WritePacket(gopacket.CaptureInfo{Timestamp: at.Add(d), Length: len(buf.Bytes()), CaptureLength: len(buf.Bytes())}, buf.Bytes())
	}
	tcp := func(sp, dp uint16, syn, ack bool, seq uint32) *layers.TCP {
		return &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), SYN: syn, ACK: ack, Seq: seq, Window: 64240}
	}
	send(0, "10.0.0.1", "10.0.0.2", tcp(40000, 22, true, false, 100))
	send(4*time.Millisecond, "10.0.0.2", "10.0.0.1", tcp(22, 40000, true, true, 900))
	send(5*time.Millisecond, "10.0.0.1", "10.0.0.2", tcp(40000, 22, false, true, 101), gopacket.Payload(make([]byte, 300)))
	send(10*time.Millisecond, "10.0.0.1", "10.0.0.3", tcp(40001, 443, true, false, 500))
	send(11*time.Millisecond, "10.0.0.1", "10.0.0.53", &layers.UDP{SrcPort: 50001, DstPort: 53},
		&layers.DNS{ID: 7, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{{Name: []byte("mudo.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}})
	f.Close()
	if truncate {
		b, _ := os.ReadFile(p)
		os.WriteFile(p, b[:len(b)-20], 0o600)
	}
	return p
}

func TestPcapEstructuradoYEn(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewToolsServiceClient(h.conn)
	p := writePcap(t, false)
	ask := func(lang, path string) *v1.AnalyzePcapResponse {
		r, err := c.AnalyzePcap(con(t, lang), &v1.AnalyzePcapRequest{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	es := ask("", p)
	// Regresión: sin idioma, con es o con uno desconocido el texto es el de siempre.
	for _, lang := range []string{"es", "es-MX", "fr"} {
		if got := ask(lang, p).Report.Text; got != es.Report.Text {
			t.Errorf("%s difiere:\n%s", lang, got)
		}
	}
	for _, want := range []string{"Captura: " + p + "\n", "Paquetes: 5 · Bytes: ", "\n== TCP\n  Handshakes completos: 1 · RTT de handshake min/prom/máx: 4ms / 4ms / 4ms\n",
		"  SYN sin respuesta (1):\n    10.0.0.1:40001 → 10.0.0.3:443  (1 intentos)\n", "\n== DNS\n  Consultas: 1 · Respuestas: 0\n  SIN RESPUESTA  mudo.example.com A  servidor 10.0.0.53:53\n",
		"\n== Conversaciones con más bytes\n  tcp  10.0.0.1:40000 ↔ 10.0.0.2:22  3 paquetes  "} {
		if !strings.Contains(es.Report.Text, want) {
			t.Errorf("falta %q en\n%s", want, es.Report.Text)
		}
	}
	var js struct {
		Packets, Bytes int
		TCP            struct{ Handshakes, Retransmissions int }
		DNS            struct{ Queries, Responses int }
		Conversations  []struct {
			Proto, A, B    string
			Packets, Bytes int
		}
		Talkers []struct {
			IP             string
			Packets, Bytes int
		}
	}
	if err := json.Unmarshal([]byte(es.Report.Json), &js); err != nil {
		t.Fatal(err)
	}
	if es.Summary.Packets != int64(js.Packets) || es.Summary.Bytes != int64(js.Bytes) || es.Summary.File != p || es.Summary.Start != "2026-11-06T18:00:00Z" || es.Summary.DurationMs != 11 ||
		es.Tcp.Handshakes != int64(js.TCP.Handshakes) || es.Tcp.RttMaxMs != 4 || es.Tcp.FailedHandshakesTotal != 1 || es.Tcp.FailedHandshakes[0].Server != "10.0.0.3:443" || es.Tcp.FailedHandshakes[0].Count != 1 ||
		es.Dns.Queries != 1 || es.Dns.Unanswered[0].Name != "mudo.example.com" || es.Dns.Unanswered[0].Server != "10.0.0.53:53" || es.Dns.Unanswered[0].Type != "A" {
		t.Errorf("resumen: %+v %+v %+v", es.Summary, es.Tcp, es.Dns)
	}
	// Cada conversación y cada equipo, tal como el texto los imprime hoy.
	if len(es.Conversations) != len(js.Conversations) || len(es.Conversations) == 0 || len(es.TopTalkers) != len(js.Talkers) || len(es.TopTalkers) == 0 {
		t.Fatalf("conversaciones %d/%d equipos %d/%d", len(es.Conversations), len(js.Conversations), len(es.TopTalkers), len(js.Talkers))
	}
	for i, cv := range es.Conversations {
		line := fmt.Sprintf("  %-4s %s ↔ %s  %d paquetes  %d bytes\n", cv.Proto, cv.A, cv.B, cv.Packets, cv.Bytes)
		if !strings.Contains(es.Report.Text, line) || cv.Proto != js.Conversations[i].Proto || cv.Bytes != int64(js.Conversations[i].Bytes) {
			t.Errorf("conversación %d: %q", i, line)
		}
	}
	for i, tk := range es.TopTalkers {
		if line := fmt.Sprintf("  %s  %d paquetes  %d bytes\n", tk.Ip, tk.Packets, tk.Bytes); !strings.Contains(es.Report.Text, line) || tk.Ip != js.Talkers[i].IP {
			t.Errorf("equipo %d: %q", i, line)
		}
	}
	var proto = map[string]int64{}
	for _, cv := range es.Conversations {
		proto[cv.Proto] += cv.Bytes
	}
	for _, pr := range es.Protocols {
		if pr.Bytes != proto[pr.Proto] {
			t.Errorf("protocolo %+v", pr)
		}
	}
	var keys []string
	for _, s := range es.Sections {
		keys = append(keys, s.Key)
		if s.Title != i18n.Msg(i18n.Es, s.Key, s.Args) || !strings.Contains(es.Report.Text, "== "+s.Title+"\n") {
			t.Errorf("sección %+v", s)
		}
	}
	if strings.Join(keys, ",") != "pcap.section.tcp,pcap.section.dns,pcap.section.conversations,pcap.section.top_talkers" || len(es.Warnings) != 0 {
		t.Errorf("secciones %v avisos %v", keys, es.Warnings)
	}
	// en: encabezados y frases en inglés, mismos valores.
	en := ask("en-US", p)
	for _, want := range []string{"Capture: " + p + "\n", "Packets: 5 · Bytes: ", "\n== TCP\n  Complete handshakes: 1 · Handshake RTT min/avg/max: 4ms / 4ms / 4ms\n",
		"  Unanswered SYN (1):\n    10.0.0.1:40001 → 10.0.0.3:443  (1 attempts)\n", "  NO RESPONSE  mudo.example.com A  server 10.0.0.53:53\n",
		"\n== Top conversations by bytes\n  tcp  10.0.0.1:40000 ↔ 10.0.0.2:22  3 packets  ", "\n== Top talkers\n  10.0.0.1  "} {
		if !strings.Contains(en.Report.Text, want) {
			t.Errorf("en: falta %q en\n%s", want, en.Report.Text)
		}
	}
	if strings.Contains(en.Report.Text, "paquetes") || strings.Contains(en.Report.Text, "Conversaciones") || en.Report.Json != es.Report.Json || len(en.Conversations) != len(es.Conversations) || en.Sections[2].Title != "Top conversations by bytes" || en.Sections[2].Key != es.Sections[2].Key {
		t.Errorf("en:\n%s", en.Report.Text)
	}
	// Aviso con clave: captura truncada.
	tr := ask("en", writePcap(t, true))
	if len(tr.Warnings) != 1 || tr.Warnings[0].Key != "pcap.warn.truncated" || tr.Warnings[0].Args["packets"] == "" || !strings.HasPrefix(tr.Warnings[0].Text, "file truncated after ") ||
		!strings.Contains(tr.Report.Text, "WARNING: file truncated after ") {
		t.Errorf("aviso: %+v\n%s", tr.Warnings, tr.Report.Text)
	}
	trEs := ask("", writePcap(t, true))
	if !strings.Contains(trEs.Report.Text, "AVISO: archivo truncado tras ") || !strings.HasPrefix(trEs.Warnings[0].Text, "archivo truncado tras ") {
		t.Errorf("aviso es: %+v", trEs.Warnings)
	}
}
