package tools

import (
	"sort"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
)

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func flows[T any](in []T, conv func(T) *v1.PcapFlow) []*v1.PcapFlow {
	var out []*v1.PcapFlow
	for _, f := range in {
		out = append(out, conv(f))
	}
	return out
}

func dnsQueries(in []pcapan.DNSQuery) []*v1.PcapDnsQuery {
	var out []*v1.PcapDnsQuery
	for _, q := range in {
		out = append(out, &v1.PcapDnsQuery{Client: q.Client, Server: q.Server, Name: q.Name, Type: q.Type, Rcode: q.RCode, LatencyMs: ms(q.Latency)})
	}
	return out
}

func icmpEvents(in []pcapan.ICMPEvent) []*v1.PcapIcmpEvent {
	var out []*v1.PcapIcmpEvent
	for _, e := range in {
		out = append(out, &v1.PcapIcmpEvent{From: e.From, Target: e.Target, Code: int32(e.Code)})
	}
	return out
}

// pcapResponse arma la forma estructurada del informe (fase 30b) en el idioma pedido; los valores no se traducen.
func pcapResponse(loc string, r pcapan.Report) *v1.AnalyzePcapResponse {
	out := &v1.AnalyzePcapResponse{
		Summary:   &v1.PcapSummary{File: r.File, Packets: int64(r.Packets), Bytes: int64(r.Bytes), DurationMs: ms(r.Duration), Start: r.Start.UTC().Format(time.RFC3339)},
		Fragments: int64(r.Fragments),
		Tcp: &v1.PcapTcp{Handshakes: int64(r.TCP.Handshakes), RttMinMs: ms(r.TCP.HandshakeRTT.Min), RttAvgMs: ms(r.TCP.HandshakeRTT.Avg), RttMaxMs: ms(r.TCP.HandshakeRTT.Max),
			Retransmissions: int64(r.TCP.Retransmissions), ZeroWindow: int64(r.TCP.ZeroWindow), FailedHandshakesTotal: int64(r.TCP.FailedHandshakesTotal),
			FailedHandshakes: flows(r.TCP.FailedHandshakes, func(f pcapan.FailedHandshake) *v1.PcapFlow {
				return &v1.PcapFlow{Client: f.Client, Server: f.Server, Count: int64(f.Attempts)}
			}),
			Resets: flows(r.TCP.Resets, func(f pcapan.FlowCount) *v1.PcapFlow {
				return &v1.PcapFlow{Client: f.Client, Server: f.Server, Count: int64(f.Count)}
			})},
		Dns:  &v1.PcapDns{Queries: int64(r.DNS.Queries), Responses: int64(r.DNS.Responses), Errors: dnsQueries(r.DNS.Errors), Slow: dnsQueries(r.DNS.Slow), Unanswered: dnsQueries(r.DNS.Unanswered)},
		Icmp: &v1.PcapIcmp{Unreachable: icmpEvents(r.ICMP.Unreachable), TtlExceeded: icmpEvents(r.ICMP.TTLExceeded)},
	}
	by := map[string]*v1.PcapProtocol{}
	for _, c := range r.Conversations {
		out.Conversations = append(out.Conversations, &v1.PcapConversation{Proto: c.Proto, A: c.A, B: c.B, Packets: int64(c.Packets), Bytes: int64(c.Bytes)})
		p := by[c.Proto]
		if p == nil {
			p = &v1.PcapProtocol{Proto: c.Proto}
			by[c.Proto] = p
			out.Protocols = append(out.Protocols, p)
		}
		p.Packets += int64(c.Packets)
		p.Bytes += int64(c.Bytes)
	}
	sort.SliceStable(out.Protocols, func(i, j int) bool { return out.Protocols[i].Bytes > out.Protocols[j].Bytes })
	for _, t := range r.Talkers {
		out.TopTalkers = append(out.TopTalkers, &v1.PcapTalker{Ip: t.IP, Packets: int64(t.Packets), Bytes: int64(t.Bytes)})
	}
	for _, n := range r.Neighbors {
		out.Neighbors = append(out.Neighbors, &v1.PcapNeighbor{Protocol: n.Protocol, DeviceId: n.DeviceID, Port: n.Port, Platform: n.Platform, MgmtIp: n.MgmtIP, NativeVlan: uint32(n.NativeVLAN)})
	}
	for _, t := range r.TLS {
		out.Tls = append(out.Tls, &v1.PcapTlsHello{Client: t.Client, Server: t.Server, Sni: t.SNI})
	}
	for _, c := range r.ARPConflicts {
		out.ArpConflicts = append(out.ArpConflicts, &v1.PcapArpConflict{Ip: c.IP, Macs: c.MACs})
	}
	for i, w := range r.Warnings {
		pw := &v1.PcapWarning{Text: w}
		if i < len(r.WarnItems) {
			pw.Key, pw.Args, pw.Text = r.WarnItems[i].Key, r.WarnItems[i].Args, r.WarnItems[i].In(loc)
		}
		out.Warnings = append(out.Warnings, pw)
	}
	for _, s := range r.Sections() {
		out.Sections = append(out.Sections, &v1.PcapSection{Key: s.Key, Args: s.Args, Title: i18n.Msg(loc, s.Key, s.Args)})
	}
	return out
}
