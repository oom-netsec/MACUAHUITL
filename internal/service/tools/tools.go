package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/dnsq"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/syslogd"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tlsinspect"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

type toolsSvc struct {
	v1.UnimplementedToolsServiceServer
	d service.Deps
}

var resolvConf = "/etc/resolv.conf" // las pruebas lo apuntan a un archivo propio

func (s *toolsSvc) AnalyzePcap(ctx context.Context, r *v1.AnalyzePcapRequest) (*v1.AnalyzePcapResponse, error) {
	s.d.MarkActive()
	if !filepath.IsAbs(r.Path) {
		return nil, status.Error(codes.InvalidArgument, "la ruta de la captura debe ser absoluta")
	}
	s.d.Audit("tools.pcap", r.Path, "")
	rep, err := pcapan.Analyze(ctx, r.Path, pcapan.Options{Top: int(r.Top), SlowDNS: service.MS(r.SlowDnsMs, 0)})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &v1.AnalyzePcapResponse{Report: service.Report(rep, rep.Text())}, nil
}

var deepModes = map[v1.DnsMode]bool{v1.DnsMode_DNS_MODE_TRACE: true, v1.DnsMode_DNS_MODE_ZONE: true, v1.DnsMode_DNS_MODE_DNSSEC: true}

// Dns aplica la política de salida (spec §6.1): en modo ligero solo se contacta a
// los servidores escritos; en profundo, cualquier IP pero solo en 53/853/443. Cada
// servidor contactado queda en auditoría.
func (s *toolsSvc) Dns(ctx context.Context, r *v1.DnsRequest) (*v1.DnsResponse, error) {
	s.d.MarkActive()
	if r.Mode == v1.DnsMode_DNS_MODE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "modo DNS no indicado")
	}
	if deepModes[r.Mode] && !r.Deep {
		return nil, status.Error(codes.FailedPrecondition, "este modo contacta raíces y autoritativos: requiere activar el modo profundo")
	}
	if r.Mode != v1.DnsMode_DNS_MODE_EXPOSURE && strings.TrimSpace(r.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "nombre no indicado")
	}
	qtype, err := dnsq.ParseType(r.Type)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	var servers []dnsq.Server
	switch {
	case len(r.Servers) > 0:
		for _, v := range r.Servers {
			sv, err := dnsq.ParseServer(v)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			servers = append(servers, sv)
		}
	case r.Deep: // los públicos son terceros: solo con autorización explícita
		servers = append(servers, dnsq.PublicResolvers...)
	default:
		if servers, err = dnsq.SystemResolvers(resolvConf); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}
	id := service.RunID("dns")
	defer s.d.Guard().Revoke(id)
	hosts := make([]string, 0, len(servers))
	for _, sv := range servers {
		hosts = append(hosts, sv.Host)
	}
	if !deepModes[r.Mode] {
		if err := s.d.Guard().Allow(ctx, id, hosts); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if r.Deep {
		s.d.Guard().AllowAnyOnPorts(id, []uint16{53, 853, 443})
	}
	s.d.Audit("dns.run", r.Name, fmt.Sprintf("run=%s modo=%s tipo=%s profundo=%t servidores=%q", id, r.Mode, dns(r.Type), r.Deep, hosts))
	o := dnsq.Options{Timeout: service.MS(r.TimeoutMs, 0), DNSSEC: r.Dnssec, OnContact: func(srv string) { s.d.Audit("dns.contact", srv, id) }}
	d := dnsq.Dialer(s.d.Guard().DialerFor(id))
	var out any
	switch r.Mode {
	case v1.DnsMode_DNS_MODE_QUERY:
		out = dnsq.Compare(ctx, d, servers, r.Name, qtype, o)
	case v1.DnsMode_DNS_MODE_TRANSPORT:
		out = dnsq.CheckTransport(ctx, d, servers[0], r.Name, o)
	case v1.DnsMode_DNS_MODE_HYGIENE:
		out = dnsq.CheckHygiene(ctx, d, servers[0], r.Name, dnsq.HygieneOptions{DKIMSelector: r.DkimSelector}, o)
	case v1.DnsMode_DNS_MODE_EXPOSURE:
		out = dnsq.CheckExposure(ctx, d, servers[0], o)
	case v1.DnsMode_DNS_MODE_TRACE:
		out, err = dnsq.Trace(ctx, d, r.Name, qtype, dnsq.RootServers, o)
	case v1.DnsMode_DNS_MODE_ZONE:
		out, err = dnsq.CheckZone(ctx, d, r.Name, dnsq.RootServers, o)
	case v1.DnsMode_DNS_MODE_DNSSEC:
		out, err = dnsq.CheckDNSSEC(ctx, d, r.Name, dnsq.RootServers, dnsq.RootAnchors, o)
	default:
		return nil, status.Error(codes.InvalidArgument, "modo DNS desconocido")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &v1.DnsResponse{Report: service.Report(out, "")}, nil
}

func dns(t string) string {
	if t == "" {
		return "A"
	}
	return strings.ToUpper(t)
}

func (s *toolsSvc) InspectTls(ctx context.Context, r *v1.InspectTlsRequest) (*v1.InspectTlsResponse, error) {
	s.d.MarkActive()
	if strings.TrimSpace(r.Host) == "" || strings.HasPrefix(r.Host, "-") {
		return nil, status.Error(codes.InvalidArgument, "host inválido")
	}
	port := uint16(443)
	if r.Port > 0xffff {
		return nil, status.Error(codes.InvalidArgument, "puerto inválido")
	} else if r.Port != 0 {
		port = uint16(r.Port)
	}
	id := service.RunID("tls")
	defer s.d.Guard().Revoke(id)
	if err := s.d.Guard().Allow(ctx, id, []string{r.Host}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.d.Audit("tools.tls", fmt.Sprintf("%s:%d", r.Host, port), "sni="+r.Sni)
	rep, err := tlsinspect.Inspect(ctx, tlsinspect.Dialer(s.d.Guard().DialerFor(id)), r.Host, port, r.Sni, tlsinspect.Options{Timeout: service.MS(r.TimeoutMs, 0)})
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &v1.InspectTlsResponse{Report: service.Report(rep, "")}, nil
}

// Syslog escucha hasta que el cliente cancele o se cumpla la duración.
func (s *toolsSvc) Syslog(r *v1.SyslogRequest, st v1.ToolsService_SyslogServer) error {
	s.d.MarkActive()
	addr := r.Addr
	if addr == "" {
		addr = "127.0.0.1:5514"
	}
	if err := syslogd.ValidateAddr(addr, r.AllowAny); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	lim, sink, err := service.IngestOpts{RatePerSource: r.RatePerSource, BurstPerSource: r.BurstPerSource, RateGlobal: r.RateGlobal, BurstGlobal: r.BurstGlobal, QueueSize: r.QueueSize,
		RotateMB: r.RotateMb, RotateMinutes: r.RotateMinutes, MaxFiles: r.MaxFiles, NameTemplate: r.NameTemplate, Format: r.Format, Prefs: s.d.Settings().Ingest()}.Build(filepath.Join(s.d.Outputs(), "syslog"), defTemplate)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(st.Context(), service.SyslogDuration(r.DurationSeconds))
	defer cancel()
	// Un cliente atascado no frena al receptor ni al archivo (ver service.Pump).
	pump := service.NewPump(st.Send, outQueue)
	send := pump.Send
	cfg := syslogd.Config{Addr: addr, Proto: r.Protocol, AllowAny: r.AllowAny, Limits: lim}
	var outDir string
	if r.Save {
		outDir = sink.Dir
		sink.OnOpen = func(p string) { send(&v1.SyslogResponse{RotatedPath: p}) }
		sink.OnRemove = func(p string) {
			s.d.Audit("tools.syslog.retencion", p, "borrado por exceder max_archivos="+strconv.Itoa(sink.MaxFiles))
		}
		cfg.Sink = &sink
	}
	var n int
	var last syslogd.Drops
	cfg.OnListening = func(a string) {
		s.d.Audit("tools.syslog", a, fmt.Sprintf("proto=%s todas=%t salida=%s ", cfg.Proto, r.AllowAny, outDir)+service.IngestDetail(lim, sink, r.Save))
		send(&v1.SyslogResponse{Listening: a, OutputPath: outDir})
	}
	cfg.OnMessage = func(m syslogd.Message) {
		n++
		b, _ := json.Marshal(m)
		send(&v1.SyslogResponse{Json: string(b)})
	}
	cfg.OnDrops = func(d syslogd.Drops) {
		last = d
		send(&v1.SyslogResponse{Drops: service.DropsProto(d)})
	}
	err = syslogd.Listen(ctx, cfg)
	lost := pump.Close(closeGrace)
	s.d.Audit("tools.syslog.done", addr, fmt.Sprintf("mensajes=%d descartes=%d por_origen=%d global=%d cola_llena=%d perdidos_en_la_interfaz=%d", n, last.Total, last.PorOrigen, last.Global, last.ColaLlena, lost))
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	return nil
}

// outQueue son los eventos que esperan su turno hacia el cliente.
var outQueue = 1024

// closeGrace es lo que se espera, al cerrar, a que el cliente reciba lo que quedó en cola.
var closeGrace = 2 * time.Second

// defTemplate es el nombre por omisión de los archivos de syslog.
const defTemplate = "syslog_{fecha}_{hora}"

// Module registra el servicio Tools.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterToolsServiceServer(s, &toolsSvc{d: d})
}
