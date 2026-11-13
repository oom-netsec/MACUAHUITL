package visibility

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/flows"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/gnmic"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/topo"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

type visibilitySvc struct {
	v1.UnimplementedVisibilityServiceServer
	d service.Deps
}

func (s *visibilitySvc) BuildTopology(ctx context.Context, r *v1.BuildTopologyRequest) (*v1.BuildTopologyResponse, error) {
	s.d.MarkActive()
	dir := r.Dir
	if r.JobId != "" {
		j, err := s.d.Job(r.JobId)
		if err != nil {
			return nil, err
		}
		if j.Dir == "" {
			return nil, service.Err(ctx, codes.FailedPrecondition, "visibility.err.job_empty", nil)
		}
		dir = j.Dir
	}
	if dir == "" && r.PcapPath == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "visibility.err.no_source", nil)
	}
	for _, p := range []string{dir, r.PcapPath} {
		if p != "" && !filepath.IsAbs(p) {
			return nil, service.Err(ctx, codes.InvalidArgument, "visibility.err.relative", i18n.A("path", p))
		}
	}
	s.d.Audit("visibility.topo", strings.TrimSpace(dir+" "+r.PcapPath), r.JobId)
	var devs []topo.Device
	var err error
	if dir != "" {
		if devs, err = topo.LoadPatrolDir(dir); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	var neigh []pcapan.Neighbor
	if r.PcapPath != "" {
		rep, err := pcapan.Analyze(ctx, r.PcapPath, pcapan.Options{})
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		neigh = rep.Neighbors
	}
	g := topo.Build(devs, neigh, filepath.Base(r.PcapPath))
	return &v1.BuildTopologyResponse{Report: service.Report(g, g.Text()), Svg: g.SVG()}, nil
}

// credential descifra una credencial de la bóveda; quien llama hace Destroy.
func (s *visibilitySvc) credential(ctx context.Context, id string) (vault.Credential, error) {
	v := s.d.Vault()
	if v == nil {
		return vault.Credential{}, service.Err(ctx, codes.FailedPrecondition, "visibility.err.no_vault", nil)
	}
	if id == "" {
		return vault.Credential{}, service.Err(ctx, codes.InvalidArgument, "visibility.err.no_cred", nil)
	}
	c, err := v.Get(id)
	return c, service.VaultErr(err)
}

func destroy(c vault.Credential) {
	c.Password.Destroy()
	c.Enable.Destroy()
	c.SSHKey.Destroy()
}

// snmpTarget arma el destino con la credencial y autoriza solo ese host para la ejecución.
// shortcut: gosnmp recibe las llaves como string; la copia vive lo que dura la ejecución.
func (s *visibilitySvc) snmpTarget(ctx context.Context, t *v1.SnmpTarget, id string) (snmp.Target, error) {
	if t == nil || strings.TrimSpace(t.Host) == "" || strings.HasPrefix(t.Host, "-") {
		return snmp.Target{}, service.Err(ctx, codes.InvalidArgument, "visibility.err.bad_snmp", nil)
	}
	if t.Port > 0xffff {
		return snmp.Target{}, service.Err(ctx, codes.InvalidArgument, "visibility.err.bad_port", nil)
	}
	cred, err := s.credential(ctx, t.CredentialId)
	if err != nil {
		return snmp.Target{}, err
	}
	defer destroy(cred)
	st := snmp.Target{Host: t.Host, Port: uint16(t.Port), Version: t.Version, Timeout: service.MS(t.TimeoutMs, 0), Control: s.d.Guard().Control(id)}
	if t.Version == "3" {
		st.User, st.AuthProto, st.AuthPass, st.PrivProto, st.PrivPass = cred.Username, t.AuthProtocol, string(cred.Password.Bytes()), t.PrivProtocol, string(cred.Enable.Bytes())
	} else {
		st.Community = string(cred.Password.Bytes())
	}
	if err := s.d.Guard().Allow(ctx, id, []string{t.Host}); err != nil {
		return snmp.Target{}, status.Error(codes.InvalidArgument, err.Error())
	}
	return st, nil
}

func snmpErr(err error) error {
	if errors.Is(err, snmp.ErrInvalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Unavailable, err.Error())
}

func (s *visibilitySvc) SnmpGet(ctx context.Context, r *v1.SnmpGetRequest) (*v1.SnmpGetResponse, error) {
	s.d.MarkActive()
	id := service.RunID("snmp")
	defer s.d.Guard().Revoke(id)
	t, err := s.snmpTarget(ctx, r.Target, id)
	if err != nil {
		return nil, err
	}
	s.d.Audit("visibility.snmp", t.Host, fmt.Sprintf("run=%s op=get version=%s oids=%d", id, t.Version, len(r.Oids)))
	vs, err := snmp.Get(ctx, t, r.Oids)
	if err != nil {
		return nil, snmpErr(err)
	}
	return &v1.SnmpGetResponse{Report: service.Report(vs, varsText(vs))}, nil
}

func (s *visibilitySvc) SnmpWalk(ctx context.Context, r *v1.SnmpWalkRequest) (*v1.SnmpWalkResponse, error) {
	s.d.MarkActive()
	id := service.RunID("snmp")
	defer s.d.Guard().Revoke(id)
	t, err := s.snmpTarget(ctx, r.Target, id)
	if err != nil {
		return nil, err
	}
	s.d.Audit("visibility.snmp", t.Host, fmt.Sprintf("run=%s op=walk bulk=%t version=%s oid=%s", id, r.Bulk, t.Version, r.Oid))
	vs, err := snmp.Walk(ctx, t, r.Oid, r.Bulk, int(r.Limit))
	if err != nil {
		return nil, snmpErr(err)
	}
	return &v1.SnmpWalkResponse{Report: service.Report(vs, varsText(vs))}, nil
}

func varsText(vs []snmp.Var) string {
	var sb strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&sb, "%s = %s: %v\n", v.OID, v.Type, v.Value)
	}
	return sb.String()
}

func (s *visibilitySvc) SnmpPoll(r *v1.SnmpPollRequest, st v1.VisibilityService_SnmpPollServer) error {
	s.d.MarkActive()
	ctx, cancel := context.WithTimeout(st.Context(), service.SyslogDuration(r.DurationSeconds))
	defer cancel()
	id := service.RunID("snmp")
	defer s.d.Guard().Revoke(id)
	t, err := s.snmpTarget(ctx, r.Target, id)
	if err != nil {
		return err
	}
	every := time.Duration(r.IntervalSeconds) * time.Second
	if r.IntervalSeconds <= 0 {
		every = 10 * time.Second
	}
	s.d.Audit("visibility.snmp", t.Host, fmt.Sprintf("run=%s op=poll version=%s profiles=%q interval=%s", id, t.Version, r.Profiles, every))
	err = snmp.Poll(ctx, t, r.Profiles, every, int(r.Count), func(sm snmp.Sample) {
		b, _ := json.Marshal(sm)
		st.Send(&v1.SnmpPollResponse{Json: string(b)})
	})
	if err != nil {
		return snmpErr(err)
	}
	return nil
}

// outQueue son los eventos que esperan su turno hacia el cliente.
var outQueue = 1024

// closeGrace es lo que se espera, al cerrar, a que el cliente reciba lo que quedó en cola.
var closeGrace = 2 * time.Second

// Defaults de la tasa de flujos, en datagramas/s (ráfaga 2x); solo rigen con save.
const (
	flowsRatePerSource = 1000
	flowsRateGlobal    = 5000
)

// preListenErr distingue el fallo del disco al preparar la salida (interno) de una petición inválida.
func preListenErr(ctx context.Context, err error) error {
	if errors.As(err, new(*ingest.OutputError)) {
		return service.ErrFrom(ctx, codes.Internal, err)
	}
	return service.ErrFrom(ctx, codes.InvalidArgument, err)
}

// ingestOpts pasa los campos de topes y archivo de la petición a los que comparten los receptores.
func ingestOpts(prefs service.IngestDefaults, rate, burst, rateG, burstG, queue, mb, mins, max int32, tpl, format string) service.IngestOpts {
	return service.IngestOpts{RatePerSource: rate, BurstPerSource: burst, RateGlobal: rateG, BurstGlobal: burstG, QueueSize: queue,
		RotateMB: mb, RotateMinutes: mins, MaxFiles: max, NameTemplate: tpl, Format: format, Prefs: prefs}
}

func (s *visibilitySvc) SnmpTraps(r *v1.SnmpTrapsRequest, st v1.VisibilityService_SnmpTrapsServer) error {
	s.d.MarkActive()
	lim, sink, err := ingestOpts(s.d.Settings().Ingest(), r.RatePerSource, r.BurstPerSource, r.RateGlobal, r.BurstGlobal, r.QueueSize, r.RotateMb, r.RotateMinutes, r.MaxFiles, r.NameTemplate, r.Format).
		Build(st.Context(), filepath.Join(s.d.Outputs(), "snmp-traps"), "traps_{fecha}_{hora}")
	if err != nil {
		return err
	}
	cfg := snmp.TrapConfig{Addr: r.Addr, AllowAny: r.AllowAny, Limits: lim}
	if cfg.Addr == "" {
		cfg.Addr = snmp.DefaultTrapAddr
	}
	if r.V3CredentialId != "" {
		cred, err := s.credential(st.Context(), r.V3CredentialId)
		if err != nil {
			return err
		}
		cfg.V3 = &snmp.Target{User: cred.Username, AuthProto: r.AuthProtocol, AuthPass: string(cred.Password.Bytes()), PrivProto: r.PrivProtocol, PrivPass: string(cred.Enable.Bytes())}
		destroy(cred)
	}
	ctx, cancel := context.WithTimeout(st.Context(), service.SyslogDuration(r.DurationSeconds))
	defer cancel()
	// Un cliente atascado no frena al receptor ni al archivo (ver service.Pump).
	pump := service.NewPump(st.Send, outQueue)
	send := pump.Send
	var outDir string
	if r.Save {
		outDir = sink.Dir
		sink.OnOpen = func(p string) { send(&v1.SnmpTrapsResponse{RotatedPath: p}) }
		sink.OnRemove = func(p string) {
			s.d.Audit("visibility.traps.retencion", p, "deleted for exceeding max_files="+strconv.Itoa(sink.MaxFiles))
		}
		cfg.Sink = &sink
	}
	var n int
	var last ingest.Drops
	listening := false
	cfg.OnListening = func(a string) {
		listening = true
		s.d.Audit("visibility.traps", a, fmt.Sprintf("all=%t v3=%t output=%s ", r.AllowAny, cfg.V3 != nil, outDir)+service.IngestDetail(lim, sink, r.Save))
		send(&v1.SnmpTrapsResponse{Listening: a, OutputPath: outDir})
	}
	cfg.OnTrap = func(t snmp.Trap) {
		n++
		b, _ := json.Marshal(t)
		send(&v1.SnmpTrapsResponse{Json: string(b)})
	}
	cfg.OnDrops = func(d ingest.Drops) {
		last = d
		send(&v1.SnmpTrapsResponse{Drops: service.DropsProto(d)})
	}
	err = snmp.ListenTraps(ctx, cfg)
	lost := pump.Close(closeGrace)
	if !listening { // dirección, puerto o credencial rechazados antes de abrir el socket, o la carpeta de salida
		return preListenErr(st.Context(), err)
	}
	s.d.Audit("visibility.traps.done", cfg.Addr, fmt.Sprintf("traps=%d drops=%d per_origin=%d global=%d queue_full=%d lost_on_interface=%d", n, last.Total, last.PorOrigen, last.Global, last.ColaLlena, lost))
	if err != nil {
		return service.ErrFrom(st.Context(), codes.Unavailable, err)
	}
	return nil
}

func (s *visibilitySvc) Flows(r *v1.FlowsRequest, st v1.VisibilityService_FlowsServer) error {
	s.d.MarkActive()
	// Un exportador NetFlow/IPFIX manda muchos más datagramas que un equipo syslog: defaults más altos que los de syslog y traps.
	fo := ingestOpts(s.d.Settings().Ingest(), r.RatePerSource, r.BurstPerSource, r.RateGlobal, r.BurstGlobal, r.QueueSize, r.RotateMb, r.RotateMinutes, r.MaxFiles, r.NameTemplate, r.Format)
	fo.DefPerSource, fo.DefGlobal = flowsRatePerSource, flowsRateGlobal
	lim, sink, err := fo.Build(st.Context(), filepath.Join(s.d.Outputs(), "flows"), "flujos_{fecha}_{hora}")
	if err != nil {
		return err
	}
	cfg := flows.Config{Addr: r.Addr, AllowAny: r.AllowAny, Top: int(r.Top), Every: time.Duration(r.EverySeconds) * time.Second, Limits: lim}
	if cfg.Addr == "" {
		cfg.Addr = flows.DefaultAddr
	}
	ctx, cancel := context.WithTimeout(st.Context(), service.SyslogDuration(r.DurationSeconds))
	defer cancel()
	pump := service.NewPump(st.Send, outQueue)
	send := pump.Send
	var outDir string
	if r.Save {
		outDir = sink.Dir
		sink.OnOpen = func(p string) { send(&v1.FlowsResponse{RotatedPath: p}) }
		sink.OnRemove = func(p string) {
			s.d.Audit("visibility.flows.retencion", p, "deleted for exceeding max_files="+strconv.Itoa(sink.MaxFiles))
		}
		cfg.Sink = &sink
	}
	snap := func(sn flows.Snapshot, final bool) {
		b, _ := json.Marshal(sn)
		send(&v1.FlowsResponse{Json: string(b), Final: final})
	}
	var last ingest.Drops
	listening := false
	cfg.OnListening = func(a string) {
		listening = true
		detail := "sin tope de tasa (sin archivo)" // el tope protege la escritura: sin save no se aplica
		if r.Save {
			detail = service.IngestDetail(lim, sink, true)
		}
		s.d.Audit("visibility.flows", a, fmt.Sprintf("all=%t output=%s ", r.AllowAny, outDir)+detail)
		send(&v1.FlowsResponse{Listening: a, OutputPath: outDir})
	}
	cfg.OnSnapshot = func(sn flows.Snapshot) { snap(sn, false) }
	cfg.OnDrops = func(d ingest.Drops) {
		last = d
		send(&v1.FlowsResponse{Drops: service.DropsProto(d)})
	}
	sn, err := flows.Listen(ctx, cfg)
	if !listening {
		pump.Close(closeGrace)
		return preListenErr(st.Context(), err)
	}
	snap(sn, true)
	lost := pump.Close(closeGrace)
	s.d.Audit("visibility.flows.done", cfg.Addr, fmt.Sprintf("flows=%d bytes=%d errors=%d drops=%d per_origin=%d global=%d queue_full=%d lost_on_interface=%d", sn.Flows, sn.Bytes, sn.Errors, last.Total, last.PorOrigen, last.Global, last.ColaLlena, lost))
	if err != nil {
		return service.ErrFrom(st.Context(), codes.Unavailable, err)
	}
	return nil
}

// gnmiTarget arma el destino con la credencial y autoriza solo ese host.
func (s *visibilitySvc) gnmiTarget(ctx context.Context, t *v1.GnmiTarget, id string) (gnmic.Target, error) {
	if t == nil || strings.TrimSpace(t.Host) == "" || strings.HasPrefix(t.Host, "-") || t.Port > 0xffff {
		return gnmic.Target{}, service.Err(ctx, codes.InvalidArgument, "visibility.err.bad_gnmi", nil)
	}
	gt := gnmic.Target{Host: t.Host, Port: uint16(t.Port), ServerName: t.ServerName, Timeout: service.MS(t.TimeoutMs, 0)}
	if t.CaPath != "" {
		if !filepath.IsAbs(t.CaPath) {
			return gnmic.Target{}, service.Err(ctx, codes.InvalidArgument, "visibility.err.ca_relative", nil)
		}
		b, err := os.ReadFile(t.CaPath)
		if err != nil {
			return gnmic.Target{}, status.Error(codes.InvalidArgument, err.Error())
		}
		gt.CA = b
	}
	if t.CredentialId != "" {
		cred, err := s.credential(ctx, t.CredentialId)
		if err != nil {
			return gnmic.Target{}, err
		}
		gt.Username, gt.Password = cred.Username, string(cred.Password.Bytes())
		destroy(cred)
	}
	if err := s.d.Guard().Allow(ctx, id, []string{t.Host}); err != nil {
		return gnmic.Target{}, status.Error(codes.InvalidArgument, err.Error())
	}
	return gt, nil
}

func gnmiErr(err error) error {
	if errors.Is(err, gnmic.ErrInvalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Unavailable, err.Error())
}

func (s *visibilitySvc) GnmiGet(ctx context.Context, r *v1.GnmiGetRequest) (*v1.GnmiGetResponse, error) {
	s.d.MarkActive()
	id := service.RunID("gnmi")
	defer s.d.Guard().Revoke(id)
	t, err := s.gnmiTarget(ctx, r.Target, id)
	if err != nil {
		return nil, err
	}
	s.d.Audit("visibility.gnmi", t.Host, fmt.Sprintf("run=%s op=get paths=%q", id, r.Paths))
	ups, err := gnmic.Get(ctx, gnmic.Dialer(s.d.Guard().DialerFor(id)), t, r.Paths, r.Encoding)
	if err != nil {
		return nil, gnmiErr(err)
	}
	return &v1.GnmiGetResponse{Report: service.Report(ups, "")}, nil
}

func (s *visibilitySvc) GnmiSubscribe(r *v1.GnmiSubscribeRequest, st v1.VisibilityService_GnmiSubscribeServer) error {
	s.d.MarkActive()
	ctx, cancel := context.WithTimeout(st.Context(), service.SyslogDuration(r.DurationSeconds))
	defer cancel()
	id := service.RunID("gnmi")
	defer s.d.Guard().Revoke(id)
	t, err := s.gnmiTarget(ctx, r.Target, id)
	if err != nil {
		return err
	}
	s.d.Audit("visibility.gnmi", t.Host, fmt.Sprintf("run=%s op=subscribe mode=%s paths=%q", id, r.Mode, r.Paths))
	err = gnmic.Subscribe(ctx, gnmic.Dialer(s.d.Guard().DialerFor(id)), t, r.Paths, r.Mode, time.Duration(r.IntervalSeconds)*time.Second, func(u gnmic.Update) {
		b, _ := json.Marshal(u)
		st.Send(&v1.GnmiSubscribeResponse{Json: string(b)})
	})
	if err != nil {
		return gnmiErr(err)
	}
	return nil
}

// Module registra el servicio Visibility.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterVisibilityServiceServer(s, &visibilitySvc{d: d})
}
