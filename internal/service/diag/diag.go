package diag

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/ifaces"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

type diagSvc struct {
	v1.UnimplementedDiagServiceServer
	d    service.Deps
	mu   sync.Mutex
	runs map[string]*liveRun // ejecuciones vivas por run_id
}

// liveRun es lo único que StopRun puede hacer con una ejecución: pedirle que pare.
type liveRun struct {
	stop chan struct{}
	once sync.Once
}

func (l *liveRun) halt() { l.once.Do(func() { close(l.stop) }) }

func (s *diagSvc) liveRuns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runs)
}

// StopRun detiene una ejecución en curso sin cortar su stream: Run manda el resumen y done. No expone su salida.
func (s *diagSvc) StopRun(ctx context.Context, r *v1.StopRunRequest) (*v1.StopRunResponse, error) {
	s.mu.Lock()
	l := s.runs[r.RunId]
	s.mu.Unlock()
	if l == nil {
		return nil, service.Err(ctx, codes.NotFound, "diag.err.no_run", nil)
	}
	l.halt()
	s.d.Audit("diag.stop", r.RunId, "")
	return &v1.StopRunResponse{}, nil
}

var diagTools = map[v1.DiagTool]diag.Tool{
	v1.DiagTool_DIAG_TOOL_PING: diag.Ping, v1.DiagTool_DIAG_TOOL_TRACEROUTE: diag.Traceroute, v1.DiagTool_DIAG_TOOL_NMAP: diag.Nmap,
	v1.DiagTool_DIAG_TOOL_IPERF3: diag.Iperf3, v1.DiagTool_DIAG_TOOL_PCAP: diag.Pcap,
}

// Run ejecuta la herramienta y transmite su salida. Si el cliente se desconecta, el
// contexto del stream cancela el proceso. Cada ejecución queda en auditoría con su argv.
func (s *diagSvc) Run(r *v1.RunRequest, st v1.DiagService_RunServer) error {
	s.d.MarkActive()
	tool, ok := diagTools[r.Tool]
	if !ok {
		return service.Err(st.Context(), codes.InvalidArgument, "diag.err.no_tool", nil)
	}
	req := diag.Request{Tool: tool, Options: r.Options, OutputDir: r.OutputDir}
	for _, t := range r.Targets {
		req.Targets = append(req.Targets, t.GetAddress())
	}
	factory := req.OutputDir == ""
	if factory {
		req.OutputDir = filepath.Join(s.d.Outputs(), "diag")
	} else if dir, err := service.CheckOutputs(req.OutputDir, s.d.Settings(), true); err != nil { // la misma validación que Ajustes
		return service.ErrFrom(st.Context(), codes.InvalidArgument, err)
	} else {
		req.OutputDir = dir
	}
	bin, argv, err := diag.Build(req)
	if err != nil {
		return service.ErrFrom(st.Context(), codes.InvalidArgument, err)
	}
	if factory { // la de fábrica la crea el núcleo (0700), ya con la petición válida
		if err := os.MkdirAll(req.OutputDir, 0o700); err != nil {
			return service.ErrFrom(st.Context(), codes.InvalidArgument, i18n.Wrap("ingest.err.out_dir", err, nil))
		}
	}
	sweep := ""
	if p, err := diag.Plan(req); err == nil && p.Sweep != nil {
		sweep = fmt.Sprintf(" sweep=%d-%d/%d", p.Sweep.Start, p.Sweep.End, p.Sweep.Step)
	}
	id, live := service.NewID(), &liveRun{stop: make(chan struct{})}
	s.d.Audit("diag.run", string(tool), fmt.Sprintf("run=%s %s %q%s", id, bin, argv, sweep))
	s.mu.Lock()
	if s.runs == nil {
		s.runs = map[string]*liveRun{}
	}
	s.runs[id] = live
	s.mu.Unlock()
	defer func() { // por cualquier camino de salida
		s.mu.Lock()
		delete(s.runs, id)
		s.mu.Unlock()
	}()
	if err := st.Send(&v1.RunResponse{RunId: id}); err != nil {
		return err
	}
	run := diag.Runner{LookPath: s.d.DiagLookPath(), Stop: live.stop, OnSweep: func(p diag.SweepPoint) {
		st.Send(&v1.RunResponse{SweepPoint: &v1.SweepPoint{Size: int32(p.Size), Sent: p.Sent, Received: p.Received, Result: p.Result}})
	}}
	res, err := run.Run(st.Context(), req, func(line string) {
		st.Send(&v1.RunResponse{OutputLine: line})
		if w := avisoNmap(i18n.Locale(st.Context()), tool, req.Options, line); w != "" {
			st.Send(&v1.RunResponse{OutputLine: w})
		}
	})
	code := res.ExitCode
	if err != nil {
		code = -1
	}
	// Lo que corrió de verdad: binario resuelto (tracepath por traceroute) y argv completo, entrecomillado.
	s.d.Audit("diag.done", string(tool), fmt.Sprintf("run=%s exit=%d bin=%s argv=%q output=%s%s", id, code, res.Bin, res.Argv, res.OutputPath, sweep))
	if errors.Is(err, diag.ErrNotInstalled) {
		return service.ErrFrom(st.Context(), codes.FailedPrecondition, err)
	}
	if err != nil && st.Context().Err() == nil {
		return service.ErrFrom(st.Context(), codes.Internal, err)
	}
	final := &v1.RunResponse{Done: true, ExitCode: int32(res.ExitCode), OutputPath: res.OutputPath}
	if p := res.Ping; p != nil {
		final.PingSummary = &v1.PingSummary{Sent: p.Sent, Received: p.Received, LossPct: p.LossPct, MinMs: p.MinMs, AvgMs: p.AvgMs, MaxMs: p.MaxMs, MdevMs: p.MdevMs}
	}
	return st.Send(final)
}

// ListInterfaces lee las interfaces del sistema; no envía nada a la red.
func (s *diagSvc) ListInterfaces(ctx context.Context, _ *v1.ListInterfacesRequest) (*v1.ListInterfacesResponse, error) {
	ifs, err := ifaces.List()
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.Internal, err)
	}
	r := &v1.ListInterfacesResponse{}
	for _, i := range ifs {
		r.Interfaces = append(r.Interfaces, &v1.NetInterface{Name: i.Name, Up: i.Up, Loopback: i.Loopback, Addresses: i.Addresses, HardwareAddr: i.HardwareAddr})
	}
	return r, nil
}

// Module registra el servicio Diag.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterDiagServiceServer(s, &diagSvc{d: d, runs: map[string]*liveRun{}})
}

// avisoNmap devuelve el aviso de 0 hosts up (vacío si no toca); solo viaja por el flujo, no va al archivo de salida.
// Sin aviso con scan=ping ni con skip_discovery (la sugerencia no aplicaría) ni con «0 IP addresses» (nombre sin resolver: -Pn no ayuda).
func avisoNmap(loc string, tool diag.Tool, opts map[string]string, line string) string {
	if tool != diag.Nmap || !diag.NmapZeroUp(line) || strings.Contains(line, " 0 IP addresses") ||
		opts["scan"] == "ping" || opts["skip_discovery"] == "true" {
		return ""
	}
	return i18n.Msg(loc, "diag.warn.zero_up", nil)
}
