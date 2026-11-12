package diag

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/ifaces"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

type diagSvc struct {
	v1.UnimplementedDiagServiceServer
	d service.Deps
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
		return status.Error(codes.InvalidArgument, "herramienta no indicada")
	}
	req := diag.Request{Tool: tool, Options: r.Options, OutputDir: r.OutputDir}
	for _, t := range r.Targets {
		req.Targets = append(req.Targets, t.GetAddress())
	}
	factory := req.OutputDir == ""
	if factory {
		req.OutputDir = filepath.Join(s.d.Outputs(), "diag")
	} else if dir, err := service.CheckOutputs(req.OutputDir, s.d.Settings(), true); err != nil { // la misma validación que Ajustes
		return err
	} else {
		req.OutputDir = dir
	}
	bin, argv, err := diag.Build(req)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if factory { // la de fábrica la crea el núcleo (0700), ya con la petición válida
		if err := os.MkdirAll(req.OutputDir, 0o700); err != nil {
			return status.Errorf(codes.InvalidArgument, "carpeta de salida: %v", err)
		}
	}
	s.d.Audit("diag.run", string(tool), fmt.Sprintf("%s %q", bin, argv))
	res, err := diag.Runner{LookPath: s.d.DiagLookPath()}.Run(st.Context(), req, func(line string) {
		st.Send(&v1.RunResponse{OutputLine: line})
	})
	code := res.ExitCode
	if err != nil {
		code = -1
	}
	// Lo que corrió de verdad: binario resuelto (tracepath por traceroute) y argv completo, entrecomillado.
	s.d.Audit("diag.done", string(tool), fmt.Sprintf("exit=%d bin=%s argv=%q output=%s", code, res.Bin, res.Argv, res.OutputPath))
	if errors.Is(err, diag.ErrNotInstalled) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if err != nil && st.Context().Err() == nil {
		return status.Error(codes.Internal, err.Error())
	}
	return st.Send(&v1.RunResponse{Done: true, ExitCode: int32(res.ExitCode), OutputPath: res.OutputPath})
}

// ListInterfaces lee las interfaces del sistema; no envía nada a la red.
func (s *diagSvc) ListInterfaces(context.Context, *v1.ListInterfacesRequest) (*v1.ListInterfacesResponse, error) {
	ifs, err := ifaces.List()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
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
	v1.RegisterDiagServiceServer(s, &diagSvc{d: d})
}
