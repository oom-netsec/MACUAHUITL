package calc

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/calc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// calcSvc, como aclSvc, no toca la bóveda, la red ni la auditoría: calcula sobre lo
// que escribe el ingeniero.
type calcSvc struct {
	v1.UnimplementedCalcServiceServer
}

func calcResult[T calc.Reporter](v T, err error) (*v1.CalcResult, error) {
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	b, _ := json.Marshal(v)
	rep := v.Report()
	out := &v1.CalcResult{Json: string(b), Text: rep.Text(), Notes: rep.Notes}
	for _, t := range rep.Tables {
		pt := &v1.CalcTable{Title: t.Title, Head: t.Head}
		for _, row := range t.Rows {
			pt.Rows = append(pt.Rows, &v1.CalcRow{Cells: row})
		}
		out.Tables = append(out.Tables, pt)
	}
	return out, nil
}

func (calcSvc) Subnet(_ context.Context, r *v1.SubnetRequest) (*v1.SubnetResponse, error) {
	res, err := calcResult(calc.Subnet(r.Prefix))
	return &v1.SubnetResponse{Result: res}, err
}

func (calcSvc) Vlsm(_ context.Context, r *v1.VlsmRequest) (*v1.VlsmResponse, error) {
	needs := make([]calc.Need, 0, len(r.Needs))
	for _, n := range r.Needs {
		needs = append(needs, calc.Need{Name: n.Name, Hosts: n.Hosts})
	}
	res, err := calcResult(calc.VLSM(r.Network, needs))
	return &v1.VlsmResponse{Result: res}, err
}

func (calcSvc) Summarize(_ context.Context, r *v1.SummarizeRequest) (*v1.SummarizeResponse, error) {
	res, err := calcResult(calc.Summarize(r.Prefixes))
	return &v1.SummarizeResponse{Result: res}, err
}

func (calcSvc) Wildcard(_ context.Context, r *v1.WildcardRequest) (*v1.WildcardResponse, error) {
	res, err := calcResult(calc.Wildcard(r.Address, r.Value))
	return &v1.WildcardResponse{Result: res}, err
}

func (calcSvc) Ipv6(_ context.Context, r *v1.Ipv6Request) (*v1.Ipv6Response, error) {
	res, err := calcResult(calc.IPv6(r.Address, r.Mac))
	return &v1.Ipv6Response{Result: res}, err
}

func (calcSvc) Mtu(_ context.Context, r *v1.MtuRequest) (*v1.MtuResponse, error) {
	res, err := calcResult(calc.MTU(int(min(r.Physical, 1<<20)), r.Layers, r.InnerIpv6))
	return &v1.MtuResponse{Result: res}, err
}

func (calcSvc) Tcp(_ context.Context, r *v1.TcpRequest) (*v1.TcpResponse, error) {
	res, err := calcResult(calc.TCP(r.Bandwidth, r.RttMs, r.Window, r.LossPercent, int(min(r.Mss, 1<<20))))
	return &v1.TcpResponse{Result: res}, err
}

func (calcSvc) Dscp(_ context.Context, r *v1.DscpRequest) (*v1.DscpResponse, error) {
	res, err := calcResult(calc.DSCP(r.Query, r.Field))
	return &v1.DscpResponse{Result: res}, err
}

func (calcSvc) Optics(_ context.Context, r *v1.OpticsRequest) (*v1.OpticsResponse, error) {
	var res *v1.CalcResult
	var err error
	if r.Convert != "" {
		res, err = calcResult(calc.Power(r.Convert))
	} else {
		res, err = calcResult(calc.Optics(calc.OpticsInput{TxDbm: r.TxDbm, RxSensDbm: r.RxSensitivityDbm, RxOverloadDbm: r.RxOverloadDbm, Km: r.Km,
			Fiber: r.Fiber, LossPerKm: r.LossPerKm, Connectors: int(min(r.Connectors, 1000)), ConnectorLoss: r.ConnectorLossDb,
			Splices: int(min(r.Splices, 1000)), SpliceLoss: r.SpliceLossDb, MarginDb: r.MarginDb}))
	}
	return &v1.OpticsResponse{Result: res}, err
}

func (calcSvc) Bgp(_ context.Context, r *v1.BgpRequest) (*v1.BgpResponse, error) {
	routes := make([]calc.Route, 0, len(r.Routes))
	for _, p := range r.Routes {
		routes = append(routes, calc.Route{Name: p.Name, Weight: p.Weight, LocalPref: p.LocalPref, Local: p.LocallyOriginated, ASPath: p.AsPath,
			Origin: p.Origin, MED: p.Med, EBGP: p.Ebgp, IGPMetric: p.IgpMetric, RouterID: p.RouterId, OriginatorID: p.OriginatorId,
			ClusterListLen: int(min(p.ClusterListLength, 1000)), Neighbor: p.Neighbor, AgeSeconds: p.AgeSeconds, NextHopUnreachable: p.NextHopUnreachable})
	}
	res, err := calcResult(calc.BGPBestPath(routes, calc.BGPOptions{AlwaysCompareMED: r.AlwaysCompareMed, DeterministicMED: r.DeterministicMed,
		MultipathRelax: r.MultipathRelax, MaximumPaths: int(min(r.MaximumPaths, 64))}))
	return &v1.BgpResponse{Result: res}, err
}

// Module registra el servicio Calc.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterCalcServiceServer(s, calcSvc{})
}
