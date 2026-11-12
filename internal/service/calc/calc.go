package calc

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/calc"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	full := v.Report()
	out := &v1.CalcResult{Json: string(b), Text: full.Text(), Notes: full.Notes}
	for _, t := range full.Tables {
		pt := &v1.CalcTable{Title: t.Title, Head: t.Head, TitleKey: t.TitleKey, TitleArgs: t.TitleArgs}
		for _, hk := range t.HeadKeys {
			pt.Columns = append(pt.Columns, &v1.CalcColumn{Key: hk})
		}
		for j, row := range t.Rows {
			pr := &v1.CalcRow{Cells: row}
			if j < len(t.RowKeys) {
				pr.LabelKey, pr.LabelArgs = t.RowKeys[j], t.RowArgs[j]
			}
			pt.Rows = append(pt.Rows, pr)
		}
		out.Tables = append(out.Tables, pt)
	}
	for _, n := range full.NoteItems {
		out.NotesStructured = append(out.NotesStructured, &v1.CalcNote{Key: n.Key, Args: n.Args})
	}
	return out, nil
}

// localize pone en el idioma del contexto los textos de la respuesta (título, encabezados, etiquetas de fila,
// notas y el texto completo) a partir de sus claves. Con es no toca nada: el texto es el de siempre. Los valores
// (direcciones, cifras, nombres) no se traducen.
func localize(ctx context.Context, r *v1.CalcResult) *v1.CalcResult {
	loc := i18n.Locale(ctx)
	if r == nil || loc != i18n.En {
		return r
	}
	rep := calc.Report{}
	for _, t := range r.Tables {
		if t.TitleKey != "" {
			t.Title = i18n.Msg(loc, t.TitleKey, t.TitleArgs)
		}
		for i, c := range t.Columns {
			if i < len(t.Head) {
				t.Head[i] = i18n.Msg(loc, c.Key, nil)
			}
		}
		ct := calc.Table{Title: t.Title, Head: t.Head}
		for _, row := range t.Rows {
			if row.LabelKey != "" && len(row.Cells) > 0 {
				row.Cells[0] = i18n.Msg(loc, row.LabelKey, row.LabelArgs)
			}
			ct.Rows = append(ct.Rows, row.Cells)
		}
		rep.Tables = append(rep.Tables, ct)
	}
	for i, n := range r.NotesStructured {
		if i < len(r.Notes) {
			r.Notes[i] = i18n.Msg(loc, n.Key, n.Args)
		}
	}
	rep.Notes = r.Notes
	r.Text = rep.Text()
	return r
}

func (calcSvc) Subnet(ctx context.Context, r *v1.SubnetRequest) (*v1.SubnetResponse, error) {
	res, err := calcResult(calc.Subnet(r.Prefix))
	return &v1.SubnetResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Vlsm(ctx context.Context, r *v1.VlsmRequest) (*v1.VlsmResponse, error) {
	needs := make([]calc.Need, 0, len(r.Needs))
	for _, n := range r.Needs {
		needs = append(needs, calc.Need{Name: n.Name, Hosts: n.Hosts})
	}
	res, err := calcResult(calc.VLSM(r.Network, needs))
	return &v1.VlsmResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Summarize(ctx context.Context, r *v1.SummarizeRequest) (*v1.SummarizeResponse, error) {
	res, err := calcResult(calc.Summarize(r.Prefixes))
	return &v1.SummarizeResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Wildcard(ctx context.Context, r *v1.WildcardRequest) (*v1.WildcardResponse, error) {
	res, err := calcResult(calc.Wildcard(r.Address, r.Value))
	return &v1.WildcardResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Ipv6(ctx context.Context, r *v1.Ipv6Request) (*v1.Ipv6Response, error) {
	res, err := calcResult(calc.IPv6(r.Address, r.Mac))
	return &v1.Ipv6Response{Result: localize(ctx, res)}, err
}

func (calcSvc) Mtu(ctx context.Context, r *v1.MtuRequest) (*v1.MtuResponse, error) {
	res, err := calcResult(calc.MTU(int(min(r.Physical, 1<<20)), r.Layers, r.InnerIpv6))
	return &v1.MtuResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Tcp(ctx context.Context, r *v1.TcpRequest) (*v1.TcpResponse, error) {
	res, err := calcResult(calc.TCP(r.Bandwidth, r.RttMs, r.Window, r.LossPercent, int(min(r.Mss, 1<<20))))
	return &v1.TcpResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Dscp(ctx context.Context, r *v1.DscpRequest) (*v1.DscpResponse, error) {
	res, err := calcResult(calc.DSCP(r.Query, r.Field))
	return &v1.DscpResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Optics(ctx context.Context, r *v1.OpticsRequest) (*v1.OpticsResponse, error) {
	var res *v1.CalcResult
	var err error
	if r.Convert != "" {
		res, err = calcResult(calc.Power(r.Convert))
	} else {
		res, err = calcResult(calc.Optics(calc.OpticsInput{TxDbm: r.TxDbm, RxSensDbm: r.RxSensitivityDbm, RxOverloadDbm: r.RxOverloadDbm, Km: r.Km,
			Fiber: r.Fiber, LossPerKm: r.LossPerKm, Connectors: int(min(r.Connectors, 1000)), ConnectorLoss: r.ConnectorLossDb,
			Splices: int(min(r.Splices, 1000)), SpliceLoss: r.SpliceLossDb, MarginDb: r.MarginDb}))
	}
	return &v1.OpticsResponse{Result: localize(ctx, res)}, err
}

func (calcSvc) Bgp(ctx context.Context, r *v1.BgpRequest) (*v1.BgpResponse, error) {
	routes := make([]calc.Route, 0, len(r.Routes))
	for _, p := range r.Routes {
		routes = append(routes, calc.Route{Name: p.Name, Weight: p.Weight, LocalPref: p.LocalPref, Local: p.LocallyOriginated, ASPath: p.AsPath,
			Origin: p.Origin, MED: p.Med, EBGP: p.Ebgp, IGPMetric: p.IgpMetric, RouterID: p.RouterId, OriginatorID: p.OriginatorId,
			ClusterListLen: int(min(p.ClusterListLength, 1000)), Neighbor: p.Neighbor, AgeSeconds: p.AgeSeconds, NextHopUnreachable: p.NextHopUnreachable})
	}
	res, err := calcResult(calc.BGPBestPath(routes, calc.BGPOptions{AlwaysCompareMED: r.AlwaysCompareMed, DeterministicMED: r.DeterministicMed,
		MultipathRelax: r.MultipathRelax, MaximumPaths: int(min(r.MaximumPaths, 64))}))
	return &v1.BgpResponse{Result: localize(ctx, res)}, err
}

// Module registra el servicio Calc.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterCalcServiceServer(s, calcSvc{})
}
