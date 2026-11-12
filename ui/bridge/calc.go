package bridge

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Calculadoras ----

type CalcTableDTO struct {
	Title string     `json:"title"`
	Head  []string   `json:"head"`
	Rows  [][]string `json:"rows"`
}

type CalcResultDTO struct {
	Text   string         `json:"text"`
	Tables []CalcTableDTO `json:"tables"`
	Notes  []string       `json:"notes"`
}

type calcFn func(context.Context, v1.CalcServiceClient, string) (*v1.CalcResult, error)

// calcRPC adapta un método del cliente: la UI manda la solicitud en protojson
// (camelCase), así un solo método del puente sirve a todas las calculadoras. Opt se
// infiere (grpc.CallOption) para no importar grpc aquí: noegress lo prohíbe fuera de ipc.
func calcRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp interface{ GetResult() *v1.CalcResult }, Opt any](m func(v1.CalcServiceClient, context.Context, PReq, ...Opt) (Resp, error)) calcFn {
	return func(ctx context.Context, c v1.CalcServiceClient, js string) (*v1.CalcResult, error) {
		req := PReq(new(Req))
		if err := protojson.Unmarshal([]byte(js), req); err != nil {
			return nil, fmt.Errorf("solicitud inválida: %w", err)
		}
		r, err := m(c, ctx, req)
		if err != nil {
			return nil, err
		}
		return r.GetResult(), nil
	}
}

var calcRPCs = map[string]calcFn{
	"subnet": calcRPC(v1.CalcServiceClient.Subnet), "vlsm": calcRPC(v1.CalcServiceClient.Vlsm),
	"summarize": calcRPC(v1.CalcServiceClient.Summarize), "wildcard": calcRPC(v1.CalcServiceClient.Wildcard),
	"ipv6": calcRPC(v1.CalcServiceClient.Ipv6), "mtu": calcRPC(v1.CalcServiceClient.Mtu), "tcp": calcRPC(v1.CalcServiceClient.Tcp),
	"dscp": calcRPC(v1.CalcServiceClient.Dscp), "optics": calcRPC(v1.CalcServiceClient.Optics), "bgp": calcRPC(v1.CalcServiceClient.Bgp),
}

func (b *Bridge) Calc(kind, reqJSON string) (CalcResultDTO, error) {
	f, ok := calcRPCs[kind]
	if !ok {
		return CalcResultDTO{}, fmt.Errorf("calculadora %q desconocida", kind)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CalcResultDTO, error) {
		r, err := f(ctx, v1.NewCalcServiceClient(c), reqJSON)
		if err != nil {
			return CalcResultDTO{}, err
		}
		out := CalcResultDTO{Text: r.Text, Tables: []CalcTableDTO{}, Notes: r.Notes}
		if out.Notes == nil {
			out.Notes = []string{}
		}
		for _, t := range r.Tables {
			dt := CalcTableDTO{Title: t.Title, Head: t.Head, Rows: [][]string{}}
			for _, row := range t.Rows {
				dt.Rows = append(dt.Rows, row.Cells)
			}
			out.Tables = append(out.Tables, dt)
		}
		return out, nil
	})
}
