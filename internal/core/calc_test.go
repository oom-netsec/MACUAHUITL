package core

import (
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestCalcServiceEachCalculator(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewCalcServiceClient(h.conn)
	ov := -1.0
	results := map[string]func() (*v1.CalcResult, error){
		"subnet": func() (*v1.CalcResult, error) {
			r, err := c.Subnet(ctx(t), &v1.SubnetRequest{Prefix: "10.0.0.1/31"})
			return r.GetResult(), err
		},
		"vlsm": func() (*v1.CalcResult, error) {
			r, err := c.Vlsm(ctx(t), &v1.VlsmRequest{Network: "10.0.0.0/24", Needs: []*v1.VlsmNeed{{Name: "lan", Hosts: 100}}})
			return r.GetResult(), err
		},
		"summarize": func() (*v1.CalcResult, error) {
			r, err := c.Summarize(ctx(t), &v1.SummarizeRequest{Prefixes: []string{"10.0.0.0/24", "10.0.1.0/24"}})
			return r.GetResult(), err
		},
		"wildcard": func() (*v1.CalcResult, error) {
			r, err := c.Wildcard(ctx(t), &v1.WildcardRequest{Address: "10.0.0.1", Value: "0.0.0.254"})
			return r.GetResult(), err
		},
		"ipv6": func() (*v1.CalcResult, error) {
			r, err := c.Ipv6(ctx(t), &v1.Ipv6Request{Mac: "00:50:56:ab:cd:ef"})
			return r.GetResult(), err
		},
		"mtu": func() (*v1.CalcResult, error) {
			r, err := c.Mtu(ctx(t), &v1.MtuRequest{Physical: 1500, Layers: []string{"gre"}})
			return r.GetResult(), err
		},
		"tcp": func() (*v1.CalcResult, error) {
			r, err := c.Tcp(ctx(t), &v1.TcpRequest{Bandwidth: "1g", RttMs: 50})
			return r.GetResult(), err
		},
		"dscp": func() (*v1.CalcResult, error) {
			r, err := c.Dscp(ctx(t), &v1.DscpRequest{Query: "ef"})
			return r.GetResult(), err
		},
		"optics": func() (*v1.CalcResult, error) {
			r, err := c.Optics(ctx(t), &v1.OpticsRequest{TxDbm: 4, RxSensitivityDbm: -15, RxOverloadDbm: &ov, Km: 2, Fiber: "smf-1310", Connectors: 2, ConnectorLossDb: 0.5, MarginDb: 3})
			return r.GetResult(), err
		},
		"power": func() (*v1.CalcResult, error) {
			r, err := c.Optics(ctx(t), &v1.OpticsRequest{Convert: "-3dBm"})
			return r.GetResult(), err
		},
		"bgp": func() (*v1.CalcResult, error) {
			lp := uint32(200)
			r, err := c.Bgp(ctx(t), &v1.BgpRequest{Routes: []*v1.BgpRoute{
				{Name: "A", AsPath: "65001", Ebgp: true, RouterId: "10.0.0.1"},
				{Name: "B", AsPath: "65002", LocalPref: &lp, RouterId: "10.0.0.2"},
			}})
			return r.GetResult(), err
		},
	}
	want := map[string]string{"subnet": "RFC 3021", "vlsm": "10.0.0.0/25", "summarize": "10.0.0.0/23", "wildcard": "128", "ipv6": "fe80::250:56ff:feab:cdef",
		"mtu": "1436", "tcp": "5.96 MiB (6250000 bytes)", "dscp": "101110", "optics": "atenuador", "power": "0.501", "bgp": "Gana B"}
	for name, f := range results {
		r, err := f()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !json.Valid([]byte(r.Json)) || len(r.Tables) == 0 || len(r.Tables[0].Rows) == 0 || !strings.Contains(r.Text, want[name]) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if _, err := c.Subnet(ctx(t), &v1.SubnetRequest{Prefix: "10.0.0.0/33"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("prefijo inválido: %v", err)
	}
	if _, err := c.Bgp(ctx(t), &v1.BgpRequest{Routes: []*v1.BgpRoute{{Name: "solo"}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("una sola ruta: %v", err)
	}
	// El JSON es el resultado tipado, no solo las tablas.
	r, _ := c.Mtu(ctx(t), &v1.MtuRequest{Physical: 1500, Layers: []string{"gre"}})
	var m struct{ MSS int }
	if json.Unmarshal([]byte(r.Result.Json), &m); m.MSS != 1436 {
		t.Fatalf("json: %s", r.Result.Json)
	}
}
