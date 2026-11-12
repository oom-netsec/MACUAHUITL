package acl

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/acl"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// aclSvc no toca la bóveda ni la red ni escribe auditoría: es una calculadora
// sobre texto del ingeniero (spec §13).
type aclSvc struct {
	v1.UnimplementedAclServiceServer
}

func parsePortsText(s string) ([]acl.PortRange, error) {
	var out []acl.PortRange
	f := strings.Fields(s)
	for len(f) > 0 {
		n := 2
		if f[0] == "range" {
			n = 3
		}
		if len(f) < n {
			return nil, fmt.Errorf("puertos %q incompletos", s)
		}
		pr, err := acl.ParsePorts(f[0], f[1:n]...)
		if err != nil {
			return nil, err
		}
		out = append(out, pr...)
		f = f[n:]
	}
	return out, nil
}

func ruleToProto(r acl.Rule) *v1.AclRule {
	p := &v1.AclRule{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: r.Protocol, Source: r.Src.String(), Destination: r.Dst.String(),
		SourcePorts: acl.PortsText(r.SrcPorts), DestinationPorts: acl.PortsText(r.DstPorts), Log: r.Log, Remark: r.Remark, Established: r.Established}
	if r.Action == acl.Deny {
		p.Action = v1.AclAction_ACL_ACTION_DENY
	}
	return p
}

func aclFromProto(p *v1.Acl) (acl.ACL, error) {
	out := acl.ACL{Name: p.GetName()}
	for i, pr := range p.GetRules() {
		r := acl.Rule{Protocol: acl.CanonProtocol(pr.Protocol), Log: pr.Log, Remark: pr.Remark, Established: pr.Established}
		if pr.Action == v1.AclAction_ACL_ACTION_DENY {
			r.Action = acl.Deny
		}
		var err error
		if r.Src, err = netip.ParsePrefix(pr.Source); err != nil {
			return out, fmt.Errorf("regla %d: origen %q: %w", i+1, pr.Source, err)
		}
		if r.Dst, err = netip.ParsePrefix(pr.Destination); err != nil {
			return out, fmt.Errorf("regla %d: destino %q: %w", i+1, pr.Destination, err)
		}
		if r.SrcPorts, err = parsePortsText(pr.SourcePorts); err != nil {
			return out, fmt.Errorf("regla %d: %w", i+1, err)
		}
		if r.DstPorts, err = parsePortsText(pr.DestinationPorts); err != nil {
			return out, fmt.Errorf("regla %d: %w", i+1, err)
		}
		r.SrcPorts, r.DstPorts = acl.NormalizePorts(r.SrcPorts), acl.NormalizePorts(r.DstPorts)
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}

func (aclSvc) Import(_ context.Context, r *v1.ImportRequest) (*v1.ImportResponse, error) {
	a, err := acl.Parse(r.Vendor, r.Text)
	if err != nil {
		var le *acl.LineError
		if errors.As(err, &le) {
			return nil, status.Errorf(codes.InvalidArgument, "acl: %v", err)
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	out := &v1.Acl{Name: a.Name}
	for _, rule := range a.Rules {
		out.Rules = append(out.Rules, ruleToProto(rule))
	}
	return &v1.ImportResponse{Acl: out}, nil
}

func (aclSvc) Analyze(_ context.Context, r *v1.AnalyzeRequest) (*v1.AnalyzeResponse, error) {
	a, err := aclFromProto(r.Acl)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	out := &v1.AnalyzeResponse{}
	for _, f := range acl.Analyze(a) {
		out.Findings = append(out.Findings, &v1.Finding{RuleIndex: uint32(f.Index), Kind: f.Kind, Detail: f.Detail})
	}
	return out, nil
}

func (aclSvc) Generate(_ context.Context, r *v1.GenerateRequest) (*v1.GenerateResponse, error) {
	a, err := aclFromProto(r.Acl)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	script, err := acl.Generate(r.Vendor, a)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &v1.GenerateResponse{Script: script}, nil
}

// Module registra el servicio Acl.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterAclServiceServer(s, aclSvc{})
}
