package core

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const asaSample = "access-list EDGE extended permit tcp 10.0.0.0 255.255.255.0 any eq 22\naccess-list EDGE extended deny tcp host 10.0.0.5 any eq 22\naccess-list EDGE extended deny ip any any log\n"

func TestAclImportAnalyzeGenerate(t *testing.T) {
	h := newHarness(t, nil)
	acl := v1.NewAclServiceClient(h.conn)
	imp, err := acl.Import(ctx(t), &v1.ImportRequest{Vendor: "asa", Text: asaSample})
	if err != nil {
		t.Fatal(err)
	}
	if imp.Acl.Name != "EDGE" || len(imp.Acl.Rules) != 3 || imp.Acl.Rules[0].Source != "10.0.0.0/24" || imp.Acl.Rules[0].DestinationPorts != "eq 22" {
		t.Fatalf("import = %+v", imp.Acl)
	}
	an, err := acl.Analyze(ctx(t), &v1.AnalyzeRequest{Acl: imp.Acl})
	if err != nil || len(an.Findings) != 1 || an.Findings[0].RuleIndex != 1 || an.Findings[0].Kind != "shadowed" {
		t.Fatalf("analyze = %+v %v", an, err)
	}
	gen, err := acl.Generate(ctx(t), &v1.GenerateRequest{Acl: imp.Acl, Vendor: "ios-xe"})
	if err != nil || !strings.Contains(gen.Script, "ip access-list extended EDGE") || !strings.Contains(gen.Script, "permit tcp 10.0.0.0 0.0.0.255 any eq 22") {
		t.Fatalf("generate = %q %v", gen.GetScript(), err)
	}
	if _, err := acl.Import(ctx(t), &v1.ImportRequest{Vendor: "asa", Text: "access-list X extended permit ip 10.0.0.0 0.0.0.255 any\n"}); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "línea 1") {
		t.Fatalf("bad import err = %v", err)
	}
	if _, err := acl.Generate(ctx(t), &v1.GenerateRequest{Acl: imp.Acl, Vendor: "junos"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown vendor err = %v", err)
	}
	if txt := h.auditText(t); strings.Contains(txt, "10.0.0.0") {
		t.Fatal("ACL contents must not land in the audit log")
	}
}
