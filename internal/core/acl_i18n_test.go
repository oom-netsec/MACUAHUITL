package core

import (
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

var españolFlota = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(línea|origen|destino|regla|reglas|puerto|puertos|máscara|dirección|falta|inválido|inválida|desconocido|no soportado|se esperaba|ninguna|bloque|sin)\b`)

// Con en, los errores de ACL salen en inglés con su reason y el detalle de los hallazgos trae clave; con es, lo de siempre.
func TestAclIdiomaYErrores(t *testing.T) {
	h := newHarness(t, nil)
	al := v1.NewAclServiceClient(h.conn)
	for i, txt := range []string{"access-list X extended permit ip 10.0.0.0 0.0.0.255 any\n", "access-list EDGE extended permit tcp any any eq\n", "basura\n", "", "access-list A extended permit ip any any\naccess-list B extended permit ip any any\n"} {
		_, err := al.Import(con(t, "en"), &v1.ImportRequest{Vendor: "asa", Text: txt})
		if status.Code(err) != codes.InvalidArgument || !strings.HasPrefix(status.Convert(err).Message(), "acl: ") {
			t.Fatalf("%d: %v", i, err)
		}
		if m := españolFlota.FindString(status.Convert(err).Message()); m != "" {
			t.Errorf("%d: español (%s) en %q", i, m, status.Convert(err).Message())
		}
		if why, md := reasonOf(err); i < 4 && (why != "acl.err.import" || md["line"] != "1" || md["cause_reason"] != "acl.err.line") {
			t.Errorf("%d: reason %q %v", i, why, md)
		}
		_, esErr := al.Import(con(t, ""), &v1.ImportRequest{Vendor: "asa", Text: txt})
		if !strings.Contains(status.Convert(esErr).Message(), "línea") && !strings.Contains(status.Convert(esErr).Message(), "ACL") {
			t.Errorf("%d: con es debe seguir en español: %v", i, esErr)
		}
	}
	if _, err := al.Import(con(t, "en"), &v1.ImportRequest{Vendor: "junos", Text: "x"}); status.Convert(err).Message() != `acl: vendor "junos" not supported (ios-xe, nx-os, asa)` {
		t.Errorf("vendor: %v", err)
	}
	imp, _ := al.Import(ctx(t), &v1.ImportRequest{Vendor: "asa", Text: asaSample})
	if _, err := al.Generate(con(t, "en"), &v1.GenerateRequest{Acl: imp.Acl, Vendor: "junos"}); status.Convert(err).Message() != `acl: vendor "junos" not supported (ios-xe, nx-os, asa)` {
		t.Errorf("generate: %v", err)
	}
	bad := &v1.Acl{Rules: []*v1.AclRule{{Source: "mal", Destination: "0.0.0.0/0"}}}
	if _, err := al.Analyze(con(t, "en"), &v1.AnalyzeRequest{Acl: bad}); !strings.HasPrefix(status.Convert(err).Message(), `rule 1: source "mal":`) {
		t.Errorf("analyze: %v", err)
	}
	// hallazgos: texto en el idioma, clave y argumentos siempre
	an := &v1.Acl{Name: "T", Rules: []*v1.AclRule{
		{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: "ip", Source: "10.0.0.0/8", Destination: "0.0.0.0/0"},
		{Action: v1.AclAction_ACL_ACTION_DENY, Protocol: "tcp", Source: "10.1.0.0/16", Destination: "0.0.0.0/0"},
		{Action: v1.AclAction_ACL_ACTION_PERMIT, Protocol: "icmp", Source: "10.0.0.0/8", Destination: "0.0.0.0/0", DestinationPorts: "eq 80"},
	}}
	en, err := al.Analyze(con(t, "en"), &v1.AnalyzeRequest{Acl: an})
	if err != nil || len(en.Findings) != 2 {
		t.Fatalf("%v %v", err, en)
	}
	if f := en.Findings[0]; f.Detail != "rule 1 (permit) already covers everything this one matches" || f.DetailKey != "acl.finding.covered" || f.DetailArgs["n"] != "1" {
		t.Errorf("hallazgo en: %+v", f)
	}
	if f := en.Findings[1]; f.Detail != "ports only apply to tcp/udp, not to icmp" || f.DetailKey != "acl.err.ports_proto" || f.DetailArgs["proto"] != "icmp" {
		t.Errorf("imposible en: %+v", f)
	}
	es, _ := al.Analyze(ctx(t), &v1.AnalyzeRequest{Acl: an})
	if es.Findings[0].Detail != "la regla 1 (permit) ya cubre todo lo que esta coincide" || es.Findings[1].Detail != "los puertos solo aplican a tcp/udp, no a icmp" {
		t.Errorf("hallazgo es: %+v", es.Findings)
	}
}
