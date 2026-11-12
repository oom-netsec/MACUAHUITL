package security

import (
	"strings"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/radiustest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tacacstest"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ikedec"
	"github.com/oom-netsec/MACUAHUITL/internal/pki"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// Forma estructurada de los informes de seguridad (fase 30b): lo mismo que dice el texto, con claves estables.
// Nada de aquí lleva el secreto compartido ni la contraseña: el informe de dominio tampoco los trae.

func secText(loc string, t i18n.Text) *v1.SecText {
	if t.Empty() {
		return nil
	}
	return &v1.SecText{Key: t.Key, Args: t.Args, Text: t.In(loc)}
}

func radiusExchanges(loc string, r radiustest.Report) []*v1.RadiusExchange {
	var out []*v1.RadiusExchange
	for _, e := range r.Exchanges {
		x := &v1.RadiusExchange{Kind: e.Kind, Code: e.Code, RttMs: e.RTTMillis, Attempts: int32(e.Attempts),
			MessageAuthenticator: radiustest.MACode(e.MessageAuthenticator), Error: secText(loc, e.ErrText)}
		x.Mschap2Verified = e.MSCHAP2Verified
		for _, a := range e.Attrs {
			x.Attrs = append(x.Attrs, &v1.RadiusAttribute{Name: a.Name, Value: a.Value})
		}
		out = append(out, x)
	}
	return out
}

func radiusFindings(loc string, r radiustest.Report) []*v1.SecFinding {
	var out []*v1.SecFinding
	for _, f := range r.Findings {
		out = append(out, &v1.SecFinding{Code: f.Code, Severity: radiustest.SeverityCode(f.Severity), Args: f.ArgsIn(loc), Message: f.DetailIn(loc)})
	}
	return out
}

func tacacsSteps(loc string, r tacacstest.Report) []*v1.TacacsStep {
	var out []*v1.TacacsStep
	for _, s := range r.Steps {
		x := &v1.TacacsStep{Kind: s.Kind, Status: s.Status, RttMs: s.RTTMillis, Error: secText(loc, s.ErrText), Prompts: s.Prompts, Message: s.ServerMsg, Data: s.Data}
		for _, a := range s.Sent {
			x.AvPairs = append(x.AvPairs, &v1.TacacsAvPair{Direction: "sent", Value: a})
		}
		for _, a := range s.AVPairs {
			x.AvPairs = append(x.AvPairs, &v1.TacacsAvPair{Direction: "received", Value: a})
		}
		out = append(out, x)
	}
	return out
}

func tacacsFindings(loc string, r tacacstest.Report) []*v1.SecFinding {
	var out []*v1.SecFinding
	for _, f := range r.Findings {
		out = append(out, &v1.SecFinding{Code: f.Code, Severity: tacacstest.SeverityCode(f.Severity), Args: f.ArgsIn(loc), Message: f.DetailIn(loc)})
	}
	return out
}

func certificates(loc string, sums []pki.Summary) []*v1.PkiCertificate {
	var out []*v1.PkiCertificate
	for _, s := range sums {
		c := &v1.PkiCertificate{Kind: map[string]string{"certificado": "certificate", "CSR": "csr"}[s.Kind], Subject: s.Subject, Issuer: s.Issuer,
			Serial: s.Serial, NotBefore: s.NotBefore, NotAfter: s.NotAfter, San: s.SANs, KeyUsage: s.KeyUsage, ExtKeyUsage: s.ExtKeyUsage,
			IsCa: s.IsCA, SelfSigned: s.SelfSigned, Sha1: s.SHA1, Sha256: s.SHA256,
			Key:       &v1.PkiKey{Algorithm: s.KeyAlg, Bits: uint32(s.KeyBits), Curve: s.KeyCurve, Description: s.KeyType},
			Signature: &v1.PkiSignature{Algorithm: s.SigAlg}}
		if s.NotAfter != "" {
			d := int32(s.DaysLeft)
			c.DaysLeft = &d
		}
		if s.Kind == "CSR" {
			c.Signature.Valid = &s.SignatureValid
		}
		for i, w := range s.Warnings {
			pw := &v1.PkiWarning{Message: w}
			if i < len(s.WarnItems) {
				pw.Code, pw.Args, pw.Message = strings.TrimPrefix(s.WarnItems[i].Key, "security.pki.warn."), s.WarnItems[i].Args, s.WarnItems[i].In(loc)
			}
			c.Warnings = append(c.Warnings, pw)
		}
		out = append(out, c)
	}
	return out
}

// ikeResponse arma la respuesta del decodificador IKE: el informe (texto y JSON) en el idioma pedido y su forma
// estructurada. Las fases y los resultados salen como códigos cerrados en inglés.
func ikeResponse(rep ikedec.Report, loc string) *v1.IkeDecodeResponse {
	local := rep.In(loc)
	k1, k2 := rep.PhaseKeys()
	out := &v1.IkeDecodeResponse{Report: service.Report(local, rep.TextIn(loc)), Phase1: ikeCode(k1), Phase2: ikeCode(k2), Note: local.Note}
	for i, f := range rep.Findings {
		lf := local.Findings[i]
		out.Findings = append(out.Findings, &v1.IkeFinding{Code: f.Code, Severity: ikeSeverity(f.Severity), Phase: int32(f.Phase), Key: f.Key(), ExplanationKey: f.ExplanationKey(),
			Args: f.Args(), Title: lf.Title, Explanation: lf.Explanation, Action: lf.Action, Evidence: lf.Evidence})
	}
	for i, p := range rep.Proposals {
		out.Proposals = append(out.Proposals, &v1.IkeProposal{Phase: int32(p.Phase), SourceKey: p.SourceKey(), SourceArgs: p.SourceArgs(), Source: local.Proposals[i].Source,
			Detail: p.Detail, Result: ikeCode(p.ResultKey())})
	}
	return out
}

// ikeCode es el último tramo de una clave de valor (ike.val.phase.no_data da no_data).
func ikeCode(key string) string { return key[strings.LastIndex(key, ".")+1:] }

func ikeSeverity(s string) string {
	if s == "aviso" {
		return "warning"
	}
	return s
}
