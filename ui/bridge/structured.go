package bridge

import (
	"context"
	"fmt"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Datos estructurados (fase 30b) ----
// Los métodos de texto de siempre (SecRadius, SecTacacs, SecPkiDecode, ToolsPcap) siguen igual. Estos devuelven lo
// mismo con los datos en forma estructurada, con claves estables: la vista dibuja sin leer el español. Los campos
// vacíos no viajan (omitempty). Ningún campo trae secretos.

// KeyArgsDTO es una clave del catálogo con sus argumentos.
type KeyArgsDTO struct {
	Key  string            `json:"key"`
	Args map[string]string `json:"args,omitempty"`
}

// reportKeys son las claves de ToolReport.keys (fase 30c): por cada texto del json que sale del catálogo, su clave y
// argumentos bajo su ruta JSON (rows.2.detail, warnings.0). Sin claves no viaja nada (omitempty).
func reportKeys(r *v1.ToolReport) map[string]KeyArgsDTO {
	if len(r.GetKeys()) == 0 {
		return nil
	}
	out := make(map[string]KeyArgsDTO, len(r.Keys))
	for p, k := range r.Keys {
		out[p] = KeyArgsDTO{Key: k.Key, Args: k.Args}
	}
	return out
}

// SecTextDTO es un texto de catálogo con la clave, los argumentos y el texto en el idioma de la interfaz.
type SecTextDTO struct {
	Key  string            `json:"key"`
	Args map[string]string `json:"args,omitempty"`
	Text string            `json:"text"`
}

func secText(t *v1.SecText) *SecTextDTO {
	if t == nil {
		return nil
	}
	return &SecTextDTO{Key: t.Key, Args: t.Args, Text: t.Text}
}

type SecFindingDTO struct {
	Code     string            `json:"code"`
	Severity string            `json:"severity"` // warning, error, info
	Args     map[string]string `json:"args,omitempty"`
	Message  string            `json:"message"`
}

func findings(in []*v1.SecFinding) []SecFindingDTO {
	out := []SecFindingDTO{}
	for _, f := range in {
		out = append(out, SecFindingDTO{Code: f.Code, Severity: f.Severity, Args: f.Args, Message: f.Message})
	}
	return out
}

type NameValueDTO struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RadiusExchangeDTO struct {
	Kind                 string         `json:"kind"`
	Code                 string         `json:"code,omitempty"`
	RttMs                float64        `json:"rttMs"`
	Attempts             int            `json:"attempts"`
	MessageAuthenticator string         `json:"messageAuthenticator,omitempty"` // absent, valid, invalid
	Error                *SecTextDTO    `json:"error,omitempty"`
	Attrs                []NameValueDTO `json:"attrs"`
	Mschap2Verified      *bool          `json:"mschap2Verified,omitempty"` // fase 30c: solo MS-CHAPv2; true si el MS-CHAP2-Success verificó al servidor
}

type RadiusReportDTO struct {
	Text      string              `json:"text"`
	Server    string              `json:"server"`
	Method    string              `json:"method,omitempty"`
	Exchanges []RadiusExchangeDTO `json:"exchanges"`
	Findings  []SecFindingDTO     `json:"findings"`
}

func (b *Bridge) SecRadiusReport(d RadiusDTO) (RadiusReportDTO, error) {
	ap, err := port(d.AuthPort)
	if err != nil {
		return RadiusReportDTO{}, wrapErr(err)
	}
	cp, err := port(d.AcctPort)
	if err != nil {
		return RadiusReportDTO{}, wrapErr(err)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (RadiusReportDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).RadiusTest(ctx, &v1.RadiusTestRequest{Host: d.Host, AuthPort: ap, AcctPort: cp,
			SharedSecret: source(d.SecretCredID, d.Secret), Username: d.Username, Password: source(d.CredID, d.Password), Method: d.Method,
			NasIp: d.NasIP, NasIdentifier: d.NasID, NasPortType: d.PortType, ServiceType: d.ServiceType, CalledStationId: d.Called,
			CallingStationId: d.Calling, StatusServer: d.StatusServer, Accounting: d.Accounting})
		if err != nil {
			return RadiusReportDTO{}, err
		}
		out := RadiusReportDTO{Text: r.GetReport().GetText(), Server: r.Server, Method: r.Method, Exchanges: []RadiusExchangeDTO{}, Findings: findings(r.Findings)}
		for _, e := range r.Exchanges {
			x := RadiusExchangeDTO{Kind: e.Kind, Code: e.Code, RttMs: e.RttMs, Attempts: int(e.Attempts), MessageAuthenticator: e.MessageAuthenticator, Error: secText(e.Error), Attrs: []NameValueDTO{}, Mschap2Verified: e.Mschap2Verified}
			for _, a := range e.Attrs {
				x.Attrs = append(x.Attrs, NameValueDTO{Name: a.Name, Value: a.Value})
			}
			out.Exchanges = append(out.Exchanges, x)
		}
		return out, nil
	})
}

type TacacsAvPairDTO struct {
	Direction string `json:"direction"` // sent, received
	Value     string `json:"value"`
}

type TacacsStepDTO struct {
	Kind    string            `json:"kind"`
	Status  string            `json:"status,omitempty"`
	RttMs   float64           `json:"rttMs"`
	Error   *SecTextDTO       `json:"error,omitempty"`
	Prompts []string          `json:"prompts"`
	Message string            `json:"message,omitempty"`
	Data    string            `json:"data,omitempty"`
	AvPairs []TacacsAvPairDTO `json:"avPairs"`
}

type TacacsReportDTO struct {
	Text     string          `json:"text"`
	Server   string          `json:"server"`
	Steps    []TacacsStepDTO `json:"steps"`
	Findings []SecFindingDTO `json:"findings"`
}

func (b *Bridge) SecTacacsReport(d TacacsDTO) (TacacsReportDTO, error) {
	p, err := port(d.Port)
	if err != nil {
		return TacacsReportDTO{}, wrapErr(err)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TacacsReportDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).TacacsTest(ctx, &v1.TacacsTestRequest{Host: d.Host, Port: p, SharedSecret: source(d.SecretCredID, d.Secret),
			Username: d.Username, Password: source(d.CredID, d.Password), AuthenType: d.AuthenType, Command: d.Command, Accounting: d.Accounting})
		if err != nil {
			return TacacsReportDTO{}, err
		}
		out := TacacsReportDTO{Text: r.GetReport().GetText(), Server: r.Server, Steps: []TacacsStepDTO{}, Findings: findings(r.Findings)}
		for _, s := range r.Steps {
			x := TacacsStepDTO{Kind: s.Kind, Status: s.Status, RttMs: s.RttMs, Error: secText(s.Error), Prompts: append([]string{}, s.Prompts...), Message: s.Message, Data: s.Data, AvPairs: []TacacsAvPairDTO{}}
			for _, a := range s.AvPairs {
				x.AvPairs = append(x.AvPairs, TacacsAvPairDTO{Direction: a.Direction, Value: a.Value})
			}
			out.Steps = append(out.Steps, x)
		}
		return out, nil
	})
}

type PkiKeyDTO struct {
	Algorithm   string `json:"algorithm"`
	Bits        int    `json:"bits"`
	Curve       string `json:"curve,omitempty"`
	Description string `json:"description"`
}

type PkiSignatureDTO struct {
	Algorithm string `json:"algorithm"`
	Valid     *bool  `json:"valid,omitempty"` // solo en CSR
}

type PkiWarningDTO struct {
	Code    string            `json:"code"`
	Args    map[string]string `json:"args,omitempty"`
	Message string            `json:"message"`
}

// CertificateDTO es un certificado o CSR: kind es certificate o csr; las fechas son RFC 3339 UTC y sin validez
// (CSR) no hay fechas ni daysLeft.
type CertificateDTO struct {
	Kind        string          `json:"kind"`
	Subject     string          `json:"subject"`
	Issuer      string          `json:"issuer,omitempty"`
	Serial      string          `json:"serial,omitempty"`
	NotBefore   string          `json:"notBefore,omitempty"`
	NotAfter    string          `json:"notAfter,omitempty"`
	DaysLeft    *int            `json:"daysLeft,omitempty"`
	Key         PkiKeyDTO       `json:"key"`
	Signature   PkiSignatureDTO `json:"signature"`
	San         []string        `json:"san"`
	KeyUsage    []string        `json:"keyUsage"`
	ExtKeyUsage []string        `json:"extKeyUsage"`
	IsCA        bool            `json:"isCa"`
	SelfSigned  bool            `json:"selfSigned"`
	Sha1        string          `json:"sha1,omitempty"`
	Sha256      string          `json:"sha256,omitempty"`
	Warnings    []PkiWarningDTO `json:"warnings"`
}

func certificates(in []*v1.PkiCertificate) []CertificateDTO {
	out := []CertificateDTO{}
	for _, c := range in {
		x := CertificateDTO{Kind: c.Kind, Subject: c.Subject, Issuer: c.Issuer, Serial: c.Serial, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
			Key:       PkiKeyDTO{Algorithm: c.GetKey().GetAlgorithm(), Bits: int(c.GetKey().GetBits()), Curve: c.GetKey().GetCurve(), Description: c.GetKey().GetDescription()},
			Signature: PkiSignatureDTO{Algorithm: c.GetSignature().GetAlgorithm()}, San: append([]string{}, c.San...), KeyUsage: append([]string{}, c.KeyUsage...),
			ExtKeyUsage: append([]string{}, c.ExtKeyUsage...), IsCA: c.IsCa, SelfSigned: c.SelfSigned, Sha1: c.Sha1, Sha256: c.Sha256, Warnings: []PkiWarningDTO{}}
		if c.DaysLeft != nil {
			d := int(*c.DaysLeft)
			x.DaysLeft = &d
		}
		if c.GetSignature().Valid != nil {
			v := c.GetSignature().GetValid()
			x.Signature.Valid = &v
		}
		for _, w := range c.Warnings {
			x.Warnings = append(x.Warnings, PkiWarningDTO{Code: w.Code, Args: w.Args, Message: w.Message})
		}
		out = append(out, x)
	}
	return out
}

type PkiReportDTO struct {
	Text         string           `json:"text"`
	Certificates []CertificateDTO `json:"certificates"`
}

func (b *Bridge) SecPkiDecodeReport(text string) (PkiReportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PkiReportDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).PkiDecode(ctx, &v1.PkiDecodeRequest{Data: []byte(text)})
		if err != nil {
			return PkiReportDTO{}, err
		}
		return PkiReportDTO{Text: r.GetReport().GetText(), Certificates: certificates(r.Certificates)}, nil
	})
}

// ---- Captura (pcap) ----

type PcapSummaryDTO struct {
	File       string  `json:"file"`
	Packets    int64   `json:"packets"`
	Bytes      int64   `json:"bytes"`
	DurationMs float64 `json:"durationMs"`
	Start      string  `json:"start"`
}

type PcapConversationDTO struct {
	Proto   string `json:"proto"`
	A       string `json:"a"`
	B       string `json:"b"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

type PcapTalkerDTO struct {
	IP      string `json:"ip"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

type PcapProtocolDTO struct {
	Proto   string `json:"proto"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

type PcapNeighborDTO struct {
	Protocol   string `json:"protocol"`
	DeviceID   string `json:"deviceId"`
	Port       string `json:"port"`
	Platform   string `json:"platform"`
	MgmtIP     string `json:"mgmtIp"`
	NativeVlan int    `json:"nativeVlan"`
}

type PcapFlowDTO struct {
	Client string `json:"client"`
	Server string `json:"server"`
	Count  int64  `json:"count"`
}

type PcapTcpDTO struct {
	Handshakes            int64         `json:"handshakes"`
	RttMinMs              float64       `json:"rttMinMs"`
	RttAvgMs              float64       `json:"rttAvgMs"`
	RttMaxMs              float64       `json:"rttMaxMs"`
	Retransmissions       int64         `json:"retransmissions"`
	ZeroWindow            int64         `json:"zeroWindow"`
	FailedHandshakesTotal int64         `json:"failedHandshakesTotal"`
	FailedHandshakes      []PcapFlowDTO `json:"failedHandshakes"`
	Resets                []PcapFlowDTO `json:"resets"`
}

type PcapDnsQueryDTO struct {
	Client    string  `json:"client"`
	Server    string  `json:"server"`
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Rcode     string  `json:"rcode,omitempty"`
	LatencyMs float64 `json:"latencyMs"`
}

type PcapDnsDTO struct {
	Queries    int64             `json:"queries"`
	Responses  int64             `json:"responses"`
	Errors     []PcapDnsQueryDTO `json:"errors"`
	Slow       []PcapDnsQueryDTO `json:"slow"`
	Unanswered []PcapDnsQueryDTO `json:"unanswered"`
}

type PcapTlsDTO struct {
	Client string `json:"client"`
	Server string `json:"server"`
	Sni    string `json:"sni"`
}

type PcapIcmpEventDTO struct {
	From   string `json:"from"`
	Target string `json:"target"`
	Code   int    `json:"code"`
}

type PcapIcmpDTO struct {
	Unreachable []PcapIcmpEventDTO `json:"unreachable"`
	TtlExceeded []PcapIcmpEventDTO `json:"ttlExceeded"`
}

type PcapArpConflictDTO struct {
	IP   string   `json:"ip"`
	Macs []string `json:"macs"`
}

// PcapSectionDTO es un encabezado de sección del informe: key pcap.section.*, sus args y el título en el idioma de la interfaz.
type PcapSectionDTO struct {
	Key   string            `json:"key"`
	Args  map[string]string `json:"args,omitempty"`
	Title string            `json:"title"`
}

type PcapWarningDTO struct {
	Key  string            `json:"key"`
	Args map[string]string `json:"args,omitempty"`
	Text string            `json:"text"`
}

type PcapReportDTO struct {
	Text          string                `json:"text"`
	Summary       PcapSummaryDTO        `json:"summary"`
	Conversations []PcapConversationDTO `json:"conversations"`
	TopTalkers    []PcapTalkerDTO       `json:"topTalkers"`
	Protocols     []PcapProtocolDTO     `json:"protocols"`
	Neighbors     []PcapNeighborDTO     `json:"neighbors"`
	Tcp           PcapTcpDTO            `json:"tcp"`
	Dns           PcapDnsDTO            `json:"dns"`
	Tls           []PcapTlsDTO          `json:"tls"`
	Icmp          PcapIcmpDTO           `json:"icmp"`
	ArpConflicts  []PcapArpConflictDTO  `json:"arpConflicts"`
	Fragments     int64                 `json:"fragments"`
	Warnings      []PcapWarningDTO      `json:"warnings"`
	Sections      []PcapSectionDTO      `json:"sections"`
}

func pcapFlows(in []*v1.PcapFlow) []PcapFlowDTO {
	out := []PcapFlowDTO{}
	for _, f := range in {
		out = append(out, PcapFlowDTO{Client: f.Client, Server: f.Server, Count: f.Count})
	}
	return out
}

func pcapQueries(in []*v1.PcapDnsQuery) []PcapDnsQueryDTO {
	out := []PcapDnsQueryDTO{}
	for _, q := range in {
		out = append(out, PcapDnsQueryDTO{Client: q.Client, Server: q.Server, Name: q.Name, Type: q.Type, Rcode: q.Rcode, LatencyMs: q.LatencyMs})
	}
	return out
}

func pcapEvents(in []*v1.PcapIcmpEvent) []PcapIcmpEventDTO {
	out := []PcapIcmpEventDTO{}
	for _, e := range in {
		out = append(out, PcapIcmpEventDTO{From: e.From, Target: e.Target, Code: int(e.Code)})
	}
	return out
}

func pcapReport(r *v1.AnalyzePcapResponse) PcapReportDTO {
	s, t, d, i := r.GetSummary(), r.GetTcp(), r.GetDns(), r.GetIcmp()
	out := PcapReportDTO{Text: r.GetReport().GetText(), Fragments: r.Fragments,
		Summary:       PcapSummaryDTO{File: s.GetFile(), Packets: s.GetPackets(), Bytes: s.GetBytes(), DurationMs: s.GetDurationMs(), Start: s.GetStart()},
		Conversations: []PcapConversationDTO{}, TopTalkers: []PcapTalkerDTO{}, Protocols: []PcapProtocolDTO{}, Neighbors: []PcapNeighborDTO{}, Tls: []PcapTlsDTO{},
		ArpConflicts: []PcapArpConflictDTO{}, Warnings: []PcapWarningDTO{}, Sections: []PcapSectionDTO{},
		Tcp: PcapTcpDTO{Handshakes: t.GetHandshakes(), RttMinMs: t.GetRttMinMs(), RttAvgMs: t.GetRttAvgMs(), RttMaxMs: t.GetRttMaxMs(), Retransmissions: t.GetRetransmissions(),
			ZeroWindow: t.GetZeroWindow(), FailedHandshakesTotal: t.GetFailedHandshakesTotal(), FailedHandshakes: pcapFlows(t.GetFailedHandshakes()), Resets: pcapFlows(t.GetResets())},
		Dns:  PcapDnsDTO{Queries: d.GetQueries(), Responses: d.GetResponses(), Errors: pcapQueries(d.GetErrors()), Slow: pcapQueries(d.GetSlow()), Unanswered: pcapQueries(d.GetUnanswered())},
		Icmp: PcapIcmpDTO{Unreachable: pcapEvents(i.GetUnreachable()), TtlExceeded: pcapEvents(i.GetTtlExceeded())}}
	for _, c := range r.Conversations {
		out.Conversations = append(out.Conversations, PcapConversationDTO{Proto: c.Proto, A: c.A, B: c.B, Packets: c.Packets, Bytes: c.Bytes})
	}
	for _, x := range r.TopTalkers {
		out.TopTalkers = append(out.TopTalkers, PcapTalkerDTO{IP: x.Ip, Packets: x.Packets, Bytes: x.Bytes})
	}
	for _, x := range r.Protocols {
		out.Protocols = append(out.Protocols, PcapProtocolDTO{Proto: x.Proto, Packets: x.Packets, Bytes: x.Bytes})
	}
	for _, n := range r.Neighbors {
		out.Neighbors = append(out.Neighbors, PcapNeighborDTO{Protocol: n.Protocol, DeviceID: n.DeviceId, Port: n.Port, Platform: n.Platform, MgmtIP: n.MgmtIp, NativeVlan: int(n.NativeVlan)})
	}
	for _, x := range r.Tls {
		out.Tls = append(out.Tls, PcapTlsDTO{Client: x.Client, Server: x.Server, Sni: x.Sni})
	}
	for _, x := range r.ArpConflicts {
		out.ArpConflicts = append(out.ArpConflicts, PcapArpConflictDTO{IP: x.Ip, Macs: append([]string{}, x.Macs...)})
	}
	for _, w := range r.Warnings {
		out.Warnings = append(out.Warnings, PcapWarningDTO{Key: w.Key, Args: w.Args, Text: w.Text})
	}
	for _, x := range r.Sections {
		out.Sections = append(out.Sections, PcapSectionDTO{Key: x.Key, Args: x.Args, Title: x.Title})
	}
	return out
}

// ToolsPcapReport es ToolsPcap con el informe estructurado además del texto.
func (b *Bridge) ToolsPcapReport(path string, top int) (PcapReportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PcapReportDTO, error) {
		r, err := v1.NewToolsServiceClient(c).AnalyzePcap(ctx, &v1.AnalyzePcapRequest{Path: path, Top: int32(top)})
		if err != nil {
			return PcapReportDTO{}, err
		}
		return pcapReport(r), nil
	})
}

// ---- Fase 30c-A: IKE, DNS y TLS estructurados ----

// FindingDTO es un hallazgo de DNS o TLS: code estable, severity cerrada, la clave del detalle (vacía si el detalle
// es un dato) con sus argumentos y el mensaje en el idioma de la interfaz.
type FindingDTO struct {
	Code     string            `json:"code"`
	Severity string            `json:"severity"` // warning, error, info
	Key      string            `json:"key,omitempty"`
	Args     map[string]string `json:"args,omitempty"`
	Message  string            `json:"message"`
}

// DnsReportDTO: text y json son los del informe, con el detalle de los hallazgos en el idioma de la interfaz.
type DnsReportDTO struct {
	Text     string       `json:"text"`
	Json     string       `json:"json"`
	Findings []FindingDTO `json:"findings"`
}

func (b *Bridge) ToolsDnsReport(d DnsDTO) (DnsReportDTO, error) {
	mode, ok := dnsModes[d.Mode]
	if !ok {
		return DnsReportDTO{}, wrapErr(fmt.Errorf("modo DNS %q desconocido", d.Mode))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (DnsReportDTO, error) {
		r, err := v1.NewToolsServiceClient(c).Dns(ctx, &v1.DnsRequest{Mode: mode, Name: d.Name, Type: d.Type, Servers: d.Servers, Deep: d.Deep, Dnssec: d.Dnssec})
		if err != nil {
			return DnsReportDTO{}, err
		}
		out := DnsReportDTO{Text: r.GetReport().GetText(), Json: r.GetReport().GetJson(), Findings: []FindingDTO{}}
		for _, f := range r.Findings {
			out.Findings = append(out.Findings, FindingDTO{Code: f.Code, Severity: f.Severity, Key: f.Key, Args: f.Args, Message: f.Message})
		}
		return out, nil
	})
}

// TlsReportDTO gana verifyCode: unknown_authority, hostname, expired, not_yet_valid, other; ausente si verificó. El
// verifyError del json es el texto de la biblioteca x509 y no se traduce.
type TlsReportDTO struct {
	Text       string       `json:"text"`
	Json       string       `json:"json"`
	Findings   []FindingDTO `json:"findings"`
	VerifyCode string       `json:"verifyCode,omitempty"`
}

func (b *Bridge) ToolsTlsReport(host string, port int, sni string) (TlsReportDTO, error) {
	if port < 0 || port > 65535 {
		return TlsReportDTO{}, wrapErr(fmt.Errorf("puerto %d inválido", port))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TlsReportDTO, error) {
		r, err := v1.NewToolsServiceClient(c).InspectTls(ctx, &v1.InspectTlsRequest{Host: host, Port: uint32(port), Sni: sni})
		if err != nil {
			return TlsReportDTO{}, err
		}
		out := TlsReportDTO{Text: r.GetReport().GetText(), Json: r.GetReport().GetJson(), Findings: []FindingDTO{}, VerifyCode: r.VerifyCode}
		for _, f := range r.Findings {
			out.Findings = append(out.Findings, FindingDTO{Code: f.Code, Severity: f.Severity, Key: f.Key, Args: f.Args, Message: f.Message})
		}
		return out, nil
	})
}

type IkeFindingDTO struct {
	Code           string            `json:"code"`
	Severity       string            `json:"severity"` // warning, error, info
	Phase          int               `json:"phase,omitempty"`
	Key            string            `json:"key"` // ike.finding.<código>; .title y .action; ver explanationKey
	ExplanationKey string            `json:"explanationKey"`
	Args           map[string]string `json:"args,omitempty"`
	Title          string            `json:"title"`
	Explanation    string            `json:"explanation"`
	Action         string            `json:"action"`
	Evidence       []string          `json:"evidence"`
}

type IkeProposalDTO struct {
	Phase      int               `json:"phase"`
	SourceKey  string            `json:"sourceKey"`
	SourceArgs map[string]string `json:"sourceArgs,omitempty"`
	Source     string            `json:"source"`
	Detail     string            `json:"detail"`
	Result     string            `json:"result,omitempty"` // accepted, rejected
}

// IkeReportDTO: phase1 y phase2 ∈ established, failed, mixed, incomplete, no_data.
type IkeReportDTO struct {
	Text      string           `json:"text"`
	Json      string           `json:"json"`
	Phase1    string           `json:"phase1"`
	Phase2    string           `json:"phase2"`
	Findings  []IkeFindingDTO  `json:"findings"`
	Proposals []IkeProposalDTO `json:"proposals"`
	Note      string           `json:"note"`
}

func (b *Bridge) SecIkeReport(text string) (IkeReportDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (IkeReportDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).IkeDecode(ctx, &v1.IkeDecodeRequest{Text: text})
		if err != nil {
			return IkeReportDTO{}, err
		}
		out := IkeReportDTO{Text: r.GetReport().GetText(), Json: r.GetReport().GetJson(), Phase1: r.Phase1, Phase2: r.Phase2, Note: r.Note, Findings: []IkeFindingDTO{}, Proposals: []IkeProposalDTO{}}
		for _, f := range r.Findings {
			out.Findings = append(out.Findings, IkeFindingDTO{Code: f.Code, Severity: f.Severity, Phase: int(f.Phase), Key: f.Key, ExplanationKey: f.ExplanationKey, Args: f.Args,
				Title: f.Title, Explanation: f.Explanation, Action: f.Action, Evidence: append([]string{}, f.Evidence...)})
		}
		for _, p := range r.Proposals {
			out.Proposals = append(out.Proposals, IkeProposalDTO{Phase: int(p.Phase), SourceKey: p.SourceKey, SourceArgs: p.SourceArgs, Source: p.Source, Detail: p.Detail, Result: p.Result})
		}
		return out, nil
	})
}
