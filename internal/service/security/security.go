package security

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/radiustest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tacacstest"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ikedec"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/pki"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

type securitySvc struct {
	v1.UnimplementedSecurityServiceServer
	d service.Deps
}

// secretFrom resuelve un secreto: la contraseña de una credencial de la bóveda
// (y su usuario) o el valor escrito. done lo borra; siempre es seguro llamarlo.
func secretFrom(d service.Deps, src *v1.SecretSource) (user string, val []byte, done func(), err error) {
	if src.GetCredentialId() == "" {
		v := src.GetValue()
		return "", v, func() { clear(v) }, nil
	}
	v := d.Vault()
	if v == nil {
		return "", nil, func() {}, status.Error(codes.FailedPrecondition, "no hay bóveda")
	}
	cr, err := v.Get(src.CredentialId)
	if err != nil {
		return "", nil, func() {}, service.VaultErr(err)
	}
	cr.Enable.Destroy()
	cr.SSHKey.Destroy()
	return cr.Username, cr.Password.Bytes(), cr.Password.Destroy, nil
}

// origin dice de dónde vino un secreto, para la auditoría; nunca el valor.
func origin(src *v1.SecretSource) string {
	if id := src.GetCredentialId(); id != "" {
		return "vault:" + id
	}
	return "typed"
}

func validHost(h string) error {
	if strings.TrimSpace(h) == "" || strings.HasPrefix(h, "-") {
		return status.Error(codes.InvalidArgument, "servidor inválido")
	}
	return nil
}

func port16(p uint32) (uint16, error) {
	if p > 0xffff {
		return 0, status.Error(codes.InvalidArgument, "puerto inválido")
	}
	return uint16(p), nil
}

func (s *securitySvc) RadiusTest(ctx context.Context, r *v1.RadiusTestRequest) (*v1.RadiusTestResponse, error) {
	s.d.MarkActive()
	if err := validHost(r.Host); err != nil {
		return nil, err
	}
	auth, err := port16(r.AuthPort)
	if err != nil {
		return nil, err
	}
	acct, err := port16(r.AcctPort)
	if err != nil {
		return nil, err
	}
	_, secret, sdone, err := secretFrom(s.d, r.SharedSecret)
	defer sdone()
	if err != nil {
		return nil, err
	}
	user, pw, pdone, err := secretFrom(s.d, r.Password)
	defer pdone()
	if err != nil {
		return nil, err
	}
	if r.Username != "" {
		user = r.Username
	}
	id := service.RunID("radius")
	defer s.d.Guard().Revoke(id)
	if err := s.d.Guard().Allow(ctx, id, []string{r.Host}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	cfg := radiustest.Config{Host: r.Host, AuthPort: auth, AcctPort: acct, Secret: secret, Username: user, Password: pw, Method: r.Method,
		NASIP: r.NasIp, NASIdentifier: r.NasIdentifier, NASPortType: r.NasPortType, ServiceType: r.ServiceType,
		CalledStationID: r.CalledStationId, CallingStationID: r.CallingStationId, StatusServer: r.StatusServer, Accounting: r.Accounting,
		Timeout: service.MS(r.TimeoutMs, 0), Retries: int(r.Retries)}
	s.d.Audit("security.radius", r.Host, fmt.Sprintf("run=%s ports=%d/%d method=%s user=%q secret=%s password=%s status-server=%t accounting=%t",
		id, auth, acct, r.Method, user, origin(r.SharedSecret), origin(r.Password), r.StatusServer, r.Accounting))
	rep, err := radiustest.Run(ctx, radiustest.Dialer(s.d.Guard().DialerFor(id)), cfg)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	var res []string
	for _, e := range rep.Exchanges {
		res = append(res, e.Kind+"="+map[bool]string{true: e.Code, false: "no-response"}[e.Code != ""])
	}
	s.d.Audit("security.radius.result", r.Host, id+" "+strings.Join(res, " "))
	loc := i18n.Locale(ctx)
	return &v1.RadiusTestResponse{Report: service.Report(rep, rep.TextIn(loc)), Server: rep.Server, Method: strings.ToUpper(rep.Method),
		Exchanges: radiusExchanges(loc, rep), Findings: radiusFindings(loc, rep)}, nil
}

func (s *securitySvc) TacacsTest(ctx context.Context, r *v1.TacacsTestRequest) (*v1.TacacsTestResponse, error) {
	s.d.MarkActive()
	if err := validHost(r.Host); err != nil {
		return nil, err
	}
	port, err := port16(r.Port)
	if err != nil {
		return nil, err
	}
	_, secret, sdone, err := secretFrom(s.d, r.SharedSecret)
	defer sdone()
	if err != nil {
		return nil, err
	}
	user, pw, pdone, err := secretFrom(s.d, r.Password)
	defer pdone()
	if err != nil {
		return nil, err
	}
	if r.Username != "" {
		user = r.Username
	}
	id := service.RunID("tacacs")
	defer s.d.Guard().Revoke(id)
	if err := s.d.Guard().Allow(ctx, id, []string{r.Host}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.d.Audit("security.tacacs", r.Host, fmt.Sprintf("run=%s port=%d type=%s user=%q secret=%s password=%s command=%q accounting=%t",
		id, port, r.AuthenType, user, origin(r.SharedSecret), origin(r.Password), r.Command, r.Accounting))
	rep, err := tacacstest.Run(ctx, tacacstest.Dialer(s.d.Guard().DialerFor(id)), tacacstest.Config{Host: r.Host, Port: port, Secret: secret,
		Username: user, Password: pw, AuthenType: r.AuthenType, PrivLvl: int(r.PrivLvl), Command: r.Command, Accounting: r.Accounting, Timeout: service.MS(r.TimeoutMs, 0)})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	var res []string
	for _, st := range rep.Steps {
		res = append(res, st.Kind+"="+map[bool]string{true: st.Status, false: "no-response"}[st.Status != ""])
	}
	s.d.Audit("security.tacacs.result", r.Host, id+" "+strings.Join(res, " "))
	loc := i18n.Locale(ctx)
	return &v1.TacacsTestResponse{Report: service.Report(rep, rep.TextIn(loc)), Server: rep.Server, Steps: tacacsSteps(loc, rep),
		Findings: tacacsFindings(loc, rep)}, nil
}

// ---- PKI de laboratorio (sin red) ----

func pkiErr(err error) error {
	switch {
	case errors.Is(err, vault.ErrWrongPassword):
		return status.Error(codes.PermissionDenied, "contraseña de la llave incorrecta")
	case errors.Is(err, vault.ErrWeakParams):
		return status.Error(codes.Internal, err.Error())
	}
	return status.Error(codes.InvalidArgument, err.Error())
}

func (s *securitySvc) newSealedKey(alg string, pw []byte) (crypto.Signer, string, error) {
	if alg == "" {
		alg = "p256"
	}
	k, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, "", pkiErr(err)
	}
	sealed, err := pki.SealKey(k, pw, s.d.SealParams())
	if err != nil {
		return nil, "", pkiErr(err)
	}
	return k, string(sealed), nil
}

// decoded arma el informe de un PEM recién generado; con lab, el texto abre con el aviso de CA de laboratorio.
func (s *securitySvc) decoded(ctx context.Context, pemText []byte, lab bool) (*v1.ToolReport, []*v1.PkiCertificate) {
	loc := i18n.Locale(ctx)
	sums, _ := pki.Decode(pemText, s.d.Now())
	txt := pki.TextIn(sums, loc)
	if lab {
		txt = i18n.Msg(loc, "security.pki.lab_warning", nil) + "\n\n" + txt
	}
	return service.Report(sums, txt), certificates(loc, sums)
}

func (s *securitySvc) PkiKey(_ context.Context, r *v1.PkiKeyRequest) (*v1.PkiKeyResponse, error) {
	s.d.MarkActive()
	defer clear(r.KeyPassword)
	_, sealed, err := s.newSealedKey(r.Algorithm, r.KeyPassword)
	if err != nil {
		return nil, err
	}
	s.d.Audit("pki.key", "", "algorithm="+r.Algorithm)
	return &v1.PkiKeyResponse{SealedKeyPem: sealed}, nil
}

func (s *securitySvc) PkiCsr(ctx context.Context, r *v1.PkiCsrRequest) (*v1.PkiCsrResponse, error) {
	s.d.MarkActive()
	defer clear(r.KeyPassword)
	var k crypto.Signer
	sealed, keyOrigin := r.SealedKeyPem, "existente"
	var err error
	if sealed == "" {
		if k, sealed, err = s.newSealedKey(r.Algorithm, r.KeyPassword); err != nil {
			return nil, err
		}
		keyOrigin = "nueva:" + r.Algorithm
	} else if k, err = pki.OpenKey([]byte(sealed), r.KeyPassword); err != nil {
		return nil, pkiErr(err)
	}
	sub := r.GetSubject()
	csr, err := pki.CreateCSR(k, pki.CSRRequest{Subject: pki.Subject{CN: sub.GetCn(), O: sub.GetO(), OU: sub.GetOu(), L: sub.GetL(), ST: sub.GetSt(), C: sub.GetC()}, DNS: r.Dns, IPs: r.Ips})
	if err != nil {
		return nil, pkiErr(err)
	}
	s.d.Audit("pki.csr", sub.GetCn(), fmt.Sprintf("key=%s san=%d", keyOrigin, len(r.Dns)+len(r.Ips)))
	rep, certs := s.decoded(ctx, csr, false)
	return &v1.PkiCsrResponse{CsrPem: string(csr), SealedKeyPem: sealed, Report: rep, Certificates: certs}, nil
}

func (s *securitySvc) PkiCaInit(ctx context.Context, r *v1.PkiCaInitRequest) (*v1.PkiCaInitResponse, error) {
	s.d.MarkActive()
	defer clear(r.KeyPassword)
	days := int(r.Days)
	if days == 0 {
		days = 3650
	}
	k, sealed, err := s.newSealedKey(r.Algorithm, r.KeyPassword)
	if err != nil {
		return nil, err
	}
	ca, err := pki.InitCA(k, r.Name, days, s.d.Now())
	if err != nil {
		return nil, pkiErr(err)
	}
	s.d.Audit("pki.ca.init", r.Name, fmt.Sprintf("days=%d algorithm=%s", days, r.Algorithm))
	rep, certs := s.decoded(ctx, ca, true)
	return &v1.PkiCaInitResponse{CaCertPem: string(ca), SealedKeyPem: sealed, Report: rep, Certificates: certs, LabWarning: true}, nil
}

func (s *securitySvc) PkiCaSign(ctx context.Context, r *v1.PkiCaSignRequest) (*v1.PkiCaSignResponse, error) {
	s.d.MarkActive()
	defer clear(r.CaKeyPassword)
	k, err := pki.OpenKey([]byte(r.CaSealedKeyPem), r.CaKeyPassword)
	if err != nil {
		return nil, pkiErr(err)
	}
	profile, days := r.Profile, int(r.Days)
	if profile == "" {
		profile = "server"
	}
	if days == 0 {
		days = 365
	}
	cert, err := pki.Sign([]byte(r.CaCertPem), k, []byte(r.CsrPem), profile, days, s.d.Now())
	if err != nil {
		return nil, pkiErr(err)
	}
	rep, certs := s.decoded(ctx, cert, true)
	sums, _ := pki.Decode(cert, s.d.Now())
	s.d.Audit("pki.ca.sign", sums[0].Subject, fmt.Sprintf("profile=%s days=%d serial=%s", profile, days, sums[0].Serial))
	return &v1.PkiCaSignResponse{CertPem: string(cert), Report: rep, Certificates: certs, LabWarning: true}, nil
}

func (s *securitySvc) PkiExport(_ context.Context, r *v1.PkiExportRequest) (*v1.PkiExportResponse, error) {
	s.d.MarkActive()
	defer clear(r.KeyPassword)
	defer clear(r.ExportPassword)
	keyNeeded := r.Format == "p12" || r.Format == "p12-legacy" || (r.Format == "pem" && r.IncludePlainKey)
	if r.Format == "pem" && r.SealedKeyPem != "" && !r.IncludePlainKey {
		return nil, status.Error(codes.InvalidArgument, "exportar la llave en claro requiere marcar include_plain_key")
	}
	var k crypto.Signer
	if keyNeeded {
		var err error
		if k, err = pki.OpenKey([]byte(r.SealedKeyPem), r.KeyPassword); err != nil {
			return nil, pkiErr(err)
		}
	}
	// shortcut: go-pkcs12 recibe la contraseña de exportación como string; esa copia no se puede borrar.
	out, err := pki.Export(r.Format, []byte(r.CertPem), []byte(r.ChainPem), k, string(r.ExportPassword))
	if err != nil {
		return nil, pkiErr(err)
	}
	s.d.Audit("pki.export", "", fmt.Sprintf("format=%s key=%s", r.Format, map[bool]string{true: "included", false: "no"}[k != nil]))
	return &v1.PkiExportResponse{Data: out}, nil
}

const maxPaste = 4 << 20

func (s *securitySvc) PkiDecode(ctx context.Context, r *v1.PkiDecodeRequest) (*v1.PkiDecodeResponse, error) {
	if len(r.Data) > maxPaste {
		return nil, status.Error(codes.InvalidArgument, "entrada demasiado grande")
	}
	sums, err := pki.Decode(r.Data, s.d.Now())
	if err != nil {
		return nil, pkiErr(err)
	}
	loc := i18n.Locale(ctx)
	return &v1.PkiDecodeResponse{Report: service.Report(sums, pki.TextIn(sums, loc)), Certificates: certificates(loc, sums)}, nil
}

// maxIkePaste acota el texto de debug IKE: el decodificador cuesta ~0,1 ms por línea.
const maxIkePaste = 1 << 20

func (s *securitySvc) IkeDecode(ctx context.Context, r *v1.IkeDecodeRequest) (*v1.IkeDecodeResponse, error) {
	if len(r.Text) > maxIkePaste {
		return nil, status.Error(codes.InvalidArgument, "entrada demasiado grande: el máximo es 1 MiB de texto de debug")
	}
	rep, err := ikedec.DecodeContext(ctx, r.Text)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	loc := i18n.Locale(ctx)
	return ikeResponse(rep, loc), nil
}

// Module registra el servicio Security.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterSecurityServiceServer(s, &securitySvc{d: d})
}
