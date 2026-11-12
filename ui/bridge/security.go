package bridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Seguridad (RADIUS, TACACS+, PKI de laboratorio, IKE) ----
// Los secretos llegan del webview como string (mismo límite declarado que la bóveda)
// y solo viajan hacia el núcleo; nada de lo que vuelve los contiene.

func source(credID, value string) *v1.SecretSource {
	if credID != "" {
		return &v1.SecretSource{CredentialId: credID}
	}
	return &v1.SecretSource{Value: []byte(value)}
}

func port(p int) (uint32, error) {
	if p < 0 || p > 65535 {
		return 0, fmt.Errorf("puerto %d inválido", p)
	}
	return uint32(p), nil
}

type RadiusDTO struct {
	Host         string `json:"host"`
	AuthPort     int    `json:"authPort"`
	AcctPort     int    `json:"acctPort"`
	SecretCredID string `json:"secretCredId"`
	Secret       string `json:"secret"`
	CredID       string `json:"credId"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Method       string `json:"method"`
	NasIP        string `json:"nasIp"`
	NasID        string `json:"nasId"`
	PortType     string `json:"portType"`
	ServiceType  string `json:"serviceType"`
	Called       string `json:"called"`
	Calling      string `json:"calling"`
	StatusServer bool   `json:"statusServer"`
	Accounting   bool   `json:"accounting"`
}

func (b *Bridge) SecRadius(d RadiusDTO) (string, error) {
	ap, err := port(d.AuthPort)
	if err != nil {
		return "", wrapErr(err)
	}
	cp, err := port(d.AcctPort)
	if err != nil {
		return "", wrapErr(err)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewSecurityServiceClient(c).RadiusTest(ctx, &v1.RadiusTestRequest{Host: d.Host, AuthPort: ap, AcctPort: cp,
			SharedSecret: source(d.SecretCredID, d.Secret), Username: d.Username, Password: source(d.CredID, d.Password), Method: d.Method,
			NasIp: d.NasIP, NasIdentifier: d.NasID, NasPortType: d.PortType, ServiceType: d.ServiceType, CalledStationId: d.Called,
			CallingStationId: d.Calling, StatusServer: d.StatusServer, Accounting: d.Accounting})
		return r.GetReport().GetText(), err
	})
}

type TacacsDTO struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	SecretCredID string `json:"secretCredId"`
	Secret       string `json:"secret"`
	CredID       string `json:"credId"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	AuthenType   string `json:"authenType"`
	Command      string `json:"command"`
	Accounting   bool   `json:"accounting"`
}

func (b *Bridge) SecTacacs(d TacacsDTO) (string, error) {
	p, err := port(d.Port)
	if err != nil {
		return "", wrapErr(err)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewSecurityServiceClient(c).TacacsTest(ctx, &v1.TacacsTestRequest{Host: d.Host, Port: p, SharedSecret: source(d.SecretCredID, d.Secret),
			Username: d.Username, Password: source(d.CredID, d.Password), AuthenType: d.AuthenType, Command: d.Command, Accounting: d.Accounting})
		return r.GetReport().GetText(), err
	})
}

func (b *Bridge) SecIkeDecode(text string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewSecurityServiceClient(c).IkeDecode(ctx, &v1.IkeDecodeRequest{Text: text})
		return r.GetReport().GetText(), err
	})
}

func (b *Bridge) SecPkiDecode(text string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewSecurityServiceClient(c).PkiDecode(ctx, &v1.PkiDecodeRequest{Data: []byte(text)})
		return r.GetReport().GetText(), err
	})
}

// PkiResultDTO: pem es el CSR o certificado; key, la llave sellada (nunca en claro).
type PkiResultDTO struct {
	Pem  string `json:"pem"`
	Key  string `json:"key"`
	Text string `json:"text"`
}

type CsrDTO struct {
	Cn          string   `json:"cn"`
	O           string   `json:"o"`
	Ou          string   `json:"ou"`
	L           string   `json:"l"`
	St          string   `json:"st"`
	C           string   `json:"c"`
	Dns         []string `json:"dns"`
	Ips         []string `json:"ips"`
	Algorithm   string   `json:"algorithm"`
	SealedKey   string   `json:"sealedKey"`
	KeyPassword string   `json:"keyPassword"`
}

func (b *Bridge) SecPkiCsr(d CsrDTO) (PkiResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PkiResultDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).PkiCsr(ctx, &v1.PkiCsrRequest{SealedKeyPem: d.SealedKey, Algorithm: d.Algorithm, KeyPassword: []byte(d.KeyPassword),
			Subject: &v1.PkiSubject{Cn: d.Cn, O: d.O, Ou: d.Ou, L: d.L, St: d.St, C: d.C}, Dns: d.Dns, Ips: d.Ips})
		return PkiResultDTO{Pem: r.GetCsrPem(), Key: r.GetSealedKeyPem(), Text: r.GetReport().GetText()}, err
	})
}

func (b *Bridge) SecPkiCaInit(name string, days int, algorithm, keyPassword string) (PkiResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PkiResultDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).PkiCaInit(ctx, &v1.PkiCaInitRequest{Name: name, Days: int32(days), Algorithm: algorithm, KeyPassword: []byte(keyPassword)})
		return PkiResultDTO{Pem: r.GetCaCertPem(), Key: r.GetSealedKeyPem(), Text: r.GetReport().GetText()}, err
	})
}

func (b *Bridge) SecPkiCaSign(caCert, caKey, caKeyPassword, csr, profile string, days int) (PkiResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PkiResultDTO, error) {
		r, err := v1.NewSecurityServiceClient(c).PkiCaSign(ctx, &v1.PkiCaSignRequest{CaCertPem: caCert, CaSealedKeyPem: caKey,
			CaKeyPassword: []byte(caKeyPassword), CsrPem: csr, Profile: profile, Days: int32(days)})
		return PkiResultDTO{Pem: r.GetCertPem(), Text: r.GetReport().GetText()}, err
	})
}

type ExportDTO struct {
	Format         string `json:"format"`
	Cert           string `json:"cert"`
	Chain          string `json:"chain"`
	SealedKey      string `json:"sealedKey"`
	KeyPassword    string `json:"keyPassword"`
	ExportPassword string `json:"exportPassword"`
	PlainKey       bool   `json:"plainKey"`
	Path           string `json:"path"` // absoluta; nunca se sobrescribe
}

// SecPkiExport escribe el archivo (0600) en la ruta indicada: el webview no tiene
// una descarga confiable para binarios como PKCS#12.
func (b *Bridge) SecPkiExport(d ExportDTO) (string, error) {
	if !filepath.IsAbs(d.Path) {
		return "", wrapErr(fmt.Errorf("la ruta de salida debe ser absoluta"))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewSecurityServiceClient(c).PkiExport(ctx, &v1.PkiExportRequest{Format: d.Format, CertPem: d.Cert, ChainPem: d.Chain,
			SealedKeyPem: d.SealedKey, KeyPassword: []byte(d.KeyPassword), ExportPassword: []byte(d.ExportPassword), IncludePlainKey: d.PlainKey})
		if err != nil {
			return "", err
		}
		f, err := os.OpenFile(d.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return "", err
		}
		if _, err := f.Write(r.Data); err != nil {
			f.Close()
			return "", err
		}
		return d.Path, f.Close()
	})
}
