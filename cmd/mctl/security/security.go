package security

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// hostPort separa HOST[:PUERTO] (o [IPv6]:PUERTO); sin puerto devuelve 0.
func hostPort(s string) (string, uint32, error) {
	h, p, ok := "", "", false
	if strings.HasPrefix(s, "[") {
		h, p, ok = strings.Cut(strings.TrimPrefix(s, "["), "]:")
	} else if strings.Count(s, ":") == 1 {
		h, p, ok = strings.Cut(s, ":")
	}
	if !ok {
		return strings.Trim(s, "[]"), 0, nil
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("puerto inválido %q", p)
	}
	return h, uint32(n), nil
}

// source pide el secreto sin eco salvo que venga de la bóveda.
func source(c *cli.Env, credID, prompt string) (*v1.SecretSource, error) {
	if credID != "" {
		return &v1.SecretSource{CredentialId: credID}, nil
	}
	b, err := c.Secret(prompt)
	return &v1.SecretSource{Value: b}, err
}

// newPassword pide dos veces la contraseña que sellará una llave nueva: un error de dedo la pierde.
func newPassword(c *cli.Env, prompt string) ([]byte, error) {
	a, err := c.Secret(prompt)
	if err != nil {
		return nil, err
	}
	b, err := c.Secret("Repite la contraseña: ")
	if err != nil {
		cli.Wipe(a)
		return nil, err
	}
	defer cli.Wipe(b)
	if string(a) != string(b) {
		cli.Wipe(a)
		return nil, errors.New("las contraseñas no coinciden")
	}
	return a, nil
}

// writeNew nunca sobrescribe: perder una llave sellada no tiene vuelta.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func radiusTest(c *cli.Env, args []string) error {
	var user, cred, secretCred, method, nasIP, nasID, portType, svcType, called, calling string
	var acctPort, timeout, retries int
	var status, acct, asJSON bool
	fs, err := cli.Flags("radius test", args, func(fs *flag.FlagSet) {
		fs.StringVar(&user, "user", "", "usuario de prueba")
		fs.StringVar(&cred, "cred", "", "credencial de la bóveda con usuario y contraseña de prueba")
		fs.StringVar(&secretCred, "secret-cred", "", "credencial de la bóveda cuya contraseña es el secreto compartido")
		fs.StringVar(&method, "method", "pap", "pap, chap o mschapv2")
		fs.StringVar(&nasIP, "nas-ip", "", "NAS-IP-Address")
		fs.StringVar(&nasID, "nas-id", "", "NAS-Identifier")
		fs.StringVar(&portType, "port-type", "", "NAS-Port-Type (Ethernet, Wireless-802.11, Virtual… o número)")
		fs.StringVar(&svcType, "service-type", "", "Service-Type (Framed, Login, Call-Check… o número)")
		fs.StringVar(&called, "called", "", "Called-Station-Id")
		fs.StringVar(&calling, "calling", "", "Calling-Station-Id (MAC del cliente)")
		fs.IntVar(&acctPort, "acct-port", 0, "puerto de accounting (1813)")
		fs.BoolVar(&status, "status", false, "solo Status-Server (RFC 5997)")
		fs.BoolVar(&acct, "acct", false, "Accounting Start y Stop")
		fs.IntVar(&timeout, "timeout", 0, "milisegundos por intento")
		fs.IntVar(&retries, "retries", 0, "reintentos")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl radius test SERVIDOR[:PUERTO] --user U [--cred ID] [--secret-cred ID] [--method pap|chap|mschapv2] [--acct] [--status]")
	}
	host, port, err := hostPort(fs.Arg(0))
	if err != nil {
		return err
	}
	if acctPort < 0 || acctPort > 0xffff {
		return errors.New("--acct-port inválido")
	}
	req := &v1.RadiusTestRequest{Host: host, AuthPort: port, AcctPort: uint32(acctPort), Username: user, Method: method, NasIp: nasIP,
		NasIdentifier: nasID, NasPortType: portType, ServiceType: svcType, CalledStationId: called, CallingStationId: calling,
		StatusServer: status, Accounting: acct, TimeoutMs: int32(timeout), Retries: int32(retries)}
	if req.SharedSecret, err = source(c, secretCred, "Secreto compartido RADIUS: "); err != nil {
		return err
	}
	defer cli.Wipe(req.SharedSecret.Value)
	if !status {
		if user == "" && cred == "" {
			return errors.New("falta --user o --cred")
		}
		if req.Password, err = source(c, cred, "Contraseña de prueba: "); err != nil {
			return err
		}
		defer cli.Wipe(req.Password.Value)
	}
	r, err := v1.NewSecurityServiceClient(c.Conn).RadiusTest(context.Background(), req)
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func tacacsTest(c *cli.Env, args []string) error {
	var user, cred, secretCred, typ, cmd string
	var priv, timeout int
	var acct, asJSON bool
	fs, err := cli.Flags("tacacs test", args, func(fs *flag.FlagSet) {
		fs.StringVar(&user, "user", "", "usuario de prueba")
		fs.StringVar(&cred, "cred", "", "credencial de la bóveda con usuario y contraseña de prueba")
		fs.StringVar(&secretCred, "secret-cred", "", "credencial de la bóveda cuya contraseña es el secreto compartido")
		fs.StringVar(&typ, "type", "ascii", "ascii o pap")
		fs.StringVar(&cmd, "cmd", "", "comando a autorizar, p. ej. \"show running-config\"")
		fs.IntVar(&priv, "priv", 0, "nivel de privilegio (1 por defecto)")
		fs.BoolVar(&acct, "acct", false, "Accounting Start y Stop")
		fs.IntVar(&timeout, "timeout", 0, "milisegundos por paso")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || (user == "" && cred == "") {
		return errors.New("uso: mctl tacacs test SERVIDOR[:PUERTO] --user U [--cred ID] [--secret-cred ID] [--type ascii|pap] [--cmd COMANDO] [--acct]")
	}
	host, port, err := hostPort(fs.Arg(0))
	if err != nil {
		return err
	}
	req := &v1.TacacsTestRequest{Host: host, Port: port, Username: user, AuthenType: typ, Command: cmd, Accounting: acct, PrivLvl: int32(priv), TimeoutMs: int32(timeout)}
	if req.SharedSecret, err = source(c, secretCred, "Secreto compartido TACACS+: "); err != nil {
		return err
	}
	defer cli.Wipe(req.SharedSecret.Value)
	if req.Password, err = source(c, cred, "Contraseña de prueba: "); err != nil {
		return err
	}
	defer cli.Wipe(req.Password.Value)
	r, err := v1.NewSecurityServiceClient(c.Conn).TacacsTest(context.Background(), req)
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func pkiKey(c *cli.Env, args []string) error {
	var alg, out string
	if _, err := cli.Flags("pki key", args, func(fs *flag.FlagSet) {
		fs.StringVar(&alg, "alg", "p256", "rsa2048, rsa3072, rsa4096, p256 o p384")
		fs.StringVar(&out, "o", "", "archivo de la llave sellada")
	}); err != nil {
		return err
	}
	if out == "" {
		return errors.New("falta -o ARCHIVO")
	}
	pw, err := newPassword(c, "Contraseña para sellar la llave: ")
	if err != nil {
		return err
	}
	defer cli.Wipe(pw)
	r, err := v1.NewSecurityServiceClient(c.Conn).PkiKey(context.Background(), &v1.PkiKeyRequest{Algorithm: alg, KeyPassword: pw})
	if err != nil {
		return err
	}
	if err := writeNew(out, []byte(r.SealedKeyPem)); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "llave sellada en %s\n", out)
	return nil
}

func pkiCsr(c *cli.Env, args []string) error {
	var sub v1.PkiSubject
	var dns, ips cli.List
	var key, alg, prefix string
	var asJSON bool
	if _, err := cli.Flags("pki csr", args, func(fs *flag.FlagSet) {
		fs.StringVar(&sub.Cn, "cn", "", "Common Name")
		fs.StringVar(&sub.O, "org", "", "Organization (O)")
		fs.StringVar(&sub.Ou, "ou", "", "Organizational Unit")
		fs.StringVar(&sub.L, "l", "", "Locality")
		fs.StringVar(&sub.St, "st", "", "State/Province")
		fs.StringVar(&sub.C, "c", "", "país (2 letras)")
		fs.Var(&dns, "dns", "SAN DNS (repetible)")
		fs.Var(&ips, "ip", "SAN IP (repetible)")
		fs.StringVar(&key, "key", "", "llave sellada existente (vacío = generar una nueva)")
		fs.StringVar(&alg, "alg", "p256", "algoritmo de la llave nueva")
		fs.StringVar(&prefix, "o", "", "prefijo de salida: PREFIJO.csr.pem y PREFIJO.key.pem (por defecto el CN)")
		fs.BoolVar(&asJSON, "json", false, "resumen en JSON")
	}); err != nil {
		return err
	}
	if sub.Cn == "" {
		return errors.New("falta --cn")
	}
	if prefix == "" {
		prefix = sub.Cn
	}
	req := &v1.PkiCsrRequest{Algorithm: alg, Subject: &sub, Dns: dns, Ips: ips}
	var pw []byte
	var err error
	if key != "" {
		b, err := os.ReadFile(key)
		if err != nil {
			return err
		}
		req.SealedKeyPem = string(b)
		pw, err = c.Secret("Contraseña de la llave: ")
		if err != nil {
			return err
		}
	} else {
		// Fallar antes de pedir contraseñas si ya hay archivos con ese prefijo.
		for _, f := range []string{prefix + ".csr.pem", prefix + ".key.pem"} {
			if _, err := os.Stat(f); err == nil {
				return fmt.Errorf("%s ya existe", f)
			}
		}
		if pw, err = newPassword(c, "Contraseña para sellar la llave nueva: "); err != nil {
			return err
		}
	}
	defer cli.Wipe(pw)
	req.KeyPassword = pw
	r, err := v1.NewSecurityServiceClient(c.Conn).PkiCsr(context.Background(), req)
	if err != nil {
		return err
	}
	if err := writeNew(prefix+".csr.pem", []byte(r.CsrPem)); err != nil {
		return err
	}
	if key == "" {
		if err := writeNew(prefix+".key.pem", []byte(r.SealedKeyPem)); err != nil {
			return err
		}
	}
	c.PrintReport(r.Report, asJSON)
	fmt.Fprintf(c.Out, "CSR en %s.csr.pem\n", prefix)
	return nil
}

func pkiCa(c *cli.Env, args []string) error {
	if len(args) == 0 {
		return errors.New("uso: mctl pki ca init|sign")
	}
	switch args[0] {
	case "init":
		return pkiCaInit(c, args[1:])
	case "sign":
		return pkiCaSign(c, args[1:])
	}
	return errors.New("uso: mctl pki ca init|sign")
}

func pkiCaInit(c *cli.Env, args []string) error {
	var name, alg, dir string
	var days int
	if _, err := cli.Flags("pki ca init", args, func(fs *flag.FlagSet) {
		fs.StringVar(&name, "name", "", "nombre de la CA")
		fs.IntVar(&days, "days", 3650, "validez en días")
		fs.StringVar(&alg, "alg", "p256", "algoritmo de la llave")
		fs.StringVar(&dir, "out", "ca-lab", "carpeta de la CA")
	}); err != nil {
		return err
	}
	if name == "" {
		return errors.New("falta --name")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	pw, err := newPassword(c, "Contraseña para sellar la llave de la CA: ")
	if err != nil {
		return err
	}
	defer cli.Wipe(pw)
	r, err := v1.NewSecurityServiceClient(c.Conn).PkiCaInit(context.Background(), &v1.PkiCaInitRequest{Name: name, Days: int32(days), Algorithm: alg, KeyPassword: pw})
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "ca.crt.pem"), []byte(r.CaCertPem)); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, "ca.key.pem"), []byte(r.SealedKeyPem)); err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.Report.Text)
	fmt.Fprintf(c.Out, "CA en %s/ (ca.crt.pem, ca.key.pem sellada)\n", dir)
	return nil
}

func pkiCaSign(c *cli.Env, args []string) error {
	var dir, csr, profile, out string
	var days int
	if _, err := cli.Flags("pki ca sign", args, func(fs *flag.FlagSet) {
		fs.StringVar(&dir, "ca", "ca-lab", "carpeta de la CA")
		fs.StringVar(&csr, "csr", "", "CSR en PEM")
		fs.StringVar(&profile, "profile", "server", "server, client o server-client")
		fs.IntVar(&days, "days", 365, "validez en días")
		fs.StringVar(&out, "o", "", "certificado de salida")
	}); err != nil {
		return err
	}
	if csr == "" || out == "" {
		return errors.New("uso: mctl pki ca sign --ca CARPETA --csr CSR.pem -o CERT.pem [--profile server|client|server-client] [--days N]")
	}
	read := func(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }
	caCert, err := read(filepath.Join(dir, "ca.crt.pem"))
	if err != nil {
		return err
	}
	caKey, err := read(filepath.Join(dir, "ca.key.pem"))
	if err != nil {
		return err
	}
	csrPEM, err := read(csr)
	if err != nil {
		return err
	}
	pw, err := c.Secret("Contraseña de la llave de la CA: ")
	if err != nil {
		return err
	}
	defer cli.Wipe(pw)
	r, err := v1.NewSecurityServiceClient(c.Conn).PkiCaSign(context.Background(), &v1.PkiCaSignRequest{CaCertPem: caCert, CaSealedKeyPem: caKey, CaKeyPassword: pw, CsrPem: csrPEM, Profile: profile, Days: int32(days)})
	if err != nil {
		return err
	}
	if err := writeNew(out, []byte(r.CertPem)); err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.Report.Text)
	fmt.Fprintf(c.Out, "certificado en %s\n", out)
	return nil
}

func pkiExport(c *cli.Env, args []string) error {
	var cert, chain, key, format, out string
	var plain bool
	if _, err := cli.Flags("pki export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&cert, "cert", "", "certificado PEM")
		fs.StringVar(&chain, "chain", "", "cadena PEM (p. ej. ca.crt.pem)")
		fs.StringVar(&key, "key", "", "llave sellada")
		fs.StringVar(&format, "format", "p12", "p12, p12-legacy (3DES, equipos viejos), pem o der")
		fs.BoolVar(&plain, "plain-key", false, "pem: incluir la llave SIN cifrar")
		fs.StringVar(&out, "o", "", "archivo de salida")
	}); err != nil {
		return err
	}
	if cert == "" || out == "" {
		return errors.New("uso: mctl pki export --cert CERT.pem [--chain CA.pem] [--key LLAVE.pem] --format p12|p12-legacy|pem|der -o SALIDA")
	}
	req := &v1.PkiExportRequest{Format: format, IncludePlainKey: plain}
	for p, dst := range map[string]*string{cert: &req.CertPem, chain: &req.ChainPem, key: &req.SealedKeyPem} {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		*dst = string(b)
	}
	if key != "" && (strings.HasPrefix(format, "p12") || plain) {
		pw, err := c.Secret("Contraseña de la llave: ")
		if err != nil {
			return err
		}
		defer cli.Wipe(pw)
		req.KeyPassword = pw
	}
	if strings.HasPrefix(format, "p12") {
		pw, err := newPassword(c, "Contraseña del PKCS#12: ")
		if err != nil {
			return err
		}
		defer cli.Wipe(pw)
		req.ExportPassword = pw
	}
	r, err := v1.NewSecurityServiceClient(c.Conn).PkiExport(context.Background(), req)
	if err != nil {
		return err
	}
	if err := writeNew(out, r.Data); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "exportado a %s\n", out)
	return nil
}

func fileArg(c *cli.Env, name string, args []string, asJSON *bool) ([]byte, error) {
	var file string
	fs, err := cli.Flags(name, args, func(fs *flag.FlagSet) {
		fs.StringVar(&file, "f", "", "archivo")
		fs.BoolVar(asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return nil, err
	}
	if file == "" && fs.NArg() == 1 {
		file = fs.Arg(0)
	}
	if file == "" {
		return nil, fmt.Errorf("uso: mctl %s -f ARCHIVO [--json]", name)
	}
	return os.ReadFile(file)
}

func pkiDecode(c *cli.Env, args []string) error {
	var asJSON bool
	b, err := fileArg(c, "pki decode", args, &asJSON)
	if err != nil {
		return err
	}
	r, err := v1.NewSecurityServiceClient(c.Conn).PkiDecode(context.Background(), &v1.PkiDecodeRequest{Data: b})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

func ikeDecode(c *cli.Env, args []string) error {
	var asJSON bool
	b, err := fileArg(c, "ike decode", args, &asJSON)
	if err != nil {
		return err
	}
	r, err := v1.NewSecurityServiceClient(c.Conn).IkeDecode(context.Background(), &v1.IkeDecodeRequest{Text: string(b)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  radius test SERVIDOR[:PUERTO] --user U|--cred ID [--secret-cred ID] [--method pap|chap|mschapv2]
        [--nas-ip IP] [--port-type T] [--service-type T] [--called X] [--calling MAC] [--acct] [--status]
  tacacs test SERVIDOR[:PUERTO] --user U|--cred ID [--secret-cred ID] [--type ascii|pap] [--cmd COMANDO] [--acct]
  pki   key --alg A -o LLAVE | csr --cn CN [--dns D]... [--ip IP]... [--key LLAVE] [-o PREFIJO]
        ca init --name N [--days D] [--out CARPETA] | ca sign --ca CARPETA --csr CSR -o CERT [--profile P]
        export --cert C [--chain CA] [--key LLAVE] --format p12|p12-legacy|pem|der -o SALIDA | decode -f ARCHIVO
  ike   decode -f ARCHIVO [--json]   (debug/show de IKEv1, IKEv2 e IPsec)`

// Area registra los comandos de security.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "radius test", Run: radiusTest},
		{Name: "tacacs test", Run: tacacsTest},
		{Name: "pki key", Run: pkiKey},
		{Name: "pki csr", Run: pkiCsr},
		{Name: "pki ca", Run: pkiCa},
		{Name: "pki export", Run: pkiExport},
		{Name: "pki decode", Run: pkiDecode},
		{Name: "ike decode", Run: ikeDecode},
	}}
}
