package transfer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	xfer "github.com/oom-netsec/MACUAHUITL/internal/diag/transfer"
	"github.com/oom-netsec/MACUAHUITL/internal/imgverify"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// job es lo que comparten get y put: la URL, la autorización en el guard, la credencial y la
// conexión SSH si hace falta. Todo lo abierto se cierra en done.
type job struct {
	id    string
	u     *url.URL
	req   xfer.Request
	label string // URL sin credenciales, para la auditoría
	wipe  func()
	done  func()
}

// errText es el error para la bitácora sin la query de ninguna URL: la de *url.Error (también la de
// una redirección) y la de la URL pedida, por si el texto la cita por otro lado.
func (j *job) errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			u.User, u.RawQuery, u.ForceQuery, u.Fragment = nil, "", false, ""
			err = &url.Error{Op: ue.Op, URL: u.String(), Err: ue.Err}
		}
	}
	msg := err.Error()
	if q := j.u.RawQuery; q != "" {
		msg = strings.ReplaceAll(strings.ReplaceAll(msg, "?"+q, ""), q, "")
	}
	return msg
}

// connErr traduce los errores de conexión a códigos gRPC; la huella de una llave nueva va en el mensaje.
func connErr(err error) error {
	var he *transport.HostKeyError
	switch {
	case errors.As(err, &he):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, transport.ErrAuth), errors.Is(err, transport.ErrEgressDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if s := service.VaultErr(err); status.Code(s) != codes.Internal {
		return s
	}
	return status.Error(codes.Unavailable, err.Error())
}

// open prepara el trabajo. A partir de aquí todo camino de salida debe llamar j.done().
func (s *svc) open(ctx context.Context, rawURL, credID string, accepted []string, legacy bool) (*job, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil, bad("URL inválida %q", rawURL)
	}
	if _, err := xfer.Port(u); err != nil {
		return nil, bad("%v", err)
	}
	if _, has := u.User.Password(); has {
		return nil, bad("no pongas la contraseña en la URL: usa una credencial de la bóveda (--cred)")
	}
	if s.ctx.Err() != nil {
		return nil, status.Error(codes.Unavailable, "el núcleo se está cerrando")
	}
	if s.clients.Add(1) > maxClients {
		s.clients.Add(-1)
		return nil, status.Errorf(codes.ResourceExhausted, "máximo %d transferencias de cliente a la vez", maxClients)
	}
	clean := *u
	clean.User, clean.RawQuery, clean.ForceQuery, clean.Fragment = nil, "", false, "" // la query suele llevar tokens
	j := &job{id: "xfer-" + service.NewID(), u: u, label: clean.String()}
	g := s.d.Guard()
	j.done = func() {
		if j.wipe != nil {
			j.wipe()
		}
		g.Revoke(j.id)
		s.clients.Add(-1)
	}
	if err := g.Allow(ctx, j.id, []string{u.Hostname()}); err != nil {
		j.done()
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	j.req = xfer.Request{URL: u, Net: xfer.GuardNet(g, j.id)}
	switch u.Scheme {
	case "scp", "sftp", "ftp":
		if credID == "" && u.Scheme != "ftp" {
			j.done()
			return nil, bad("%s necesita una credencial de la bóveda (--cred)", u.Scheme)
		}
	}
	if credID == "" {
		return j, nil
	}
	v := s.d.Vault()
	if v == nil || !v.Unlocked() {
		j.done()
		return nil, status.Error(codes.FailedPrecondition, "abre la bóveda: la transferencia necesita la credencial")
	}
	cred, err := v.Get(credID)
	if err != nil {
		j.done()
		return nil, service.VaultErr(err)
	}
	j.wipe = func() { cred.Password.Destroy(); cred.SSHKey.Destroy(); cred.Enable.Destroy() }
	cred.Enable.Destroy()
	switch u.Scheme {
	case "ftp":
		if cred.Password.Empty() {
			j.done()
			return nil, bad("la credencial no tiene contraseña")
		}
		// Límite declarado: x/net/textproto manda el texto; la copia se pierde al terminar la orden.
		j.req.User, j.req.Pass = cred.Username, string(cred.Password.Bytes())
	case "scp", "sftp":
		acc := map[string]bool{}
		for _, fp := range accepted {
			acc[fp] = true
		}
		hk := s.d.Hosts().Callback(transport.HostKeyPolicy{Accepted: acc}, func(en audit.Entry) { s.d.Audit(en.Action, en.Target, en.Detail) })
		port, _ := xfer.Port(u)
		opts := transport.SSHOptions{AllowLegacy: legacy, OnLegacy: func(n string) { s.d.Audit("transfer.ssh.legacy", j.label, n) }}
		// OpenSSH destruye la contraseña y la llave al volver; se llama una sola vez, desde el cliente.
		j.req.SSH = func(ctx context.Context) (xfer.SSHSession, error) {
			return transport.OpenSSH(ctx, g, j.id, u.Hostname(), port, cred, hk, opts)
		}
	default:
		j.wipe()
	}
	return j, nil
}

func (s *svc) limits(maxBytes int64, secs int32) (int64, time.Duration, error) {
	if maxBytes < 0 || secs < 0 {
		return 0, 0, bad("tope inválido")
	}
	to := time.Duration(secs) * time.Second
	if to > xfer.MaxTimeout {
		return 0, 0, bad("el tiempo máximo es %s", xfer.MaxTimeout)
	}
	return maxBytes, to, nil
}

func (s *svc) Get(ctx context.Context, r *v1.GetRequest) (*v1.GetResponse, error) {
	return s.get(ctx, r, nil)
}

// get es Get con aviso de avance opcional (el mismo para el stream y el lote).
func (s *svc) get(ctx context.Context, r *v1.GetRequest, onProgress func(xfer.Progress)) (*v1.GetResponse, error) {
	s.d.MarkActive()
	max, to, err := s.limits(r.MaxBytes, r.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	dest := r.DestDir
	if dest == "" {
		if dest, err = s.receiveDir(service.NewID()); err != nil {
			return nil, err
		}
	}
	if _, err := fileserve.ValidateDir(dest); err != nil { // errores de uso antes de tocar la red
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	j, err := s.open(ctx, r.Url, r.CredentialId, r.AcceptedHostKeyFingerprints, r.LegacySsh)
	if err != nil {
		return nil, err
	}
	defer j.done()
	if r.Insecure && j.u.Scheme != "https" {
		return nil, bad("--insecure solo aplica a https")
	}
	j.req.DestDir, j.req.Name, j.req.WantSHA256, j.req.WantMD5 = dest, r.Name, r.Sha256, r.Md5
	j.req.MaxBytes, j.req.Timeout, j.req.Insecure, j.req.OnProgress = max, to, r.Insecure, onProgress
	s.d.Audit("transfer.get.start", j.label, fmt.Sprintf("trabajo=%s destino=%q credencial=%q insecure=%t ssh_antiguo=%t", j.id, dest, r.CredentialId, r.Insecure, r.LegacySsh))
	res, err := xfer.Download(ctx, j.req)
	if err == nil && r.Sha512 != "" { // SHA-512 de Cisco: lo verifica imgverify, el mismo de field hash
		var ir imgverify.Result
		if ir, err = imgverify.Check(res.Path, "", r.Sha512); err == nil && !ir.OK() {
			err = fmt.Errorf("el SHA-512 no coincide con el publicado (%s): se descartó el archivo", ir.SHA512)
		}
		if err != nil {
			os.Remove(res.Path)
			res.Verified = "distinto"
		} else if res.Verified == "" {
			res.Verified = "ok"
		}
	}
	if err != nil {
		s.d.Audit("transfer.get.failed", j.label, fmt.Sprintf("trabajo=%s destino=%q razon=%q verificado=%s guard=revocado", j.id, dest, j.errText(err), res.Verified))
		return nil, connErr(err)
	}
	s.d.Audit("transfer.get", j.label, fmt.Sprintf("trabajo=%s ruta=%q bytes=%d sha256=%s md5=%s verificado=%s duración=%s guard=revocado", j.id, res.Path, res.Bytes, res.SHA256, res.MD5, res.Verified, res.Duration.Round(time.Millisecond)))
	return &v1.GetResponse{Result: result(res, "guardado")}, nil
}

func (s *svc) Put(ctx context.Context, r *v1.PutRequest) (*v1.PutResponse, error) {
	return s.put(ctx, r, nil)
}

func (s *svc) put(ctx context.Context, r *v1.PutRequest, onProgress func(xfer.Progress)) (*v1.PutResponse, error) {
	s.d.MarkActive()
	max, to, err := s.limits(r.MaxBytes, r.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	if f, _, err := fileserve.OpenFrom(r.FromDir, r.Name); err != nil { // errores de uso antes de tocar la red
		return nil, status.Error(codes.InvalidArgument, err.Error())
	} else {
		f.Close()
	}
	j, err := s.open(ctx, r.Url, r.CredentialId, r.AcceptedHostKeyFingerprints, r.LegacySsh)
	if err != nil {
		return nil, err
	}
	defer j.done()
	j.req.FromDir, j.req.Name, j.req.MaxBytes, j.req.Timeout, j.req.OnProgress = r.FromDir, r.Name, max, to, onProgress
	s.d.Audit("transfer.put.start", j.label, fmt.Sprintf("trabajo=%s carpeta=%q archivo=%q credencial=%q ssh_antiguo=%t", j.id, r.FromDir, r.Name, r.CredentialId, r.LegacySsh))
	res, err := xfer.Upload(ctx, j.req)
	if err != nil {
		s.d.Audit("transfer.put.failed", j.label, fmt.Sprintf("trabajo=%s carpeta=%q archivo=%q razon=%q guard=revocado", j.id, r.FromDir, r.Name, j.errText(err)))
		return nil, connErr(err)
	}
	s.d.Audit("transfer.put", j.label, fmt.Sprintf("trabajo=%s ruta=%q bytes=%d sha256=%s md5=%s duración=%s guard=revocado", j.id, res.Path, res.Bytes, res.SHA256, res.MD5, res.Duration.Round(time.Millisecond)))
	return &v1.PutResponse{Result: result(res, "enviado")}, nil
}

func result(r xfer.Result, verb string) *v1.TransferResult {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s (%d bytes en %s)\n", verb, r.Path, r.Bytes, r.Duration.Round(time.Millisecond))
	fmt.Fprintf(&b, "MD5      %s\nSHA-256  %s", r.MD5, r.SHA256)
	if r.Verified != "" {
		fmt.Fprintf(&b, "\nverificado: %s", r.Verified)
	}
	return &v1.TransferResult{Path: r.Path, Bytes: r.Bytes, Md5: r.MD5, Sha256: r.SHA256, Verified: r.Verified, Seconds: r.Duration.Seconds(), Report: b.String()}
}
