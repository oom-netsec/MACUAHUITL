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
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	msg := i18n.English(err)
	if q := j.u.RawQuery; q != "" {
		msg = strings.ReplaceAll(strings.ReplaceAll(msg, "?"+q, ""), q, "")
	}
	return msg
}

// connErr traduce los errores de conexión a códigos gRPC; la huella de una llave nueva va en el mensaje.
func connErr(ctx context.Context, err error) error {
	var he *transport.HostKeyError
	switch {
	case errors.As(err, &he):
		return service.ErrFrom(ctx, codes.FailedPrecondition, err)
	case errors.Is(err, transport.ErrAuth), errors.Is(err, transport.ErrEgressDenied):
		return service.ErrFrom(ctx, codes.PermissionDenied, err)
	}
	if s := service.VaultErr(err); status.Code(s) != codes.Internal {
		return s
	}
	return service.ErrFrom(ctx, codes.Unavailable, err)
}

// open prepara el trabajo. A partir de aquí todo camino de salida debe llamar j.done().
func (s *svc) open(ctx context.Context, rawURL, credID string, accepted []string, legacy bool) (*job, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil, bad(ctx, "transfer.svc.bad_url", "url", rawURL)
	}
	if _, err := xfer.Port(u); err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if _, has := u.User.Password(); has {
		return nil, bad(ctx, "transfer.svc.url_password")
	}
	if s.ctx.Err() != nil {
		return nil, service.Err(ctx, codes.Unavailable, "transfer.svc.closing", nil)
	}
	if s.clients.Add(1) > maxClients {
		s.clients.Add(-1)
		return nil, service.Err(ctx, codes.ResourceExhausted, "transfer.svc.max_clients", i18n.A("max", maxClients))
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
		return nil, service.ErrFrom(ctx, codes.PermissionDenied, err)
	}
	j.req = xfer.Request{URL: u, Net: xfer.GuardNet(g, j.id)}
	switch u.Scheme {
	case "scp", "sftp", "ftp":
		if credID == "" && u.Scheme != "ftp" {
			j.done()
			return nil, bad(ctx, "transfer.svc.need_cred", "scheme", u.Scheme)
		}
	}
	if credID == "" {
		return j, nil
	}
	v := s.d.Vault()
	if v == nil || !v.Unlocked() {
		j.done()
		return nil, service.Err(ctx, codes.FailedPrecondition, "transfer.svc.vault_closed", nil)
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
			return nil, bad(ctx, "transfer.svc.no_password")
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

func (s *svc) limits(ctx context.Context, maxBytes int64, secs int32) (int64, time.Duration, error) {
	if maxBytes < 0 || secs < 0 {
		return 0, 0, bad(ctx, "transfer.svc.bad_limits")
	}
	to := time.Duration(secs) * time.Second
	if to > xfer.MaxTimeout {
		return 0, 0, bad(ctx, "transfer.svc.max_time", "max", xfer.MaxTimeout)
	}
	return maxBytes, to, nil
}

func (s *svc) Get(ctx context.Context, r *v1.GetRequest) (*v1.GetResponse, error) {
	return s.get(ctx, r, nil)
}

// get es Get con aviso de avance opcional (el mismo para el stream y el lote).
func (s *svc) get(ctx context.Context, r *v1.GetRequest, onProgress func(xfer.Progress)) (*v1.GetResponse, error) {
	s.d.MarkActive()
	max, to, err := s.limits(ctx, r.MaxBytes, r.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	dest := r.DestDir
	if dest == "" {
		if dest, err = s.receiveDir(ctx, service.NewID()); err != nil {
			return nil, err
		}
	}
	if _, err := fileserve.ValidateDir(dest); err != nil { // errores de uso antes de tocar la red
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	j, err := s.open(ctx, r.Url, r.CredentialId, r.AcceptedHostKeyFingerprints, r.LegacySsh)
	if err != nil {
		return nil, err
	}
	defer j.done()
	if r.Insecure && j.u.Scheme != "https" {
		return nil, bad(ctx, "transfer.svc.insecure")
	}
	j.req.DestDir, j.req.Name, j.req.WantSHA256, j.req.WantMD5 = dest, r.Name, r.Sha256, r.Md5
	j.req.MaxBytes, j.req.Timeout, j.req.Insecure, j.req.OnProgress = max, to, r.Insecure, onProgress
	s.d.Audit("transfer.get.start", j.label, fmt.Sprintf("job=%s destination=%q credential=%q insecure=%t legacy_ssh=%t", j.id, dest, r.CredentialId, r.Insecure, r.LegacySsh))
	res, err := xfer.Download(ctx, j.req)
	if err == nil && r.Sha512 != "" { // SHA-512 de Cisco: lo verifica imgverify, el mismo de field hash
		var ir imgverify.Result
		if ir, err = imgverify.Check(res.Path, "", r.Sha512); err == nil && !ir.OK() {
			err = i18n.New("transfer.svc.sha512", i18n.A("sha512", ir.SHA512))
		}
		if err != nil {
			os.Remove(res.Path)
			res.Verified = "distinto"
		} else if res.Verified == "" {
			res.Verified = "ok"
		}
	}
	if err != nil {
		s.d.Audit("transfer.get.failed", j.label, fmt.Sprintf("job=%s destination=%q reason=%q verified=%s guard=revoked", j.id, dest, j.errText(err), res.Verified))
		return nil, connErr(ctx, err)
	}
	s.d.Audit("transfer.get", j.label, fmt.Sprintf("job=%s path=%q bytes=%d sha256=%s md5=%s verified=%s duration=%s guard=revoked", j.id, res.Path, res.Bytes, res.SHA256, res.MD5, res.Verified, res.Duration.Round(time.Millisecond)))
	return &v1.GetResponse{Result: result(ctx, res, "transfer.verb.got")}, nil
}

func (s *svc) Put(ctx context.Context, r *v1.PutRequest) (*v1.PutResponse, error) {
	return s.put(ctx, r, nil)
}

func (s *svc) put(ctx context.Context, r *v1.PutRequest, onProgress func(xfer.Progress)) (*v1.PutResponse, error) {
	s.d.MarkActive()
	max, to, err := s.limits(ctx, r.MaxBytes, r.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	if f, _, err := fileserve.OpenFrom(r.FromDir, r.Name); err != nil { // errores de uso antes de tocar la red
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	} else {
		f.Close()
	}
	j, err := s.open(ctx, r.Url, r.CredentialId, r.AcceptedHostKeyFingerprints, r.LegacySsh)
	if err != nil {
		return nil, err
	}
	defer j.done()
	j.req.FromDir, j.req.Name, j.req.MaxBytes, j.req.Timeout, j.req.OnProgress = r.FromDir, r.Name, max, to, onProgress
	s.d.Audit("transfer.put.start", j.label, fmt.Sprintf("job=%s folder=%q file=%q credential=%q legacy_ssh=%t", j.id, r.FromDir, r.Name, r.CredentialId, r.LegacySsh))
	res, err := xfer.Upload(ctx, j.req)
	if err != nil {
		s.d.Audit("transfer.put.failed", j.label, fmt.Sprintf("job=%s folder=%q file=%q reason=%q guard=revoked", j.id, r.FromDir, r.Name, j.errText(err)))
		return nil, connErr(ctx, err)
	}
	s.d.Audit("transfer.put", j.label, fmt.Sprintf("job=%s path=%q bytes=%d sha256=%s md5=%s duration=%s guard=revoked", j.id, res.Path, res.Bytes, res.SHA256, res.MD5, res.Duration.Round(time.Millisecond)))
	return &v1.PutResponse{Result: result(ctx, res, "transfer.verb.put")}, nil
}

// result arma el TransferResult; su informe de texto sale en el idioma de la llamada (verb es el código del verbo).
func result(ctx context.Context, r xfer.Result, verb string) *v1.TransferResult {
	loc := i18n.Locale(ctx)
	var b strings.Builder
	b.WriteString(i18n.Msg(loc, "transfer.report.line", i18n.A("verb", i18n.Msg(loc, verb, nil), "path", r.Path, "bytes", r.Bytes, "duration", r.Duration.Round(time.Millisecond))) + "\n")
	fmt.Fprintf(&b, "MD5      %s\nSHA-256  %s", r.MD5, r.SHA256)
	if r.Verified != "" {
		shown := r.Verified
		switch r.Verified { // «ok» y «distinto» son los códigos de TransferResult.verified
		case "ok":
			shown = i18n.Msg(loc, "transfer.verified.ok", nil)
		case "distinto":
			shown = i18n.Msg(loc, "transfer.verified.bad", nil)
		}
		b.WriteString("\n" + i18n.Msg(loc, "transfer.report.verified", i18n.A("result", shown)))
	}
	return &v1.TransferResult{Path: r.Path, Bytes: r.Bytes, Md5: r.MD5, Sha256: r.SHA256, Verified: r.Verified, Seconds: r.Duration.Seconds(), Report: b.String()}
}
