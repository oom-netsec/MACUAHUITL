package transfer

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	xfer "github.com/oom-netsec/MACUAHUITL/internal/diag/transfer"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// maxBatch es el tope de archivos de un GetMany.
const maxBatch = 200

// Browse lista una carpeta remota por el EgressGuard, con llave de host estricta y TLS verificado.
// La bitácora lleva la URL sin query, la carpeta y cuántas entradas, nunca las credenciales ni los nombres.
func (s *svc) Browse(ctx context.Context, r *v1.BrowseRequest) (*v1.BrowseResponse, error) {
	s.d.MarkActive()
	if r.MaxEntries < 0 || r.MaxEntries > xfer.MaxEntriesCap || r.TimeoutSeconds < 0 {
		return nil, bad(ctx, "transfer.svc.browse_limits", "max", xfer.MaxEntriesCap)
	}
	to := time.Duration(r.TimeoutSeconds) * time.Second
	if to > xfer.MaxBrowseTimeout {
		return nil, bad(ctx, "transfer.svc.max_time", "max", xfer.MaxBrowseTimeout)
	}
	if u, err := url.Parse(r.Url); err == nil && u.Scheme == "tftp" { // TFTP no lista: ni se pide autorización al guard
		nl := &xfer.NoListingError{Proto: "tftp", Reason: "TFTP no tiene comando para listar carpetas"}
		return nil, service.Err(ctx, codes.Unimplemented, "xfer.no_listing", i18n.A("reason", nl.Why(i18n.Locale(ctx))))
	}
	j, err := s.open(ctx, r.Url, r.CredentialId, r.AcceptedHostKeyFingerprints, r.LegacySsh)
	if err != nil {
		return nil, err
	}
	defer j.done()
	if r.Insecure && j.u.Scheme != "https" {
		return nil, bad(ctx, "transfer.svc.insecure")
	}
	j.req.Insecure, j.req.Timeout = r.Insecure, to
	s.d.Audit("transfer.browse.start", j.label, fmt.Sprintf("job=%s folder=%q credential=%q insecure=%t legacy_ssh=%t", j.id, r.Path, r.CredentialId, r.Insecure, r.LegacySsh))
	ls, err := xfer.Browse(ctx, j.req, r.Path, int(r.MaxEntries))
	var nl *xfer.NoListingError
	if errors.As(err, &nl) {
		s.d.Audit("transfer.browse.nolisting", j.label, fmt.Sprintf("job=%s folder=%q protocol=%s guard=revoked", j.id, r.Path, nl.Proto))
		return nil, service.Err(ctx, codes.Unimplemented, "xfer.no_listing", i18n.A("reason", nl.Why(i18n.Locale(ctx))))
	}
	if err != nil {
		s.d.Audit("transfer.browse.failed", j.label, fmt.Sprintf("job=%s folder=%q reason=%q guard=revoked", j.id, r.Path, j.errText(err)))
		return nil, connErr(ctx, err)
	}
	s.d.Audit("transfer.browse", j.label, fmt.Sprintf("job=%s folder=%q entries=%d method=%s truncated=%t guard=revoked", j.id, ls.Path, len(ls.Entries), ls.Method, ls.Truncated))
	out := &v1.BrowseResponse{Path: ls.Path, Truncated: ls.Truncated, Method: ls.Method}
	for _, e := range ls.Entries {
		re := &v1.RemoteEntry{Name: e.Name, Type: e.Type, Size: e.Size, Perms: e.Perms, Downloadable: e.Downloadable, UnsafeName: e.Unsafe}
		if !e.ModTime.IsZero() {
			re.ModifiedMs = e.ModTime.UnixMilli()
		}
		out.Entries = append(out.Entries, re)
	}
	return out, nil
}

// events manda eventos de un stream desde varias goroutines sin pisarse.
type events struct {
	mu  sync.Mutex
	st  interface{ SendMsg(m any) error }
	err error
}

func (e *events) send(m any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err == nil {
		e.err = e.st.SendMsg(m)
	}
}

func progressEvent(index, count int, name string, p xfer.Progress) *v1.TransferEvent {
	return &v1.TransferEvent{Event: &v1.TransferEvent_Progress{Progress: &v1.TransferProgress{Index: int32(index), Count: int32(count), Name: name,
		Bytes: p.Bytes, Total: p.Total, BytesPerSec: p.BytesPerSec}}}
}

// paceLimiter deja pasar a lo más un aviso cada xfer.ProgressEvery, sin importar de qué archivo vengan.
type paceLimiter struct {
	mu   sync.Mutex
	last time.Time
}

func (p *paceLimiter) allow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now := time.Now(); p.last.IsZero() || now.Sub(p.last) >= xfer.ProgressEvery {
		p.last = now
		return true
	}
	return false
}

func fileEvent(index int, name string, res *v1.TransferResult, err error) *v1.TransferEvent {
	f := &v1.FileResult{Index: int32(index), Name: name, Ok: err == nil, Result: res}
	if err != nil {
		f.Error = status.Convert(err).Message()
	}
	return &v1.TransferEvent{Event: &v1.TransferEvent_File{File: f}}
}

func (s *svc) GetStream(r *v1.GetStreamRequest, st v1.TransferService_GetStreamServer) error {
	ev := &events{st: st}
	req := r.GetRequest()
	if req == nil {
		return bad(st.Context(), "transfer.svc.no_request")
	}
	name := path.Base(req.Name)
	if req.Name == "" {
		if u, err := url.Parse(req.Url); err == nil {
			name = path.Base(u.Path)
		}
	}
	res, err := s.get(st.Context(), req, func(p xfer.Progress) { ev.send(&v1.GetStreamResponse{Event: progressEvent(0, 1, name, p)}) })
	if err != nil {
		return err
	}
	ev.send(&v1.GetStreamResponse{Event: fileEvent(0, name, res.Result, nil)})
	return ev.err
}

func (s *svc) PutStream(r *v1.PutStreamRequest, st v1.TransferService_PutStreamServer) error {
	ev := &events{st: st}
	req := r.GetRequest()
	if req == nil {
		return bad(st.Context(), "transfer.svc.no_request")
	}
	res, err := s.put(st.Context(), req, func(p xfer.Progress) { ev.send(&v1.PutStreamResponse{Event: progressEvent(0, 1, req.Name, p)}) })
	if err != nil {
		return err
	}
	ev.send(&v1.PutStreamResponse{Event: fileEvent(0, req.Name, res.Result, nil)})
	return ev.err
}

// batchName valida un nombre de archivo del lote: base sola, el nombre local debe ser aceptable.
func batchName(n string) error {
	if n == "" || strings.ContainsAny(n, `/\`) {
		return i18n.New("transfer.svc.name_no_path", nil)
	}
	if _, err := fileserve.SafeName(n); err != nil {
		return err
	}
	return nil
}

// batchURL es la URL de un archivo de la carpeta del lote, sin credenciales ni query.
func batchURL(dir *url.URL, name string) string {
	u := *dir
	u.Path, u.RawPath = path.Join("/", dir.Path, name), ""
	if strings.HasPrefix(dir.Path, "//") { // la «/» extra marca ruta absoluta (remotePath quita una sola): path.Join la colapsa
		u.Path = "/" + u.Path
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment = nil, "", false, ""
	return u.String()
}

// GetMany baja los archivos de una carpeta remota, uno a uno. Cada uno es una descarga completa
// (su propia autorización del guard, su propia sesión y su propia bitácora); si uno falla, sigue con el siguiente.
func (s *svc) GetMany(r *v1.GetManyRequest, st v1.TransferService_GetManyServer) error {
	s.d.MarkActive()
	ctx := st.Context()
	if len(r.Names) == 0 || len(r.Names) > maxBatch {
		return bad(ctx, "transfer.svc.batch", "max", maxBatch)
	}
	base, err := url.Parse(r.Url)
	if err != nil || base.Hostname() == "" {
		return bad(ctx, "transfer.svc.bad_url", "url", redacted(r.Url))
	}
	if base.Scheme == "tftp" {
		return bad(ctx, "transfer.svc.tftp_no_list")
	}
	dest := r.DestDir
	if dest == "" {
		if dest, err = s.receiveDir(ctx, service.NewID()); err != nil {
			return err
		}
	}
	if _, err := fileserve.ValidateDir(dest); err != nil {
		return service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if _, _, err := s.limits(ctx, r.MaxBytes, r.TimeoutSeconds); err != nil {
		return err
	}
	seen := map[string]bool{}
	var names []string
	for _, n := range r.Names {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	ev := &events{st: st}
	var pace paceLimiter // un solo límite de avisos para todo el lote; el fin de cada archivo va en su propio evento
	s.d.Audit("transfer.getmany.start", base.Scheme+"://"+base.Host+base.Path, fmt.Sprintf("files=%d destination=%q credential=%q", len(names), dest, r.CredentialId))
	ok, failed := 0, 0
	for i, n := range names {
		if ctx.Err() != nil {
			s.d.Audit("transfer.getmany.canceled", base.Host, fmt.Sprintf("done=%d failed=%d pending=%d", ok, failed, len(names)-i))
			return status.FromContextError(ctx.Err()).Err()
		}
		var res *v1.GetResponse
		err := batchName(n)
		if err == nil {
			idx, name := i, n
			res, err = s.get(ctx, &v1.GetRequest{Url: batchURL(base, n), DestDir: dest, CredentialId: r.CredentialId, Insecure: r.Insecure,
				AcceptedHostKeyFingerprints: r.AcceptedHostKeyFingerprints, MaxBytes: r.MaxBytes, TimeoutSeconds: r.TimeoutSeconds, LegacySsh: r.LegacySsh},
				func(p xfer.Progress) {
					if pace.allow() {
						ev.send(&v1.GetManyResponse{Event: progressEvent(idx, len(names), name, p)})
					}
				})
		}
		if err != nil {
			failed++
			ev.send(&v1.GetManyResponse{Event: fileEvent(i, n, nil, err)})
		} else {
			ok++
			ev.send(&v1.GetManyResponse{Event: fileEvent(i, n, res.Result, nil)})
		}
		if ev.err != nil {
			return ev.err
		}
	}
	s.d.Audit("transfer.getmany", base.Host, fmt.Sprintf("done=%d failed=%d", ok, failed))
	ev.send(&v1.GetManyResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_Done{Done: &v1.BatchSummary{Ok: int32(ok), Failed: int32(failed)}}}})
	return ev.err
}
