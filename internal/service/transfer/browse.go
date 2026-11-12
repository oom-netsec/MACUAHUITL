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
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// maxBatch es el tope de archivos de un GetMany.
const maxBatch = 200

// Browse lista una carpeta remota por el EgressGuard, con llave de host estricta y TLS verificado.
// La bitácora lleva la URL sin query, la carpeta y cuántas entradas, nunca las credenciales ni los nombres.
func (s *svc) Browse(ctx context.Context, r *v1.BrowseRequest) (*v1.BrowseResponse, error) {
	s.d.MarkActive()
	if r.MaxEntries < 0 || r.MaxEntries > xfer.MaxEntriesCap || r.TimeoutSeconds < 0 {
		return nil, bad("tope inválido (entradas 0 a %d, tiempo en segundos)", xfer.MaxEntriesCap)
	}
	to := time.Duration(r.TimeoutSeconds) * time.Second
	if to > xfer.MaxBrowseTimeout {
		return nil, bad("el tiempo máximo es %s", xfer.MaxBrowseTimeout)
	}
	if u, err := url.Parse(r.Url); err == nil && u.Scheme == "tftp" { // TFTP no lista: ni se pide autorización al guard
		return nil, status.Error(codes.Unimplemented, (&xfer.NoListingError{Proto: "tftp", Reason: "TFTP no tiene comando para listar carpetas"}).Error())
	}
	j, err := s.open(ctx, r.Url, r.CredentialId, r.AcceptedHostKeyFingerprints, r.LegacySsh)
	if err != nil {
		return nil, err
	}
	defer j.done()
	if r.Insecure && j.u.Scheme != "https" {
		return nil, bad("--insecure solo aplica a https")
	}
	j.req.Insecure, j.req.Timeout = r.Insecure, to
	s.d.Audit("transfer.browse.start", j.label, fmt.Sprintf("trabajo=%s carpeta=%q credencial=%q insecure=%t ssh_antiguo=%t", j.id, r.Path, r.CredentialId, r.Insecure, r.LegacySsh))
	ls, err := xfer.Browse(ctx, j.req, r.Path, int(r.MaxEntries))
	var nl *xfer.NoListingError
	if errors.As(err, &nl) {
		s.d.Audit("transfer.browse.nolisting", j.label, fmt.Sprintf("trabajo=%s carpeta=%q protocolo=%s guard=revocado", j.id, r.Path, nl.Proto))
		return nil, status.Error(codes.Unimplemented, err.Error())
	}
	if err != nil {
		s.d.Audit("transfer.browse.failed", j.label, fmt.Sprintf("trabajo=%s carpeta=%q razon=%q guard=revocado", j.id, r.Path, j.errText(err)))
		return nil, connErr(err)
	}
	s.d.Audit("transfer.browse", j.label, fmt.Sprintf("trabajo=%s carpeta=%q entradas=%d metodo=%s truncado=%t guard=revocado", j.id, ls.Path, len(ls.Entries), ls.Method, ls.Truncated))
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
		return bad("falta la petición")
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
		return bad("falta la petición")
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
		return errors.New("el nombre debe ser un archivo de la carpeta, sin ruta")
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
		return bad("indica entre 1 y %d archivos", maxBatch)
	}
	base, err := url.Parse(r.Url)
	if err != nil || base.Hostname() == "" {
		return bad("URL inválida %q", r.Url)
	}
	if base.Scheme == "tftp" {
		return bad("TFTP no lista carpetas: descarga cada archivo por su URL")
	}
	dest := r.DestDir
	if dest == "" {
		if dest, err = s.receiveDir(service.NewID()); err != nil {
			return err
		}
	} else if dest, err = s.clientDir(dest); err != nil {
		return err
	}
	if _, err := fileserve.ValidateDir(dest); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if _, _, err := s.limits(r.MaxBytes, r.TimeoutSeconds); err != nil {
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
	s.d.Audit("transfer.getmany.start", base.Scheme+"://"+base.Host+base.Path, fmt.Sprintf("archivos=%d destino=%q credencial=%q", len(names), dest, r.CredentialId))
	ok, failed := 0, 0
	for i, n := range names {
		if ctx.Err() != nil {
			s.d.Audit("transfer.getmany.canceled", base.Host, fmt.Sprintf("hechos=%d fallidos=%d pendientes=%d", ok, failed, len(names)-i))
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
	s.d.Audit("transfer.getmany", base.Host, fmt.Sprintf("hechos=%d fallidos=%d", ok, failed))
	ev.send(&v1.GetManyResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_Done{Done: &v1.BatchSummary{Ok: int32(ok), Failed: int32(failed)}}}})
	return ev.err
}
