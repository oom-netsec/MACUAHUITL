package bridge

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Transferencias (Fase 22a): servidores y clientes de TFTP, FTP, SCP, SFTP y HTTP ----
// La vista se hace aparte; este puente deja listo el contrato para ella.

type TransferServeDTO struct {
	Protocol      string   `json:"protocol"`
	Listen        string   `json:"listen"`
	AllowAny      bool     `json:"allowAny"`
	Files         []string `json:"files"`
	FromDir       string   `json:"fromDir"`
	Write         bool     `json:"write"`
	RecvDir       string   `json:"recvDir"`
	Allow         []string `json:"allow"`
	MaxFileBytes  int64    `json:"maxFileBytes"`
	MaxTotalBytes int64    `json:"maxTotalBytes"`
	Seconds       int      `json:"seconds"`
	LegacySSH     bool     `json:"legacySsh"`
	PassiveMin    int      `json:"passiveMin"`
	PassiveMax    int      `json:"passiveMax"`
}

// TransferServe abre un servidor y emite transfer:ready {runId, serverId, protocol, listening, hint,
// user, password, fingerprints, recvDir, fromDir, files}, transfer:msg {runId, transfer} por cada
// transferencia o rechazo y transfer:done {runId, error?, cleanup?}. Se detiene con TransferStop(serverId)
// o con DiagCancel(runId).
func (b *Bridge) TransferServe(d TransferServeDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewTransferServiceClient(c).StartServer(ctx, &v1.StartServerRequest{Protocol: d.Protocol, Listen: d.Listen, AllowAny: d.AllowAny,
		Files: d.Files, FromDir: d.FromDir, Write: d.Write, RecvDir: d.RecvDir, Allow: d.Allow, MaxFileBytes: d.MaxFileBytes, MaxTotalBytes: d.MaxTotalBytes,
		DurationSeconds: int32(d.Seconds), LegacySsh: d.LegacySSH, PassivePortMin: uint32(d.PassiveMin), PassivePortMax: uint32(d.PassiveMax)})
	if err != nil {
		b.finish(id, cancel)
		return "", wrapErr(err)
	}
	go func() {
		defer b.finish(id, cancel)
		cleanup := ""
		for {
			r, err := st.Recv()
			if err != nil {
				ev := map[string]any{"runId": id}
				if ctx.Err() == nil && err != io.EOF {
					ev["error"] = err.Error()
					ev["errorInfo"] = errorInfo(err)
				}
				if cleanup != "" {
					ev["cleanup"] = cleanup // cómo quitar la regla de nftables de este servidor
				}
				b.emit("transfer:done", ev)
				return
			}
			if cl := r.GetClosed(); cl != nil {
				cleanup = cl.Cleanup
				continue
			}
			if rd := r.GetReady(); rd != nil {
				b.emit("transfer:ready", map[string]any{"runId": id, "serverId": rd.ServerId, "protocol": rd.Protocol, "listening": rd.Listening,
					"hint": rd.Hint, "user": rd.User, "password": rd.Password, "fingerprints": rd.Fingerprints, "recvDir": rd.RecvDir, "fromDir": rd.FromDir, "files": rd.Files})
				continue
			}
			b.emit("transfer:msg", map[string]any{"runId": id, "transfer": r.GetTransferJson()})
		}
	}()
	return id, nil
}

func (b *Bridge) TransferStop(serverID string) (bool, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (bool, error) {
		r, err := v1.NewTransferServiceClient(c).StopServer(ctx, &v1.StopServerRequest{ServerId: serverID})
		return r.GetStopped(), err
	})
}

type TransferServerDTO struct {
	ServerID  string `json:"serverId"`
	Protocol  string `json:"protocol"`
	Listening string `json:"listening"`
	Started   int64  `json:"started"`
	Write     bool   `json:"write"`
	RecvDir   string `json:"recvDir"`
	FromDir   string `json:"fromDir"`
	Transfers int64  `json:"transfers"`
	Rejected  int64  `json:"rejected"`
}

func (b *Bridge) TransferServers() ([]TransferServerDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]TransferServerDTO, error) {
		r, err := v1.NewTransferServiceClient(c).ListServers(ctx, &v1.ListServersRequest{})
		out := []TransferServerDTO{}
		for _, s := range r.GetServers() {
			out = append(out, TransferServerDTO{ServerID: s.ServerId, Protocol: s.Protocol, Listening: s.Listening, Started: s.StartedUnix, Write: s.Write,
				RecvDir: s.RecvDir, FromDir: s.FromDir, Transfers: s.Transfers, Rejected: s.Rejected})
		}
		return out, err
	})
}

type TransferResultDTO struct {
	Path     string  `json:"path"`
	Bytes    int64   `json:"bytes"`
	MD5      string  `json:"md5"`
	SHA256   string  `json:"sha256"`
	Verified string  `json:"verified"`
	Seconds  float64 `json:"seconds"`
	Report   string  `json:"report"`
}

func resultDTO(r *v1.TransferResult) TransferResultDTO {
	return TransferResultDTO{Path: r.GetPath(), Bytes: r.GetBytes(), MD5: r.GetMd5(), SHA256: r.GetSha256(), Verified: r.GetVerified(), Seconds: r.GetSeconds(), Report: r.GetReport()}
}

type TransferGetDTO struct {
	URL          string   `json:"url"`
	DestDir      string   `json:"destDir"`
	Name         string   `json:"name"`
	CredentialID string   `json:"credentialId"`
	SHA256       string   `json:"sha256"`
	MD5          string   `json:"md5"`
	SHA512       string   `json:"sha512"`
	Insecure     bool     `json:"insecure"`
	HostKeys     []string `json:"acceptedHostKeys"`
	MaxBytes     int64    `json:"maxBytes"`
	Seconds      int      `json:"seconds"`
	LegacySSH    bool     `json:"legacySsh"`
}

func (b *Bridge) TransferGet(d TransferGetDTO) (TransferResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TransferResultDTO, error) {
		r, err := v1.NewTransferServiceClient(c).Get(ctx, &v1.GetRequest{Url: d.URL, DestDir: d.DestDir, Name: d.Name, CredentialId: d.CredentialID,
			Sha256: d.SHA256, Md5: d.MD5, Sha512: d.SHA512, Insecure: d.Insecure, AcceptedHostKeyFingerprints: d.HostKeys, MaxBytes: d.MaxBytes,
			TimeoutSeconds: int32(d.Seconds), LegacySsh: d.LegacySSH})
		return resultDTO(r.GetResult()), err
	})
}

type TransferPutDTO struct {
	URL          string   `json:"url"`
	FromDir      string   `json:"fromDir"`
	Name         string   `json:"name"`
	CredentialID string   `json:"credentialId"`
	HostKeys     []string `json:"acceptedHostKeys"`
	MaxBytes     int64    `json:"maxBytes"`
	Seconds      int      `json:"seconds"`
	LegacySSH    bool     `json:"legacySsh"`
}

func (b *Bridge) TransferPut(d TransferPutDTO) (TransferResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TransferResultDTO, error) {
		r, err := v1.NewTransferServiceClient(c).Put(ctx, &v1.PutRequest{Url: d.URL, FromDir: d.FromDir, Name: d.Name, CredentialId: d.CredentialID,
			AcceptedHostKeyFingerprints: d.HostKeys, MaxBytes: d.MaxBytes, TimeoutSeconds: int32(d.Seconds), LegacySsh: d.LegacySSH})
		return resultDTO(r.GetResult()), err
	})
}

type TransferHintDTO struct {
	StandardPort int    `json:"standardPort"`
	Nftables     string `json:"nftables"`
	Setcap       string `json:"setcap"`
	Remove       string `json:"remove"`
}

func (b *Bridge) TransferHint(protocol, ip string, port int) (TransferHintDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TransferHintDTO, error) {
		r, err := v1.NewTransferServiceClient(c).RedirectHint(ctx, &v1.RedirectHintRequest{Protocol: protocol, Ip: ip, Port: int32(port)})
		return TransferHintDTO{StandardPort: int(r.GetStandardPort()), Nftables: r.GetNftables(), Setcap: r.GetSetcap(), Remove: r.GetRemove()}, err
	})
}

// ---- Explorador remoto, avance y descarga múltiple (Fase 19) ----

type TransferBrowseDTO struct {
	URL          string   `json:"url"`
	CredentialID string   `json:"credentialId"`
	Path         string   `json:"path"`
	HostKeys     []string `json:"acceptedHostKeys"`
	Insecure     bool     `json:"insecure"`
	LegacySSH    bool     `json:"legacySsh"`
	MaxEntries   int      `json:"maxEntries"`
	Seconds      int      `json:"seconds"`
}

type RemoteEntryDTO struct {
	Name         string `json:"name"`
	Type         string `json:"type"` // file, dir, link, other
	Size         int64  `json:"size"` // -1 = el servidor no lo dice
	ModifiedMs   int64  `json:"modifiedMs"`
	Perms        string `json:"perms"`
	Downloadable bool   `json:"downloadable"`
	UnsafeName   bool   `json:"unsafeName"`
}

// TransferListingDTO: Listable=false (TFTP, o SCP sin SFTP) no es una falla: Reason trae el motivo para mostrarlo.
type TransferListingDTO struct {
	Listable bool   `json:"listable"`
	Reason   string `json:"reason"`
	// ReasonCode y ReasonArgs son el código estable del motivo (xfer.no_listing.tftp, …) y su metadata (proto); vacíos si no hay.
	ReasonCode string            `json:"reasonCode,omitempty"`
	ReasonArgs map[string]string `json:"reasonArgs,omitempty"`
	Path       string            `json:"path"`
	Entries    []RemoteEntryDTO  `json:"entries"`
	Truncated  bool              `json:"truncated"`
	Method     string            `json:"method"`
}

func (b *Bridge) TransferBrowse(d TransferBrowseDTO) (TransferListingDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (TransferListingDTO, error) {
		r, err := v1.NewTransferServiceClient(c).Browse(ctx, &v1.BrowseRequest{Url: d.URL, CredentialId: d.CredentialID, Path: d.Path, AcceptedHostKeyFingerprints: d.HostKeys,
			Insecure: d.Insecure, LegacySsh: d.LegacySSH, MaxEntries: int32(d.MaxEntries), TimeoutSeconds: int32(d.Seconds)})
		if status.Code(err) == codes.Unimplemented {
			out := TransferListingDTO{Reason: status.Convert(err).Message(), Entries: []RemoteEntryDTO{}}
			var be *Error
			if errors.As(wrapErr(err), &be) {
				out.ReasonCode, out.ReasonArgs = be.Reason, be.Metadata
			}
			return out, nil
		}
		out := TransferListingDTO{Listable: true, Path: r.GetPath(), Entries: []RemoteEntryDTO{}, Truncated: r.GetTruncated(), Method: r.GetMethod()}
		for _, e := range r.GetEntries() {
			out.Entries = append(out.Entries, RemoteEntryDTO{e.Name, e.Type, e.Size, e.ModifiedMs, e.Perms, e.Downloadable, e.UnsafeName})
		}
		return out, err
	})
}

type TransferGetManyDTO struct {
	URL          string   `json:"url"` // carpeta remota
	Names        []string `json:"names"`
	DestDir      string   `json:"destDir"`
	CredentialID string   `json:"credentialId"`
	HostKeys     []string `json:"acceptedHostKeys"`
	Insecure     bool     `json:"insecure"`
	MaxBytes     int64    `json:"maxBytes"`
	Seconds      int      `json:"seconds"`
	LegacySSH    bool     `json:"legacySsh"`
}

// emitTransfer traduce un evento del stream a los del puente: transfer:progress {runId, index, count, name,
// bytes, total, bytesPerSec} y transfer:file {runId, index, name, ok, error?, result?}. Devuelve el resumen del
// lote si el evento era el último.
func (b *Bridge) emitTransfer(id string, ev *v1.TransferEvent) *v1.BatchSummary {
	switch {
	case ev.GetProgress() != nil:
		p := ev.GetProgress()
		b.emit("transfer:progress", map[string]any{"runId": id, "index": p.Index, "count": p.Count, "name": p.Name, "bytes": p.Bytes, "total": p.Total, "bytesPerSec": p.BytesPerSec})
	case ev.GetFile() != nil:
		f := ev.GetFile()
		m := map[string]any{"runId": id, "index": f.Index, "name": f.Name, "ok": f.Ok}
		if f.Error != "" {
			m["error"] = f.Error
		}
		if f.Result != nil {
			m["result"] = resultDTO(f.Result)
		}
		b.emit("transfer:file", m)
	case ev.GetDone() != nil:
		return ev.GetDone()
	}
	return nil
}

// runTransfer lleva un stream de eventos hasta el final y emite transfer:finished {runId, error?, canceled?, ok?, failed?}.
func (b *Bridge) runTransfer(id string, ctx context.Context, cancel context.CancelFunc, recv func() (*v1.TransferEvent, error)) {
	defer b.finish(id, cancel)
	var sum *v1.BatchSummary
	for {
		ev, err := recv()
		if err != nil {
			m := map[string]any{"runId": id}
			switch {
			case err == io.EOF:
				if sum != nil {
					m["ok"], m["failed"] = sum.Ok, sum.Failed
				}
			case ctx.Err() != nil:
				m["canceled"] = true
			default:
				m["error"], m["errorInfo"] = err.Error(), errorInfo(err)
			}
			b.emit("transfer:finished", m)
			return
		}
		if s := b.emitTransfer(id, ev); s != nil {
			sum = s
		}
	}
}

// TransferGetAsync es TransferGet con avance: emite transfer:progress (a lo más unas 10 veces por segundo),
// transfer:file {…, result} y transfer:finished. Se cancela con TransferCancel(runId).
func (b *Bridge) TransferGetAsync(d TransferGetDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewTransferServiceClient(c).GetStream(ctx, &v1.GetStreamRequest{Request: &v1.GetRequest{Url: d.URL, DestDir: d.DestDir, Name: d.Name, CredentialId: d.CredentialID,
		Sha256: d.SHA256, Md5: d.MD5, Sha512: d.SHA512, Insecure: d.Insecure, AcceptedHostKeyFingerprints: d.HostKeys, MaxBytes: d.MaxBytes,
		TimeoutSeconds: int32(d.Seconds), LegacySsh: d.LegacySSH}})
	if err != nil {
		b.finish(id, cancel)
		return "", wrapErr(err)
	}
	go b.runTransfer(id, ctx, cancel, func() (*v1.TransferEvent, error) {
		r, err := st.Recv()
		return r.GetEvent(), err
	})
	return id, nil
}

func (b *Bridge) TransferPutAsync(d TransferPutDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewTransferServiceClient(c).PutStream(ctx, &v1.PutStreamRequest{Request: &v1.PutRequest{Url: d.URL, FromDir: d.FromDir, Name: d.Name, CredentialId: d.CredentialID,
		AcceptedHostKeyFingerprints: d.HostKeys, MaxBytes: d.MaxBytes, TimeoutSeconds: int32(d.Seconds), LegacySsh: d.LegacySSH}})
	if err != nil {
		b.finish(id, cancel)
		return "", wrapErr(err)
	}
	go b.runTransfer(id, ctx, cancel, func() (*v1.TransferEvent, error) {
		r, err := st.Recv()
		return r.GetEvent(), err
	})
	return id, nil
}

// TransferGetMany baja varios archivos de una carpeta remota: transfer:progress y transfer:file por archivo y
// transfer:finished {ok, failed} al terminar. Se cancela con TransferCancel(runId).
func (b *Bridge) TransferGetMany(d TransferGetManyDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewTransferServiceClient(c).GetMany(ctx, &v1.GetManyRequest{Url: d.URL, Names: d.Names, DestDir: d.DestDir, CredentialId: d.CredentialID,
		AcceptedHostKeyFingerprints: d.HostKeys, Insecure: d.Insecure, MaxBytes: d.MaxBytes, TimeoutSeconds: int32(d.Seconds), LegacySsh: d.LegacySSH})
	if err != nil {
		b.finish(id, cancel)
		return "", wrapErr(err)
	}
	go b.runTransfer(id, ctx, cancel, func() (*v1.TransferEvent, error) {
		r, err := st.Recv()
		return r.GetEvent(), err
	})
	return id, nil
}

// TransferCancel detiene una transferencia o un lote en curso (el runId que devolvieron TransferGetAsync,
// TransferPutAsync o TransferGetMany).
func (b *Bridge) TransferCancel(runID string) error { return b.DiagCancel(runID) }
