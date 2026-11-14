// Package transfer es el servicio de transferencias (fase 22a): servidores temporales de
// archivos (TFTP, FTP, SCP, SFTP y HTTP) y clientes (get y put) con la credencial de la
// bóveda. Toda escucha es temporal, en IP explícita y puerto alto; toda salida pasa por el
// EgressGuard con Revoke al terminar; todo queda auditado.
//
// No hace: abrir puertos privilegiados ni ejecutar nada con privilegios (solo explica los
// comandos) ni escribir fuera de la carpeta que el usuario eligió.
package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

const (
	maxServers      = 4
	maxClients      = 4
	defaultServeFor = 30 * time.Minute
	maxServeFor     = 24 * time.Hour
	maxNamesShown   = 50
	closeWait       = 10 * time.Second
)

// Puertos altos por omisión: ninguno privilegiado (ADR 0004).
var defaultPort = map[string]uint16{"tftp": 6969, "ftp": 2121, "scp": 2222, "sftp": 2222, "http": 8080}

type server struct {
	id, proto, listening string
	started              time.Time
	write                bool
	recvDir, fromDir     string
	transfers, rejected  atomic.Int64
	cancel               context.CancelFunc
}

type svc struct {
	v1.UnimplementedTransferServiceServer
	d       service.Deps
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	servers map[string]*server
	clients atomic.Int32
}

func newSvc(d service.Deps) *svc {
	ctx, cancel := context.WithCancel(context.Background())
	return &svc{d: d, ctx: ctx, cancel: cancel, servers: map[string]*server{}}
}

// close detiene los servidores y espera a que cierren y auditen. El núcleo lo llama antes de cerrar la base.
func (s *svc) close() {
	s.cancel()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeWait):
	}
}

// receiveDir crea la carpeta de recepción por omisión: outputs/recibidos/<sello>-<id>/.
func (s *svc) receiveDir(ctx context.Context, id string) (string, error) {
	dir := filepath.Join(s.d.Outputs(), "recibidos", s.d.Now().Format("20060102-150405")+"-"+id[len(id)-6:])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", service.Err(ctx, codes.Internal, "transfer.svc.recv_dir", i18n.A("error", err.Error()))
	}
	return dir, nil
}

// bad es el error de uso de la petición: el código del catálogo (transfer.svc.*) y sus argumentos.
func bad(ctx context.Context, key string, kv ...any) error {
	return service.Err(ctx, codes.InvalidArgument, key, i18n.A(kv...))
}

// listenAddr completa el puerto alto por omisión cuando solo llega la IP.
func listenAddr(ctx context.Context, proto, listen string) (string, error) {
	port, ok := defaultPort[proto]
	if !ok {
		return "", bad(ctx, "transfer.svc.bad_proto", "proto", proto)
	}
	if ip, err := netip.ParseAddr(strings.Trim(listen, "[]")); err == nil {
		return netip.AddrPortFrom(ip, port).String(), nil
	}
	return listen, nil
}

func (s *svc) StartServer(r *v1.StartServerRequest, st v1.TransferService_StartServerServer) error {
	s.d.MarkActive()
	ctx := st.Context()
	addr, err := listenAddr(ctx, r.Protocol, r.Listen)
	if err != nil {
		return err
	}
	var allow []netip.Addr
	for _, a := range r.Allow {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil {
			return bad(ctx, "transfer.svc.bad_origin", "ip", a)
		}
		allow = append(allow, ip)
	}
	id := service.NewID()
	cfg := fileserve.Config{Addr: addr, Proto: r.Protocol, AllowAny: r.AllowAny, Files: r.Files, FromDir: r.FromDir,
		Write: r.Write, RecvDir: r.RecvDir, MaxFile: r.MaxFileBytes, MaxTotal: r.MaxTotalBytes, Allow: allow,
		Legacy: r.LegacySsh, PassivePorts: [2]uint16{uint16(r.PassivePortMin), uint16(r.PassivePortMax)}}
	if r.PassivePortMin > 65535 || r.PassivePortMax > 65535 || r.PassivePortMin > r.PassivePortMax {
		return bad(ctx, "transfer.svc.passive")
	}
	if r.Write && r.RecvDir == "" {
		if cfg.RecvDir, err = s.receiveDir(ctx, id); err != nil {
			return err
		}
	}
	if err := fileserve.Check(cfg); err != nil {
		return service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if s.ctx.Err() != nil {
		return service.Err(ctx, codes.Unavailable, "transfer.svc.closing", nil)
	}
	s.mu.Lock()
	if len(s.servers) >= maxServers {
		s.mu.Unlock()
		return service.Err(ctx, codes.ResourceExhausted, "transfer.svc.max_servers", i18n.A("max", maxServers))
	}
	dur := defaultServeFor
	if r.DurationSeconds > 0 {
		dur = min(time.Duration(r.DurationSeconds)*time.Second, maxServeFor)
	}
	sctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	srv := &server{id: id, proto: r.Protocol, started: s.d.Now(), write: r.Write, cancel: cancel}
	s.servers[id] = srv
	s.mu.Unlock()
	s.wg.Add(1)
	defer s.wg.Done()
	defer func() { s.mu.Lock(); delete(s.servers, id); s.mu.Unlock() }()
	go func() { // cierre del núcleo → termina este servidor
		select {
		case <-s.ctx.Done():
			cancel()
		case <-sctx.Done():
		}
	}()

	k := newSink(st.Send)
	loc := i18n.Locale(ctx)
	cfg.OnTransfer = func(t fileserve.Transfer) { k.onTransfer(s.d.Audit, srv, t, loc) }
	cfg.OnReady = func(rd fileserve.Ready) {
		from, recv := fileserve.Folders(cfg)
		s.mu.Lock()
		srv.listening, srv.fromDir, srv.recvDir = rd.Addr, from, recv
		s.mu.Unlock()
		names := fileserve.Names(cfg)
		if len(names) > maxNamesShown {
			names = names[:maxNamesShown]
		}
		// Ni la contraseña ni la llave privada se auditan: solo qué se abrió, dónde y con qué reglas.
		s.d.Audit("transfer.serve.open", rd.Addr, fmt.Sprintf("server=%s proto=%s read_from=%q files=%q write=%t receive_into=%q origins=%v all=%t duration=%s legacy_ssh=%t limits=%d/%d",
			id, r.Protocol, from, r.Files, r.Write, recv, r.Allow, r.AllowAny, dur, cfg.Legacy && (r.Protocol == "scp" || r.Protocol == "sftp"), cfg.MaxFile, cfg.MaxTotal))
		k.events <- &v1.StartServerResponse{Event: &v1.StartServerResponse_Ready{Ready: &v1.ServerReady{
			ServerId: id, Protocol: r.Protocol, Listening: rd.Addr, Hint: fileserve.ServerHintIn(loc, cfg, rd, names),
			User: rd.User, Password: rd.Pass, Fingerprints: rd.Fingerprints, RecvDir: recv, FromDir: from, Files: names}}}
	}
	err = fileserve.Serve(sctx, cfg)
	s.mu.Lock()
	listening := srv.listening
	s.mu.Unlock()
	k.events <- &v1.StartServerResponse{Event: &v1.StartServerResponse_Closed{Closed: &v1.ServerClosed{Cleanup: fileserve.RedirectCleanupAddr(r.Protocol, listening)}}}
	n, rejected := k.stop()
	reason := "duration expired or canceled"
	if err != nil {
		reason = "error: " + i18n.English(err)
	}
	s.d.Audit("transfer.serve.close", listening, fmt.Sprintf("server=%s proto=%s transfers=%d rejected=%d reason=%q", id, r.Protocol, n, rejected, reason))
	if err != nil {
		return service.ErrFrom(ctx, codes.Unavailable, err)
	}
	return nil
}

func (s *svc) StopServer(_ context.Context, r *v1.StopServerRequest) (*v1.StopServerResponse, error) {
	s.d.MarkActive()
	s.mu.Lock()
	srv := s.servers[r.ServerId]
	var listening string
	if srv != nil {
		listening = srv.listening
	}
	s.mu.Unlock()
	if srv == nil {
		return &v1.StopServerResponse{}, nil
	}
	s.d.Audit("transfer.serve.stop", listening, "server="+srv.id)
	srv.cancel()
	return &v1.StopServerResponse{Stopped: true}, nil
}

func (s *svc) ListServers(context.Context, *v1.ListServersRequest) (*v1.ListServersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &v1.ListServersResponse{}
	for _, x := range s.servers {
		out.Servers = append(out.Servers, &v1.ServerInfo{ServerId: x.id, Protocol: x.proto, Listening: x.listening, StartedUnix: x.started.Unix(),
			Write: x.write, RecvDir: x.recvDir, FromDir: x.fromDir, Transfers: x.transfers.Load(), Rejected: x.rejected.Load()})
	}
	return out, nil
}

func (s *svc) RedirectHint(ctx context.Context, r *v1.RedirectHintRequest) (*v1.RedirectHintResponse, error) {
	if r.Ip != "" {
		if _, err := netip.ParseAddr(strings.Trim(r.Ip, "[]")); err != nil {
			return nil, bad(ctx, "transfer.svc.bad_listen", "ip", r.Ip)
		}
	}
	loc := i18n.Locale(ctx)
	h := fileserve.RedirectHintIn(loc, r.Protocol, r.Ip, int(r.Port))
	if h == "" || r.Port <= 0 || r.Port > 65535 {
		return nil, bad(ctx, "transfer.svc.no_redirect", "proto", r.Protocol)
	}
	std := map[string]int32{"tftp": 69, "ftp": 21, "scp": 22, "sftp": 22}[r.Protocol]
	return &v1.RedirectHintResponse{StandardPort: std, Nftables: h, Setcap: fileserve.SetcapHintIn(loc, i18n.Msg(loc, "fileserve.hint.server_path", nil)), Remove: fileserve.RedirectCleanup(r.Protocol, r.Ip, int(r.Port))}, nil
}

// sink: las transferencias reales se auditan; los rechazos (escáneres, nombres equivocados)
// solo se cuentan y se reenvían al cliente sin bloquear, y la recepción nunca espera al stream.
type sink struct {
	events      chan *v1.StartServerResponse
	drained     chan struct{}
	n, rejected atomic.Int64
}

func newSink(send func(*v1.StartServerResponse) error) *sink {
	k := &sink{events: make(chan *v1.StartServerResponse, 256), drained: make(chan struct{})}
	go func() {
		defer close(k.drained)
		for ev := range k.events {
			send(ev)
		}
	}()
	return k
}

// onTransfer reenvía la transferencia al cliente con su motivo en el idioma loc; la auditoría lo lleva en inglés.
func (k *sink) onTransfer(audit func(a, t, d string), srv *server, t fileserve.Transfer, loc string) {
	shown := t
	shown.Error = fileserve.ReasonIn(loc, t)
	shown.DirCode = service.DirEN(t.Dir)
	b, _ := json.Marshal(shown)
	ev := &v1.StartServerResponse{Event: &v1.StartServerResponse_TransferJson{TransferJson: string(b)}}
	if t.Rejected {
		k.rejected.Add(1)
		srv.rejected.Add(1)
		select {
		case k.events <- ev:
		default:
		}
		return
	}
	k.n.Add(1)
	srv.transfers.Add(1)
	audit("transfer.serve.transfer", t.Client, fmt.Sprintf("server=%s proto=%s direction=%s file=%q path=%q bytes=%d sha256=%s duration=%s result=%s error=%q",
		srv.id, t.Proto, service.DirEN(t.Dir), t.File, t.Path, t.Bytes, t.SHA256, t.Duration.Round(time.Millisecond), t.Result, fileserve.ReasonIn(i18n.En, t)))
	k.events <- ev
}

// stop se llama cuando Serve ya terminó (no quedan transferencias en curso).
func (k *sink) stop() (n, rejected int64) {
	close(k.events)
	<-k.drained
	return k.n.Load(), k.rejected.Load()
}

// Module registra el servicio Transfer.
type Module struct{}

func (Module) Register(r ipc.Registrar, d service.Deps) {
	s := newSvc(d)
	d.OnClose(s.close)
	v1.RegisterTransferServiceServer(r, s)
}

// redacted es la URL sin contraseña, para citarla en un error: una URL que no se pudo leer pierde todo su userinfo.
func redacted(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Redacted()
	}
	return userinfoRe.ReplaceAllString(raw, "://")
}

var userinfoRe = regexp.MustCompile(`://[^/@]*@`)
