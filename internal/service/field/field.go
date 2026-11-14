package field

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
	"github.com/oom-netsec/MACUAHUITL/internal/imgverify"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// fieldSvc: herramientas junto al equipo (consola serie, servidor de archivos, hashes).
type fieldSvc struct {
	v1.UnimplementedFieldServiceServer
	d service.Deps
}

func (s *fieldSvc) ListSerialPorts(context.Context, *v1.ListSerialPortsRequest) (*v1.ListSerialPortsResponse, error) {
	return &v1.ListSerialPortsResponse{Ports: serialcon.List()}, nil
}

// outFile crea outputs/<sub>/<prefijo>_<hora>.log con 0600. Nunca abre un archivo que ya existe ni sigue un
// enlace (O_EXCL|O_NOFOLLOW): si el nombre está ocupado, prueba con un sufijo.
func (s *fieldSvc) outFile(sub, prefix string) (*os.File, error) {
	dir := filepath.Join(s.d.Outputs(), sub)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, i18n.Wrap("ingest.err.out_dir", err, nil)
	}
	base := prefix + "_" + s.d.Now().Format("20060102-150405")
	for n := 0; n < 100; n++ {
		name := base + ".log"
		if n > 0 {
			name = fmt.Sprintf("%s_%d.log", base, n)
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND|sys.ONoFollow, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, i18n.Wrap("ingest.err.out_file", err, nil)
		}
		return f, nil
	}
	return nil, i18n.New("field.err.names_busy", nil)
}

// Console conecta el stream con el puerto serie. Lo tecleado no se graba ni se
// audita (puede ser una contraseña); solo lo que devuelve el equipo.
func (s *fieldSvc) Console(st v1.FieldService_ConsoleServer) error {
	s.d.MarkActive()
	first, err := st.Recv()
	if err != nil {
		return err
	}
	o := first.GetOpen()
	if o == nil {
		return service.Err(st.Context(), codes.InvalidArgument, "field.err.first_open", nil)
	}
	cfg, err := serialcon.Config{Path: o.Port, Baud: int(o.Baud), DataBits: int(o.DataBits), Parity: o.Parity, StopBits: int(o.StopBits), Flow: o.Flow}.Normalize()
	if err != nil {
		return service.ErrFrom(st.Context(), codes.InvalidArgument, err)
	}
	p, err := serialcon.Open(cfg)
	if errors.Is(err, serialcon.ErrPermission) {
		return service.ErrFrom(st.Context(), codes.PermissionDenied, err)
	} else if err != nil {
		return service.ErrFrom(st.Context(), codes.FailedPrecondition, err)
	}
	defer p.Close()
	f, err := s.outFile("console", "console_"+filepath.Base(cfg.Path))
	if err != nil {
		return service.ErrFrom(st.Context(), codes.Internal, err)
	}
	defer f.Close()
	rec := serialcon.NewRecorder(f, s.d.Now)
	summary := cfg.Path + " " + cfg.String()
	rec.Mark("abierto " + summary)
	opened := cfg.Path + " " + cfg.StringIn(i18n.Locale(st.Context()))
	s.d.Audit("field.console.open", cfg.Path, cfg.AuditString()+" output="+f.Name())
	if err := st.Send(&v1.ConsoleResponse{Opened: opened, OutputPath: f.Name()}); err != nil {
		return err
	}
	var rx, tx, breaks atomic.Int64
	portErr := make(chan error, 1)
	go func() { // equipo → cliente; solo este goroutine envía por el stream desde aquí
		buf := make([]byte, 4096)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				rx.Add(int64(n))
				rec.Write(buf[:n])
				st.Send(&v1.ConsoleResponse{Data: append([]byte(nil), buf[:n]...)})
			}
			if err != nil {
				portErr <- err
				return
			}
		}
	}()
	clientDone := make(chan struct{})
	go func() { // cliente → equipo
		defer close(clientDone)
		for {
			m, err := st.Recv()
			if err != nil {
				return
			}
			switch {
			case m.GetSendBreak():
				if p.Break() == nil {
					breaks.Add(1)
					rec.Mark("BREAK")
				}
			case len(m.GetData()) > 0:
				n, _ := p.Write(m.GetData())
				tx.Add(int64(n))
			}
		}
	}()
	var lost error
	select {
	case <-clientDone:
		p.Close()
		<-portErr
	case lost = <-portErr: // cable desconectado o equipo apagado
		p.Close()
	}
	reason, reasonEN := "cerrada por el usuario", "closed by the user"
	var lostErr error
	if lost != nil {
		lostErr = i18n.Wrap("field.err.port_lost", lost, nil)
		reason, reasonEN = lostErr.Error(), i18n.English(lostErr)
	}
	rec.Mark("cerrado: " + reason)
	s.d.Audit("field.console.close", cfg.Path, fmt.Sprintf("received=%d sent=%d break=%d %s", rx.Load(), tx.Load(), breaks.Load(), reasonEN))
	if lost != nil {
		return service.ErrFrom(st.Context(), codes.Unavailable, lostErr)
	}
	return nil
}

var defaultServePort = map[string]uint16{"tftp": 6969, "http": 8080}

// ServeFiles publica los archivos elegidos hasta que el cliente cancele o venza la duración.
func (s *fieldSvc) ServeFiles(r *v1.ServeFilesRequest, st v1.FieldService_ServeFilesServer) error {
	s.d.MarkActive()
	port, ok := defaultServePort[r.Protocol]
	if !ok {
		return service.Err(st.Context(), codes.InvalidArgument, "field.err.proto", i18n.A("proto", r.Protocol))
	}
	addr := r.Addr
	if ip, err := netip.ParseAddr(strings.Trim(addr, "[]")); err == nil { // solo IP: puerto por defecto
		addr = netip.AddrPortFrom(ip, port).String()
	}
	if err := fileserve.ValidateAddr(addr, r.AllowAny); err != nil {
		return service.ErrFrom(st.Context(), codes.InvalidArgument, err)
	}
	if _, err := fileserve.Publish(r.Files); err != nil {
		return service.ErrFrom(st.Context(), codes.InvalidArgument, err)
	}
	ctx, cancel := context.WithTimeout(st.Context(), service.SyslogDuration(r.DurationSeconds))
	defer cancel()
	k := newServeSink(i18n.Locale(st.Context()), s.d.Audit, st.Send)
	cfg := fileserve.Config{Addr: addr, Proto: r.Protocol, AllowAny: r.AllowAny, Files: r.Files, OnTransfer: k.onTransfer}
	cfg.OnListening = func(a string) {
		s.d.Audit("field.serve", a, fmt.Sprintf("proto=%s all=%t files=%q duration=%s", r.Protocol, r.AllowAny, r.Files, service.SyslogDuration(r.DurationSeconds)))
		k.events <- &v1.ServeFilesResponse{Listening: a, Hint: fileserve.HintIn(i18n.Locale(st.Context()), r.Protocol, a, r.Files)}
	}
	err := fileserve.Serve(ctx, cfg)
	n, rejected := k.stop()
	s.d.Audit("field.serve.done", addr, fmt.Sprintf("transfers=%d rejected=%d", n, rejected))
	if err != nil {
		return service.ErrFrom(st.Context(), codes.Unavailable, err)
	}
	return nil
}

// serveSink: las transferencias reales se auditan; los rechazos (escáneres, nombres
// equivocados) solo se cuentan para el resumen y se reenvían al cliente sin bloquear:
// si el stream va lento se descartan, y la recepción nunca espera.
type serveSink struct {
	loc         string // idioma de la llamada, para lo que va al cliente
	audit       func(action, target, detail string)
	events      chan *v1.ServeFilesResponse
	drained     chan struct{}
	n, rejected atomic.Int64
}

func newServeSink(loc string, audit func(action, target, detail string), send func(*v1.ServeFilesResponse) error) *serveSink {
	k := &serveSink{loc: loc, audit: audit, events: make(chan *v1.ServeFilesResponse, 256), drained: make(chan struct{})}
	go func() {
		defer close(k.drained)
		for ev := range k.events {
			send(ev)
		}
	}()
	return k
}

func (k *serveSink) onTransfer(t fileserve.Transfer) {
	shown := t
	shown.Error = fileserve.ReasonIn(k.loc, t)
	shown.DirCode = service.DirEN(t.Dir)
	b, _ := json.Marshal(shown)
	ev := &v1.ServeFilesResponse{TransferJson: string(b)}
	if t.Rejected {
		k.rejected.Add(1)
		select {
		case k.events <- ev:
		default:
		}
		return
	}
	k.n.Add(1)
	k.audit("field.serve.transfer", t.Client, fmt.Sprintf("proto=%s file=%q bytes=%d duration=%s result=%s error=%q", t.Proto, t.File, t.Bytes, t.Duration.Round(1e6), t.Result, fileserve.ReasonIn(i18n.En, t)))
	k.events <- ev // viene del goroutine de la transferencia, no del de recepción
}

// stop se llama cuando Serve ya terminó (no quedan transferencias en curso).
func (k *serveSink) stop() (n, rejected int64) {
	close(k.events)
	<-k.drained
	return k.n.Load(), k.rejected.Load()
}

func (s *fieldSvc) HashFile(ctx context.Context, r *v1.HashFileRequest) (*v1.HashFileResponse, error) {
	s.d.MarkActive()
	s.d.Audit("field.hash", r.Path, "")
	res, err := imgverify.Check(r.Path, r.Md5, r.Sha512)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	return &v1.HashFileResponse{Report: service.Report(res, hashText(i18n.Locale(ctx), res)), Ok: res.OK()}, nil
}

// Module registra el servicio Field.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterFieldServiceServer(s, &fieldSvc{d: d})
}

// hashText es el informe de HashFile en el idioma pedido.
func hashText(loc string, res imgverify.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s (%d bytes)\n", i18n.Msg(loc, "field.hash.file", nil), res.File, res.Size)
	mark := map[string]string{"ok": "  " + i18n.Msg(loc, "field.hash.match", nil), "distinto": "  " + i18n.Msg(loc, "field.hash.differ", nil), "": ""}
	fmt.Fprintf(&b, "MD5      %s%s\n", res.MD5, mark[res.MD5Match])
	fmt.Fprintf(&b, "SHA-512  %s%s\n", res.SHA512, mark[res.SHA512Match])
	fmt.Fprintf(&b, "%s\n  %s", i18n.Msg(loc, "field.hash.on_device", nil), res.VerifyCommand)
	return b.String()
}
