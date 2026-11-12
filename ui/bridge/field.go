package bridge

import (
	"context"
	"fmt"
	"io"
	"sync"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Campo (consola serie, servidor de archivos, hash) ----

func (b *Bridge) FieldPorts() ([]string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) ([]string, error) {
		r, err := v1.NewFieldServiceClient(c).ListSerialPorts(ctx, &v1.ListSerialPortsRequest{})
		return r.GetPorts(), err
	})
}

type ConsoleDTO struct {
	Port     string `json:"port"`
	Baud     int    `json:"baud"`
	DataBits int    `json:"dataBits"`
	Parity   string `json:"parity"`
	StopBits int    `json:"stopBits"`
	Flow     string `json:"flow"`
}

type consoleSess struct {
	mu sync.Mutex // gRPC no admite Send concurrentes
	st v1.FieldService_ConsoleClient
}

func (b *Bridge) next() (string, context.Context, context.CancelFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.runSeq++
	id := fmt.Sprintf("run-%d", b.runSeq)
	ctx, cancel := context.WithCancel(b.ctx)
	b.runs[id] = cancel
	return id, ctx, cancel
}

func (b *Bridge) finish(id string, cancel context.CancelFunc) {
	b.mu.Lock()
	delete(b.runs, id)
	delete(b.consoles, id)
	b.mu.Unlock()
	cancel()
}

// ConsoleOpen abre la consola y emite console:opened {runId, opened, outputPath},
// console:data {runId, data} y console:done {runId, error?}.
func (b *Bridge) ConsoleOpen(d ConsoleDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", err
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewFieldServiceClient(c).Console(ctx)
	if err == nil {
		err = st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: d.Port, Baud: int32(d.Baud),
			DataBits: int32(d.DataBits), Parity: d.Parity, StopBits: int32(d.StopBits), Flow: d.Flow}}})
	}
	if err != nil {
		b.finish(id, cancel)
		return "", err
	}
	b.mu.Lock()
	if b.consoles == nil {
		b.consoles = map[string]*consoleSess{}
	}
	b.consoles[id] = &consoleSess{st: st}
	b.mu.Unlock()
	go func() {
		defer b.finish(id, cancel)
		for {
			r, err := st.Recv()
			if err != nil {
				ev := map[string]any{"runId": id}
				if ctx.Err() == nil && err != io.EOF {
					ev["error"] = err.Error()
				}
				b.emit("console:done", ev)
				return
			}
			if r.Opened != "" {
				b.emit("console:opened", map[string]any{"runId": id, "opened": r.Opened, "outputPath": r.OutputPath})
				continue
			}
			b.emit("console:data", map[string]any{"runId": id, "data": string(r.Data)})
		}
	}()
	return id, nil
}

func (b *Bridge) console(id string, f func(st v1.FieldService_ConsoleClient) error) error {
	b.mu.Lock()
	s, ok := b.consoles[id]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("consola %q no existe o ya terminó", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return f(s.st)
}

func (b *Bridge) ConsoleSend(id, data string) error {
	return b.console(id, func(st v1.FieldService_ConsoleClient) error {
		return st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Data{Data: []byte(data)}})
	})
}

func (b *Bridge) ConsoleBreak(id string) error {
	return b.console(id, func(st v1.FieldService_ConsoleClient) error {
		return st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_SendBreak{SendBreak: true}})
	})
}

// ConsoleClose cierra el envío: el núcleo graba el cierre, lo audita y termina el stream.
func (b *Bridge) ConsoleClose(id string) error {
	return b.console(id, func(st v1.FieldService_ConsoleClient) error { return st.CloseSend() })
}

type ServeDTO struct {
	Protocol string   `json:"protocol"`
	Addr     string   `json:"addr"`
	Files    []string `json:"files"`
	AllowAny bool     `json:"allowAny"`
	Seconds  int      `json:"seconds"`
}

// ServeStart publica archivos y emite serve:msg {runId, listening, hint, transfer} y
// serve:done {runId, error?}. Se detiene con DiagCancel(id).
func (b *Bridge) ServeStart(d ServeDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", err
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewFieldServiceClient(c).ServeFiles(ctx, &v1.ServeFilesRequest{Protocol: d.Protocol, Addr: d.Addr, Files: d.Files,
		AllowAny: d.AllowAny, DurationSeconds: int32(d.Seconds)})
	if err != nil {
		b.finish(id, cancel)
		return "", err
	}
	go func() {
		defer b.finish(id, cancel)
		for {
			r, err := st.Recv()
			if err != nil {
				ev := map[string]any{"runId": id}
				if ctx.Err() == nil && err != io.EOF {
					ev["error"] = err.Error()
				}
				b.emit("serve:done", ev)
				return
			}
			b.emit("serve:msg", map[string]any{"runId": id, "listening": r.Listening, "hint": r.Hint, "transfer": r.TransferJson})
		}
	}()
	return id, nil
}

type HashDTO struct {
	Text string `json:"text"`
	Ok   bool   `json:"ok"`
}

func (b *Bridge) FieldHash(path, md5, sha512 string) (HashDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (HashDTO, error) {
		r, err := v1.NewFieldServiceClient(c).HashFile(ctx, &v1.HashFileRequest{Path: path, Md5: md5, Sha512: sha512})
		return HashDTO{Text: r.GetReport().GetText(), Ok: r.GetOk()}, err
	})
}
