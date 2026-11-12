package bridge

import (
	"fmt"
	"io"
	"sync"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// ---- Terminal SSH (Fase 16b): manual, una sesión por pestaña ----

type TerminalDTO struct {
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	Port         uint32   `json:"port"`
	CredentialID string   `json:"credentialId"`
	Accept       []string `json:"accept"`
	Rows         uint32   `json:"rows"`
	Cols         uint32   `json:"cols"`
}

type termSess struct {
	mu sync.Mutex // gRPC no admite Send concurrentes
	st v1.TerminalService_OpenTerminalClient
}

// TerminalOpen abre la sesión y emite terminal:opened {runId, opened, recording},
// terminal:data {runId, data} y terminal:done {runId, error?}. Cerrar la pestaña es TerminalClose.
func (b *Bridge) TerminalOpen(d TerminalDTO) (string, error) {
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewTerminalServiceClient(c).OpenTerminal(ctx)
	if err == nil {
		err = st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: &v1.TerminalOpen{Name: d.Name, Address: d.Address, Port: d.Port,
			CredentialId: d.CredentialID, AcceptedHostKeyFingerprints: d.Accept, Rows: d.Rows, Cols: d.Cols}}})
	}
	if err != nil {
		b.finish(id, cancel)
		return "", wrapErr(err)
	}
	b.mu.Lock()
	if b.terminals == nil {
		b.terminals = map[string]*termSess{}
	}
	b.terminals[id] = &termSess{st: st}
	b.mu.Unlock()
	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.terminals, id)
			b.mu.Unlock()
			b.finish(id, cancel)
		}()
		for {
			r, err := st.Recv()
			if err != nil {
				ev := map[string]any{"runId": id}
				if ctx.Err() == nil && err != io.EOF {
					ev["error"] = err.Error()
					ev["errorInfo"] = errorInfo(err)
				}
				b.emit("terminal:done", ev)
				return
			}
			if r.Opened != "" {
				b.emit("terminal:opened", map[string]any{"runId": id, "opened": r.Opened, "recording": r.Recording})
				continue
			}
			b.emit("terminal:data", map[string]any{"runId": id, "data": string(r.Data)})
		}
	}()
	return id, nil
}

func (b *Bridge) terminal(id string, f func(st v1.TerminalService_OpenTerminalClient) error) error {
	b.mu.Lock()
	s, ok := b.terminals[id]
	b.mu.Unlock()
	if !ok {
		return wrapErr(fmt.Errorf("terminal %q no existe o ya terminó", id))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return wrapErr(f(s.st))
}

func (b *Bridge) TerminalSend(id, data string) error {
	return b.terminal(id, func(st v1.TerminalService_OpenTerminalClient) error {
		return st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Data{Data: []byte(data)}})
	})
}

func (b *Bridge) TerminalResize(id string, rows, cols uint32) error {
	return b.terminal(id, func(st v1.TerminalService_OpenTerminalClient) error {
		return st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Resize{Resize: &v1.TerminalSize{Rows: rows, Cols: cols}}})
	})
}

// TerminalClose cierra el envío: el núcleo cierra SSH, revoca el guard, lo audita y termina el stream.
func (b *Bridge) TerminalClose(id string) error {
	return b.terminal(id, func(st v1.TerminalService_OpenTerminalClient) error { return st.CloseSend() })
}
