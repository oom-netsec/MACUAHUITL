package bridge

import (
	"io"
	"sync"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ---- Terminal SSH (Fase 16b): manual, una sesión por pestaña ----

type TerminalDTO struct {
	Name         string               `json:"name"`
	Address      string               `json:"address"`
	Port         uint32               `json:"port"`
	CredentialID string               `json:"credentialId"`
	Accept       []string             `json:"accept"`
	AcceptedKeys []AcceptedHostKeyDTO `json:"acceptedKeys"`
	Rows         uint32               `json:"rows"`
	Cols         uint32               `json:"cols"`
	// HostID abre un host guardado: con él no viajan dirección, puerto ni credencial (solo, opcional, Username).
	HostID string `json:"hostId"`
	// ExpectedStartupCommand es la orden de inicio que la UI mostró; si no coincide con la guardada el núcleo no conecta.
	ExpectedStartupCommand string `json:"expectedStartupCommand"`
	// Username es del modo tecleado: viaja con dirección sin credencial o con hostId (el núcleo rechaza si el host tiene credencial); vacío = «login as:».
	Username string `json:"username"`
	// Protocol: "telnet" o vacío/"ssh". Con telnet y dirección viajan dirección, puerto y credencial; con hostId nunca viaja (lo pone el host).
	Protocol string `json:"protocol"`
}

func (d TerminalDTO) open() *v1.TerminalOpen {
	tn := d.Protocol == "telnet"
	if d.HostID != "" { // el protocolo y el puerto los pone el host: con hostId nunca viaja Protocol (el núcleo lo rechaza)
		o := &v1.TerminalOpen{Name: d.Name, HostId: d.HostID, Rows: d.Rows, Cols: d.Cols}
		if !tn { // el puente es el límite de confianza: usuario, huellas y orden de inicio no aplican si el DTO dice Telnet
			o.Username, o.AcceptedHostKeyFingerprints, o.AcceptedHostKeys, o.ExpectedStartupCommand = d.Username, d.Accept, protoKeys(d.AcceptedKeys), d.ExpectedStartupCommand
		}
		return o // con credencial en el host el núcleo responde username_with_credential
	}
	if tn {
		return &v1.TerminalOpen{Name: d.Name, Protocol: v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET, Address: d.Address, Port: d.Port, CredentialId: d.CredentialID, Rows: d.Rows, Cols: d.Cols}
	}
	o := &v1.TerminalOpen{Name: d.Name, AcceptedHostKeyFingerprints: d.Accept, AcceptedHostKeys: protoKeys(d.AcceptedKeys), Rows: d.Rows, Cols: d.Cols, ExpectedStartupCommand: d.ExpectedStartupCommand, Address: d.Address, Port: d.Port, CredentialId: d.CredentialID}
	if d.CredentialID == "" {
		o.Username = d.Username
	}
	return o
}

type termSess struct {
	mu sync.Mutex // gRPC no admite Send concurrentes
	st v1.TerminalService_OpenTerminalClient
}

// TerminalOpen abre la sesión y emite terminal:opened {runId, opened, recording},
// terminal:data {runId, data} y terminal:done {runId, error?}. Cerrar la pestaña es TerminalClose.
func (b *Bridge) TerminalOpen(d TerminalDTO) (string, error) {
	if d.Protocol != "" && d.Protocol != "ssh" && d.Protocol != "telnet" {
		return "", b.bridgeErr(i18n.New("terminal.err.protocol", nil))
	}
	c, err := b.client()
	if err != nil {
		return "", wrapErr(err)
	}
	id, ctx, cancel := b.next()
	st, err := v1.NewTerminalServiceClient(c).OpenTerminal(ctx)
	if err == nil {
		err = st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: d.open()}})
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
			if p := r.GetAuthPrompt(); p != nil {
				qs := make([]map[string]any, 0, len(p.Prompts))
				for _, q := range p.Prompts {
					qs = append(qs, map[string]any{"text": q.Text, "echo": q.Echo})
				}
				b.emit("terminal:auth", map[string]any{"runId": id, "seq": p.Seq, "name": p.Name, "instruction": p.Instruction, "prompts": qs})
				continue
			}
			if r.Opened != "" {
				ev := map[string]any{"runId": id, "opened": r.Opened, "recording": r.Recording}
				if p := protoName(r.Protocol); p != "" {
					ev["protocol"] = p
				}
				b.emit("terminal:opened", ev)
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
		return b.bridgeErr(i18n.New("bridge.err.terminal_gone", i18n.A("id", id)))
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

// TerminalAnswer manda las respuestas de una ronda de preguntas (una por pregunta, mismo seq) por el mismo stream.
// Las respuestas son secretos: no se guardan, no se registran y los bytes enviados se ponen en ceros al volver.
func (b *Bridge) TerminalAnswer(id string, seq uint32, answers []string) error {
	return wrapErr(b.terminalAnswer(id, seq, answers, nil))
}

// afterClear (solo pruebas) recibe los bytes ya puestos en ceros: así se ve que el clear() ocurre.
func (b *Bridge) terminalAnswer(id string, seq uint32, answers []string, afterClear func([][]byte)) error {
	bs := make([][]byte, len(answers))
	for i, a := range answers {
		bs[i] = []byte(a)
	}
	if afterClear != nil {
		defer afterClear(bs)
	}
	defer func() {
		for _, x := range bs {
			clear(x)
		}
	}()
	return b.terminal(id, func(st v1.TerminalService_OpenTerminalClient) error {
		return st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_AuthAnswer{AuthAnswer: &v1.AuthAnswer{Seq: seq, Answers: bs}}})
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

// protoName es el protocolo real de la sesión para la UI. Sin dato (núcleo viejo) o con un valor desconocido devuelve ""
// y el evento no lleva la clave: la UI conserva el protocolo de la pestaña en vez de dar por hecho SSH.
func protoName(p v1.TerminalProtocol) string {
	switch p {
	case v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET:
		return "telnet"
	case v1.TerminalProtocol_TERMINAL_PROTOCOL_SSH:
		return "ssh"
	}
	return ""
}
