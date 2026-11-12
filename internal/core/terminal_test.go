package core

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Cerrar la pestaña es cancelar el stream: el núcleo cierra SSH, revoca el guard y lo audita.
func TestTerminalCerrarLaPestanaRevocaYAudita(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	tc := v1.NewTerminalServiceClient(h.conn)
	open := &v1.TerminalOpen{Name: "sw1", Address: h.target.Address, Port: h.target.Port, CredentialId: cred}
	// Sin aceptar la llave de host el núcleo no conecta y devuelve la huella.
	st, err := tc.OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}})
	_, err = st.Recv()
	if err == nil || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("llave nueva: %v", err)
	}
	fp := regexp.MustCompile(`SHA256:[^\s\\"]+`).FindString(err.Error())
	open.AcceptedHostKeyFingerprints = []string{fp}

	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err = tc.OpenTerminal(cctx)
	if err != nil {
		t.Fatal(err)
	}
	st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}})
	first, err := st.Recv()
	if err != nil || first.Recording == "" {
		t.Fatalf("abrir: %+v %v", first, err)
	}
	st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Data{Data: []byte("show version\r")}})
	var got strings.Builder
	for !strings.Contains(got.String(), "Cisco") {
		r, err := st.Recv()
		if err != nil {
			t.Fatalf("recv: %v (%q)", err, got.String())
		}
		got.Write(r.Data)
	}
	cancel()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		a := h.auditText(t)
		if strings.Contains(a, `"action":"terminal.close"`) {
			if !strings.Contains(a, "guard=revocado") {
				t.Fatalf("sin revocar:\n%s", a)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no se auditó el cierre:\n%s", a)
		}
	}
	actionsInOrder(t, h.auditText(t), "terminal.failed", "terminal.open", "terminal.close")
}
