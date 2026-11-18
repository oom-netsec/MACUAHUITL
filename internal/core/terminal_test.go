package core

import (
	"context"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
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
			if !strings.Contains(a, "guard=revoked") {
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

// recvPrompt lee del stream hasta el siguiente AuthPrompt.
func recvPrompt(t *testing.T, st v1.TerminalService_OpenTerminalClient) *v1.AuthPrompt {
	t.Helper()
	for {
		r, err := st.Recv()
		if err != nil {
			t.Fatalf("esperaba un AuthPrompt: %v", err)
		}
		if r.AuthPrompt != nil {
			return r.AuthPrompt
		}
	}
}

func answer(t *testing.T, st v1.TerminalService_OpenTerminalClient, seq uint32, ans ...string) {
	t.Helper()
	a := &v1.AuthAnswer{Seq: seq}
	for _, s := range ans {
		a.Answers = append(a.Answers, []byte(s))
	}
	if err := st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_AuthAnswer{AuthAnswer: a}}); err != nil {
		t.Fatal(err)
	}
}

// TestE2ETecleada: terminal sin credencial por el ipc real contra un simulador con MFA. Huella nueva primero (sin preguntas; la UI
// reenvía solo el usuario), luego «login as:», la ronda MFA y opened; nada de lo tecleado queda en la auditoría.
func TestE2ETecleada(t *testing.T) {
	const otp, pw = "246810", "MARCA-E2E-clave-9f3"
	h := newHarness(t, nil)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-MFA", Username: "admin", Password: pw, OTP: otp, Transcripts: transcripts()})
	ap := netip.MustParseAddrPort(addr)
	tc := v1.NewTerminalServiceClient(h.conn)
	open := &v1.TerminalOpen{Address: ap.Addr().String(), Port: uint32(ap.Port()), Username: "admin"}
	req := &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}}

	// Huella nueva (con usuario ya dado): el núcleo la devuelve antes de cualquier pregunta.
	st, err := tc.OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	st.Send(req)
	var rerr error
	for rerr == nil {
		var r *v1.OpenTerminalResponse
		if r, rerr = st.Recv(); rerr == nil && r.AuthPrompt != nil {
			t.Fatal("preguntó antes de verificar la huella")
		}
	}
	if !strings.Contains(rerr.Error(), "SHA256:") {
		t.Fatalf("huella nueva: %v", rerr)
	}
	open.AcceptedHostKeyFingerprints = []string{regexp.MustCompile(`SHA256:[^\s\\"]+`).FindString(rerr.Error())}
	// «Confiar y reintentar»: se reenvía solo el usuario, nunca respuestas.

	st, err = tc.OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	st.Send(req)
	m := recvPrompt(t, st)
	if m.Name != "MFA" || len(m.Prompts) != 2 {
		t.Fatalf("MFA = %+v", m)
	}
	answer(t, st, m.Seq, pw, otp)
	r, err := st.Recv()
	if err != nil || r.Opened != "admin@"+open.Address+":"+strconv.Itoa(int(open.Port)) {
		t.Fatalf("opened = %+v %v", r, err)
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
	st.CloseSend()

	// Sin usuario: «login as:» y luego la ronda MFA.
	open.Username = ""
	st, err = tc.OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	st.Send(req)
	l := recvPrompt(t, st)
	if len(l.Prompts) != 1 || !l.Prompts[0].Echo {
		t.Fatalf("login = %+v", l)
	}
	answer(t, st, l.Seq, "admin")
	m = recvPrompt(t, st)
	answer(t, st, m.Seq, pw, otp)
	if r, err := st.Recv(); err != nil || r.Opened == "" {
		t.Fatalf("opened = %+v %v", r, err)
	}
	st.CloseSend()

	a := h.auditText(t)
	if !strings.Contains(a, `credential=typed`) || strings.Contains(a, pw) || strings.Contains(a, otp) {
		t.Fatalf("auditoría:\n%s", a)
	}
}
