package core

import (
	"bytes"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const e2eStartup = "cmd /c echo macuahuitl-ok"

// e2eHost arma el flujo común: llave generada, simulador que solo acepta esa pública y un host windows con orden de inicio.
func e2eHost(t *testing.T) (h *harness, hostID, keyID string, log *[]string, rec *simulator.Recorder, conns *atomic.Int32) {
	t.Helper()
	return e2eHostKey(t, "windows", e2eStartup, "cmd /c echo ", func(h *harness) (string, string) {
		keyID := h.keygen(t, "llave-e2e").Id
		pub, err := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: keyID})
		if err != nil {
			t.Fatal(err)
		}
		return keyID, pub.PublicKey
	})
}

// e2eHostKey es e2eHost con la plataforma, la orden de inicio (que el simulador contesta quitando el prefijo echo) y la creación de la
// llave a cargo de mk, que devuelve su id y la línea authorized_keys que el simulador acepta.
func e2eHostKey(t *testing.T, platform, startup, echo string, mk func(h *harness) (keyID, authorized string)) (h *harness, hostID, keyID string, log *[]string, rec *simulator.Recorder, conns *atomic.Int32) {
	t.Helper()
	h = newHarness(t, nil)
	h.ready(t)
	keyID, authorized := mk(h)
	log, rec, conns = new([]string), &simulator.Recorder{}, new(atomic.Int32)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "host", Username: "pi", AuthLog: log, Recorder: rec, Conns: conns,
		Transcripts: t.TempDir(), AuthorizedKeys: simulator.Keys(simulator.ParseAuthorizedKey(t, authorized)),
		Exec: func(cmd string) string { return strings.TrimPrefix(cmd, echo) + "\r\n" }})
	ap := netip.MustParseAddrPort(addr)
	r, err := v1.NewInventoryServiceClient(h.conn).PutDevice(ctx(t), &v1.PutDeviceRequest{Device: &v1.Device{Name: "host1", Platform: platform,
		Target: &v1.Target{Address: ap.Addr().String()}, Profile: &v1.DeviceProfile{Port: uint32(ap.Port())}, CredentialId: keyID, StartupCommand: startup}})
	if err != nil {
		t.Fatal(err)
	}
	return h, r.Id, keyID, log, rec, conns
}

// TestE2ELinuxLlavesImportadas: host linux guardado con una llave IMPORTADA, terminal por host_id, huella del host aceptada, orden de
// inicio y salida. La RSA autentica con rsa-sha2 (el servidor de x/crypto no acepta ssh-rsa con SHA-1), no con el algoritmo viejo.
func TestE2ELinuxLlavesImportadas(t *testing.T) {
	frase := []byte("frase-e2e-del-dueno")
	edPEM, _ := simulator.EncryptedEd25519(t, frase)
	rsaPEM, _ := rsaPKCS1(t, 2048)
	for _, c := range []struct {
		n         string
		pem, pass []byte
	}{{"ed25519 con frase", edPEM, frase}, {"rsa 2048 sin frase", rsaPEM, nil}} {
		t.Run(c.n, func(t *testing.T) {
			startup := "echo macuahuitl-ok"
			h, hostID, _, authLog, rec, _ := e2eHostKey(t, "linux", startup, "echo ", func(h *harness) (string, string) {
				r, err := h.importKey(t, "importada", bytes.Clone(c.pem), bytes.Clone(c.pass))
				if err != nil {
					t.Fatal(err)
				}
				return r.Id, r.PublicKey
			})
			tc := v1.NewTerminalServiceClient(h.conn)
			open := &v1.TerminalOpen{HostId: hostID, ExpectedStartupCommand: startup}
			req := &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}}
			st, err := tc.OpenTerminal(ctx(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Send(req); err != nil {
				t.Fatal(err)
			}
			_, err = st.Recv()
			if err == nil || !strings.Contains(err.Error(), "SHA256:") {
				t.Fatalf("llave de host nueva: %v", err)
			}
			open.AcceptedHostKeyFingerprints = []string{regexp.MustCompile(`SHA256:[^\s\\"]+`).FindString(err.Error())}
			st, err = tc.OpenTerminal(ctx(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Send(req); err != nil {
				t.Fatal(err)
			}
			var got strings.Builder
			for {
				r, err := st.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("la sesión debía terminar sin error: %v (%q)", err, got.String())
				}
				got.Write(r.Data)
			}
			if !strings.Contains(got.String(), "macuahuitl-ok") {
				t.Fatalf("no llegó macuahuitl-ok: %q", got.String())
			}
			if !strings.Contains(strings.Join(*authLog, ","), "publickey") {
				t.Fatalf("sin publickey: %v", *authLog)
			}
			if l := strings.Join(rec.Lines(), "\n"); !strings.Contains(l, "!exec pty=true "+startup) {
				t.Fatalf("el simulador no vio el exec con PTY:\n%s", l)
			}
		})
	}
}

func TestE2EWindowsLlaveOrdenDeInicio(t *testing.T) {
	h, hostID, keyID, authLog, rec, conns := e2eHost(t)
	tc := v1.NewTerminalServiceClient(h.conn)
	open := &v1.TerminalOpen{HostId: hostID, ExpectedStartupCommand: e2eStartup}
	req := &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}}

	// Primera apertura: llave de host nueva, el núcleo devuelve la huella y no conecta la sesión.
	st, err := tc.OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(req); err != nil {
		t.Fatal(err)
	}
	_, err = st.Recv()
	if err == nil || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("llave nueva: %v", err)
	}
	open.AcceptedHostKeyFingerprints = []string{regexp.MustCompile(`SHA256:[^\s\\"]+`).FindString(err.Error())}

	st, err = tc.OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(req); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	done := make(chan error, 1)
	go func() {
		for {
			r, err := st.Recv()
			if err != nil {
				done <- err
				return
			}
			got.Write(r.Data)
		}
	}()
	err = <-done // ctx(t) acota la espera: si la sesión no termina sola, Recv devuelve DeadlineExceeded
	if err != io.EOF {
		t.Fatalf("la sesión debía terminar sin error: %v (%q)", err, got.String())
	}
	if !strings.Contains(got.String(), "macuahuitl-ok") {
		t.Fatalf("no llegó macuahuitl-ok: %q", got.String())
	}

	for _, m := range *authLog {
		if m != "none" && m != "publickey" {
			t.Fatalf("método de autenticación inesperado %q en %v", m, *authLog)
		}
	}
	if !strings.Contains(strings.Join(*authLog, ","), "publickey") {
		t.Fatalf("sin publickey: %v", *authLog)
	}
	if l := strings.Join(rec.Lines(), "\n"); !strings.Contains(l, "!exec pty=true "+e2eStartup) {
		t.Fatalf("el simulador no vio el exec con PTY:\n%s", l)
	}
	if conns.Load() == 0 {
		t.Fatal("el simulador no vio conexiones")
	}

	// Auditoría: keygen, alta con startup=, terminal.open con host= y startup=; ni semilla ni PEM de la privada.
	a := h.auditText(t)
	for _, want := range []string{`"action":"credential.keygen"`, `"action":"terminal.open"`, "host=" + hostID + ` startup=\"` + e2eStartup + `\"`} {
		if !strings.Contains(a, want) {
			t.Fatalf("falta %q en la auditoría:\n%s", want, a)
		}
	}
	if !strings.Contains(a, "platform=windows startup=") {
		t.Fatalf("el alta del host no audita startup=:\n%s", a)
	}
	c, err := h.core.vault.Get(keyID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.SSHKey.Destroy()
	if strings.Contains(a, "PRIVATE KEY") {
		t.Fatal("PEM en la auditoría")
	}
	for _, n := range needles(t, c.SSHKey.Bytes()) {
		if strings.Contains(a, n) {
			t.Fatalf("la privada (%.8q…) aparece en la auditoría", n)
		}
	}
}

func TestE2EStartupCambiadoNoConecta(t *testing.T) {
	h, hostID, _, _, _, conns := e2eHost(t)
	st, err := v1.NewTerminalServiceClient(h.conn).OpenTerminal(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	st.Send(&v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: &v1.TerminalOpen{HostId: hostID, ExpectedStartupCommand: "cmd /c echo otra"}}})
	_, err = st.Recv()
	if reason, _ := reasonOf(err); codeOf(err) != codes.FailedPrecondition || reason != "terminal.err.startup_changed" {
		t.Fatalf("esperaba FailedPrecondition startup_changed: %v", err)
	}
	if n := conns.Load(); n != 0 {
		t.Fatalf("conectó %d veces con la orden cambiada", n)
	}
}
