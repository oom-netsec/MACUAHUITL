package core

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func fakeDiagBin() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "diag", "testdata", "bin")
}

func withFakeTools(o *Options) {
	o.DiagLookPath = func(name string) (string, error) {
		p := filepath.Join(fakeDiagBin(), name)
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}
}

func TestDiagRunStreamsAndAudits(t *testing.T) {
	h := newHarness(t, withFakeTools)
	d := v1.NewDiagServiceClient(h.conn)
	st, err := d.Run(ctx(t), &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}}, Options: map[string]string{"count": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	var last *v1.RunResponse
	for {
		r, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if r.Done {
			last = r
		} else {
			lines = append(lines, r.OutputLine)
		}
	}
	if last == nil || last.ExitCode != 0 || !strings.HasPrefix(filepath.Base(last.OutputPath), "diag_ping_") || len(lines) != 3 {
		t.Fatalf("last=%+v lines=%v", last, lines)
	}
	if !strings.HasPrefix(last.OutputPath, h.out) {
		t.Fatalf("output outside the outputs dir: %s", last.OutputPath)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"diag.run"`) || !strings.Contains(txt, `\"-n\" \"-c\" \"2\" \"192.0.2.1\"`) || !strings.Contains(txt, `"action":"diag.done"`) {
		t.Fatalf("audit:\n%s", txt)
	}
}

func TestDiagRejectsBadRequest(t *testing.T) {
	h := newHarness(t, withFakeTools)
	d := v1.NewDiagServiceClient(h.conn)
	st, err := d.Run(ctx(t), &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_NMAP, Targets: []*v1.Target{{Address: "-iL"}}})
	if err == nil {
		_, err = st.Recv()
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v", err)
	}
	st, _ = d.Run(ctx(t), &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}}, OutputDir: "/etc"})
	if _, err = st.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("output outside home accepted: %v", err)
	}
}

func TestDiagCancelOnDisconnect(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.DiagLookPath = func(string) (string, error) { return filepath.Join(fakeDiagBin(), "sleeper"), nil }
	})
	c, cancel := context.WithCancel(context.Background())
	st, err := v1.NewDiagServiceClient(h.conn).Run(c, &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	st.Recv()
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(h.auditText(t), `"action":"diag.done"`) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("tool kept running after the client disconnected")
}

func TestDiagAuditsRealBinaryAndArgv(t *testing.T) {
	h := newHarness(t, func(o *Options) {
		o.DiagLookPath = func(name string) (string, error) {
			if name == "traceroute" {
				return "", os.ErrNotExist
			}
			return filepath.Join(fakeDiagBin(), name), nil
		}
	})
	st, err := v1.NewDiagServiceClient(h.conn).Run(ctx(t), &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_TRACEROUTE, Targets: []*v1.Target{{Address: "192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := st.Recv(); err != nil {
			break
		}
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `tracepath`) || !strings.Contains(txt, `\"-n\"`) {
		t.Fatalf("audit must show the real binary and quoted argv:\n%s", txt)
	}
	// Una petición inválida no debe crear carpetas.
	bad := filepath.Join(h.out, "nunca")
	st, _ = v1.NewDiagServiceClient(h.conn).Run(ctx(t), &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "-x"}}, OutputDir: bad})
	st.Recv()
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("invalid request created the output dir")
	}
}

func TestListInterfacesSortedWithLoopback(t *testing.T) {
	h := newHarness(t, nil)
	r, err := v1.NewDiagServiceClient(h.conn).ListInterfaces(ctx(t), &v1.ListInterfacesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var lo *v1.NetInterface
	for i, n := range r.Interfaces {
		if i > 0 && r.Interfaces[i-1].Name > n.Name {
			t.Fatalf("sin ordenar: %s antes de %s", r.Interfaces[i-1].Name, n.Name)
		}
		if n.Loopback {
			lo = n
		}
	}
	if lo == nil || !lo.Up || !slices.Contains(lo.Addresses, "127.0.0.1/8") {
		t.Fatalf("loopback = %+v", lo)
	}
}

// El output_dir de una herramienta de diagnóstico se valida como el de Ajustes: 0755 se rechaza; 0700 propia sirve.
func TestDiagValidaOutputDirComoAjustes(t *testing.T) {
	h := newHarness(t, withFakeTools)
	d := v1.NewDiagServiceClient(h.conn)
	correr := func(dir string) error {
		st, err := d.Run(ctx(t), &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}}, OutputDir: dir})
		if err != nil {
			return err
		}
		for {
			if _, err := st.Recv(); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
		}
	}
	laxa := filepath.Join(h.out, "laxa")
	os.Mkdir(laxa, 0o700)
	os.Chmod(laxa, 0o755)
	err := correr(laxa)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "prefs.outputs.permisos:") || !strings.Contains(err.Error(), "chmod 700 "+laxa) {
		t.Fatalf("0755 debía rechazarse con el chmod sugerido: %v", err)
	}
	if err := correr("/tmp"); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "prefs.outputs.reservada:") {
		t.Fatalf("/tmp debía rechazarse: %v", err)
	}
	propia := filepath.Join(h.out, "propia")
	os.Mkdir(propia, 0o700)
	if err := correr(propia); err != nil {
		t.Fatalf("0700 propia debía aceptarse: %v", err)
	}
}
