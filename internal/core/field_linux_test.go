//go:build linux

package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
)

func TestFieldConsoleSessionRecordsAndAudits(t *testing.T) {
	h := newHarness(t, nil)
	dev, port, err := serialcon.Pty()
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	fc := v1.NewFieldServiceClient(h.conn)
	if _, err := fc.ListSerialPorts(ctx(t), &v1.ListSerialPortsRequest{}); err != nil {
		t.Fatal(err)
	}
	st, err := fc.Console(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: port}}})
	first, err := st.Recv()
	if err != nil || !strings.Contains(first.Opened, "9600 8N1") || !strings.HasPrefix(first.OutputPath, filepath.Join(h.out, "console")) {
		t.Fatalf("first = %+v, %v", first, err)
	}
	dev.Write([]byte("\r\nSwitch>"))
	var got string
	for !strings.Contains(got, "Switch>") {
		r, err := st.Recv()
		if err != nil {
			t.Fatal(err)
		}
		got += string(r.Data)
	}
	st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Data{Data: []byte("MARKER-PW\r")}})
	buf := make([]byte, 64)
	n, _ := dev.Read(buf)
	if string(buf[:n]) != "MARKER-PW\r" {
		t.Fatalf("equipo recibió %q", buf[:n])
	}
	st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_SendBreak{SendBreak: true}})
	st.CloseSend()
	for err == nil {
		_, err = st.Recv()
	}
	if err != io.EOF {
		t.Fatalf("fin: %v", err)
	}
	rec, _ := os.ReadFile(first.OutputPath)
	if !strings.Contains(string(rec), "Switch>") || !strings.Contains(string(rec), "### BREAK") || strings.Contains(string(rec), "MARKER-PW") {
		t.Fatalf("grabación:\n%s", rec)
	}
	if fi, _ := os.Stat(first.OutputPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("permisos %v", fi.Mode())
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"field.console.open"`) || !strings.Contains(txt, `"action":"field.console.close"`) || strings.Contains(txt, "MARKER-PW") {
		t.Fatalf("auditoría:\n%s", txt)
	}
}
