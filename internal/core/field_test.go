package core

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestFieldConsoleRejectsBadStart(t *testing.T) {
	h := newHarness(t, nil)
	fc := v1.NewFieldServiceClient(h.conn)
	for _, first := range []*v1.ConsoleRequest{
		{Msg: &v1.ConsoleRequest_Data{Data: []byte("x")}},
		{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: "/etc/passwd"}}},
		{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: "/dev/ttyUSB0", Baud: 1234}}},
	} {
		st, _ := fc.Console(ctx(t))
		st.Send(first)
		if _, err := st.Recv(); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", first, err)
		}
	}
}

func TestFieldServeListensHintsAndAudits(t *testing.T) {
	h := newHarness(t, nil)
	img := filepath.Join(t.TempDir(), "c2960x.bin")
	os.WriteFile(img, []byte("ios"), 0o600)
	fc := v1.NewFieldServiceClient(h.conn)
	for _, r := range []*v1.ServeFilesRequest{
		{Protocol: "tftp", Addr: "0.0.0.0:6969", Files: []string{img}},
		{Protocol: "http", Addr: "127.0.0.1:0", Files: []string{"rel.bin"}},
		{Protocol: "http", Addr: "127.0.0.1:0"},
		{Protocol: "scp", Addr: "127.0.0.1:0", Files: []string{img}},
	} {
		st, err := fc.ServeFiles(ctx(t), r)
		if err == nil {
			_, err = st.Recv()
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: %v", r, err)
		}
	}
	// Puerto libre: el 6969 por omisión puede estar ocupado por otra suite o por la app abierta (el puerto por omisión
	// se prueba sin sockets en service/field, TestServeAddrPuertoPorOmision).
	st, err := fc.ServeFiles(ctx(t), &v1.ServeFilesRequest{Protocol: "tftp", Addr: "127.0.0.1:0", Files: []string{img}, DurationSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	port, _ := strings.CutPrefix(first.Listening, "127.0.0.1:")
	if port == "" || port == "0" || !strings.Contains(first.Hint, "copy tftp://127.0.0.1/c2960x.bin") || !strings.Contains(first.Hint, ":"+port) {
		t.Fatalf("first = %+v", first)
	}
	for err == nil {
		_, err = st.Recv()
	}
	if err != io.EOF {
		t.Fatalf("fin: %v", err)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"field.serve"`) || !strings.Contains(txt, `"action":"field.serve.done"`) || !strings.Contains(txt, "c2960x.bin") {
		t.Fatalf("auditoría:\n%s", txt)
	}
}

func TestFieldHash(t *testing.T) {
	h := newHarness(t, nil)
	img := filepath.Join(t.TempDir(), "img.bin")
	os.WriteFile(img, []byte("abc"), 0o600)
	fc := v1.NewFieldServiceClient(h.conn)
	r, err := fc.HashFile(ctx(t), &v1.HashFileRequest{Path: img, Md5: "900150983cd24fb0d6963f7d28e17f72"})
	if err != nil || !r.Ok || !strings.Contains(r.Report.Text, "verify /md5 flash:img.bin 900150983cd24fb0d6963f7d28e17f72") || !json.Valid([]byte(r.Report.Json)) {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = fc.HashFile(ctx(t), &v1.HashFileRequest{Path: img, Md5: strings.Repeat("0", 32)})
	if err != nil || r.Ok || !strings.Contains(r.Report.Text, "NO COINCIDE") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := fc.HashFile(ctx(t), &v1.HashFileRequest{Path: "rel"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if !strings.Contains(h.auditText(t), `"action":"field.hash"`) {
		t.Fatal("hash sin auditar")
	}
}
