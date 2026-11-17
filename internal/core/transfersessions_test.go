package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Campo comparte el registro con Transfer (una sola instancia): su primer evento trae server_id, ListTransferSessions
// lo acepta y "" lo incluye; ListServers no lo muestra.
func TestFieldServeSessionsShareRegistry(t *testing.T) {
	h := newHarness(t, nil)
	img := filepath.Join(t.TempDir(), "c9300.bin")
	os.WriteFile(img, []byte("ios-image"), 0o600)
	fc, tc := v1.NewFieldServiceClient(h.conn), v1.NewTransferServiceClient(h.conn)
	sctx, stop := context.WithCancel(ctx(t))
	defer stop()
	st, err := fc.ServeFiles(sctx, &v1.ServeFilesRequest{Protocol: "tftp", Addr: "127.0.0.1:0", Files: []string{img}, DurationSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil || first.ServerId == "" || first.Listening == "" {
		t.Fatalf("primer evento = %+v %v", first, err)
	}
	if _, err := tc.Get(ctx(t), &v1.GetRequest{Url: "tftp://" + first.Listening + "/c9300.bin", DestDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	for ev, err := st.Recv(); ev.GetTransferJson() == ""; ev, err = st.Recv() { // el cliente vuelve antes de que el servidor cierre la sesión
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{first.ServerId, ""} {
		r, err := tc.ListTransferSessions(ctx(t), &v1.ListTransferSessionsRequest{ServerId: id})
		if err != nil || len(r.Sessions) != 1 || r.Sessions[0].State != "done" || r.Sessions[0].Name != "c9300.bin" ||
			r.Sessions[0].ServerId != first.ServerId || r.Sessions[0].Bytes != 9 || r.Sessions[0].Total != 9 {
			t.Fatalf("id=%q: %+v %v", id, r, err)
		}
	}
	if l, _ := tc.ListServers(ctx(t), &v1.ListServersRequest{}); len(l.Servers) != 0 {
		t.Fatalf("Campo aparece en ListServers: %+v", l.Servers)
	}
	if _, err := tc.ListTransferSessions(ctx(t), &v1.ListTransferSessionsRequest{ServerId: "nada"}); status.Code(err) != codes.NotFound {
		t.Fatalf("id desconocido: %v", err)
	}
	stop()
	for err == nil {
		_, err = st.Recv()
	}
	// Cerrado hace menos de 10 min: sigue en la lista; y la auditoría cruza con session=.
	r, err := tc.ListTransferSessions(ctx(t), &v1.ListTransferSessionsRequest{ServerId: first.ServerId})
	if err != nil || len(r.Sessions) != 1 || !strings.Contains(h.auditText(t), "session="+r.Sessions[0].Id+" total=9") {
		t.Fatalf("tras cerrar: %+v %v\n%s", r, err, h.auditText(t))
	}
}
