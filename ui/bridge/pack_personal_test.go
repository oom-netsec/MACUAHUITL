package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakePackPersonal struct {
	v1.UnimplementedPackServiceServer
	got *v1.PackServiceImportRequest
}

func (fakePackPersonal) Export(_ context.Context, r *v1.PackServiceExportRequest) (*v1.PackServiceExportResponse, error) {
	return &v1.PackServiceExportResponse{Id: r.EditorName, Version: "2026.1113.1405", Sha256: "ab", Scripts: int32(len(r.ScriptIds)), OmittedPlaybooks: []string{"nx-os/x"}}, nil
}

func (f *fakePackPersonal) Import(_ context.Context, r *v1.PackServiceImportRequest) (*v1.PackServiceImportResponse, error) {
	f.got = r
	return &v1.PackServiceImportResponse{Pack: &v1.PackInfo{Id: "acme/mio"}, Applied: r.Confirm, PlaybooksRenamed: 1,
		Items: []*v1.PackImportItem{{Kind: "playbook", Id: "ios/acme-x", State: "conflicto_id", ConflictsWith: "user"}}}, nil
}

func TestPackPersonalBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakePackPersonal{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterPackServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	ex, err := b.PackExport(PackExportRequestDTO{EditorName: "acme/mio", ScriptIDs: []string{"a", "b"}, Path: "/x.mpack"})
	if err != nil || ex.ID != "acme/mio" || ex.Scripts != 2 || ex.OmittedPlaybooks[0] != "nx-os/x" {
		t.Fatalf("%+v %v", ex, err)
	}
	pv, err := b.PackImportPreview("/x.mpack")
	if err != nil || pv.Applied || f.got.Confirm || pv.Items[0].ConflictsWith != "user" {
		t.Fatalf("%+v %v", pv, err)
	}
	ap, err := b.PackImport("/x.mpack", []PackImportDecisionDTO{{ItemID: "ios/acme-x", Action: "renombrar"}})
	if err != nil || !ap.Applied || !f.got.Confirm || f.got.Decisions[0].Action != "renombrar" || ap.PlaybooksRenamed != 1 {
		t.Fatalf("%+v %v", ap, err)
	}
	j, _ := json.Marshal(packImportDTO(&v1.PackServiceImportResponse{}))
	if !strings.Contains(string(j), `"items":[]`) || !strings.Contains(string(j), `"playbookIds":[]`) || !strings.Contains(string(j), `"warnings":[]`) {
		t.Fatalf("json = %s", j)
	}
}
