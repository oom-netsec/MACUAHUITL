package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeScripts struct {
	v1.UnimplementedScriptsServiceServer
	got *v1.SaveScriptRequest
	dec []*v1.ImportDecision
}

func (f *fakeScripts) ListScripts(_ context.Context, r *v1.ListScriptsRequest) (*v1.ListScriptsResponse, error) {
	return &v1.ListScriptsResponse{Scripts: []*v1.Script{{Id: "lib-x", Name: "q=" + r.Text + "," + r.Tech, Origin: "biblioteca", ReadOnly: true, Favorite: r.OnlyFavorites, CreatedMs: 5}}}, nil
}
func (f *fakeScripts) SaveScript(_ context.Context, r *v1.SaveScriptRequest) (*v1.SaveScriptResponse, error) {
	f.got = r
	return &v1.SaveScriptResponse{Script: r.Script}, nil
}
func (f *fakeScripts) ExportScripts(_ context.Context, r *v1.ExportScriptsRequest) (*v1.ExportScriptsResponse, error) {
	return &v1.ExportScriptsResponse{Count: int32(len(r.Ids))}, nil
}
func (f *fakeScripts) PreviewImport(context.Context, *v1.PreviewImportRequest) (*v1.PreviewImportResponse, error) {
	return &v1.PreviewImportResponse{Token: "tok", ExpiresMs: 9, Items: []*v1.ImportItem{{Script: &v1.Script{Id: "a", Name: "A"}, State: "conflicto_id", ConflictsWith: "a"}}, Warnings: []string{"sin suma"}}, nil
}
func (f *fakeScripts) ApplyImport(_ context.Context, r *v1.ApplyImportRequest) (*v1.ApplyImportResponse, error) {
	f.dec = r.Decisions
	return &v1.ApplyImportResponse{Created: 1, Replaced: 2, Renamed: 3, Skipped: 4}, nil
}
func (f *fakeScripts) SetFavorite(context.Context, *v1.SetFavoriteRequest) (*v1.SetFavoriteResponse, error) {
	return &v1.SetFavoriteResponse{}, nil
}

func TestScriptsBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeScripts{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterScriptsServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	l1, err := b.ListScripts(ScriptFilterDTO{Text: "ospf", Tech: "l3", OnlyFavorites: true})
	if err != nil || len(l1) != 1 || l1[0].Name != "q=ospf,l3" || !l1[0].ReadOnly || !l1[0].Favorite || l1[0].CreatedMs != 5 {
		t.Fatalf("lista = %+v err = %v", l1, err)
	}
	if l1[0].Commands == nil || l1[0].Tags == nil {
		t.Fatalf("las listas van como [] y no como null: %+v", l1[0])
	}
	s, err := b.SaveScript(ScriptDTO{Name: "N", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Origin: "biblioteca", Favorite: true})
	if err != nil || s.Name != "N" || f.got.Script.Origin != "" || f.got.Script.Favorite {
		t.Fatalf("save = %+v got = %+v err = %v (origen, favorito y fechas no viajan al guardar)", s, f.got, err)
	}
	if n, err := b.ExportScripts([]string{"a", "b"}, "/tmp/x.json", false); err != nil || n != 2 {
		t.Fatalf("export = %d err = %v", n, err)
	}
	p, err := b.PreviewScriptsImport("/tmp/x.json")
	if err != nil || p.Token != "tok" || p.ExpiresMs != 9 || len(p.Items) != 1 || p.Items[0].State != "conflicto_id" || p.Items[0].ConflictsWith != "a" || len(p.Warnings) != 1 || p.Warnings[0] != "sin suma" {
		t.Fatalf("preview = %+v err = %v", p, err)
	}
	r, err := b.ApplyScriptsImport("tok", []ImportDecisionDTO{{ScriptID: "a", Action: "omitir"}})
	if err != nil || r != (ImportResultDTO{1, 2, 3, 4}) || len(f.dec) != 1 || f.dec[0].ScriptId != "a" || f.dec[0].Action != "omitir" {
		t.Fatalf("apply = %+v dec = %v err = %v", r, f.dec, err)
	}
	if err := b.SetScriptFavorite("lib-x", true); err != nil {
		t.Fatal(err)
	}
}
