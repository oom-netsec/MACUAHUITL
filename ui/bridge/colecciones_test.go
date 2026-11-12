package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeCols struct {
	v1.UnimplementedScriptsServiceServer
	save    *v1.SaveCollectionRequest
	set     *v1.SetCollectionScriptsRequest
	pin     *v1.SetPinnedRequest
	reorder []string
	pinned  []string
	apply   *v1.ApplyImportCollectionsRequest
}

func (f *fakeCols) ListCollections(context.Context, *v1.ListCollectionsRequest) (*v1.ListCollectionsResponse, error) {
	return &v1.ListCollectionsResponse{Collections: []*v1.Collection{{Id: "favoritos", Name: "Favoritos", Order: 0}, {Id: "x", Name: "X", Order: 1, ScriptIds: []string{"a", "lib-b"}, CreatedMs: 3, UpdatedMs: 4}}}, nil
}
func (f *fakeCols) GetCollection(_ context.Context, r *v1.GetCollectionRequest) (*v1.GetCollectionResponse, error) {
	return &v1.GetCollectionResponse{Collection: &v1.Collection{Id: r.Id, Name: "N"}}, nil
}
func (f *fakeCols) SaveCollection(_ context.Context, r *v1.SaveCollectionRequest) (*v1.SaveCollectionResponse, error) {
	f.save = r
	return &v1.SaveCollectionResponse{Collection: r.Collection}, nil
}
func (f *fakeCols) DeleteCollection(context.Context, *v1.DeleteCollectionRequest) (*v1.DeleteCollectionResponse, error) {
	return &v1.DeleteCollectionResponse{}, nil
}
func (f *fakeCols) ReorderCollections(_ context.Context, r *v1.ReorderCollectionsRequest) (*v1.ReorderCollectionsResponse, error) {
	f.reorder = r.Ids
	return &v1.ReorderCollectionsResponse{}, nil
}
func (f *fakeCols) SetCollectionScripts(_ context.Context, r *v1.SetCollectionScriptsRequest) (*v1.SetCollectionScriptsResponse, error) {
	f.set = r
	return &v1.SetCollectionScriptsResponse{Collection: &v1.Collection{Id: r.Id, ScriptIds: r.ScriptIds}}, nil
}
func (f *fakeCols) SetPinned(_ context.Context, r *v1.SetPinnedRequest) (*v1.SetPinnedResponse, error) {
	f.pin = r
	return &v1.SetPinnedResponse{}, nil
}
func (f *fakeCols) ListPinned(context.Context, *v1.ListPinnedRequest) (*v1.ListPinnedResponse, error) {
	return &v1.ListPinnedResponse{Scripts: []*v1.Script{{Id: "p", Name: "P", Pinned: true, Collections: []string{"x"}}}}, nil
}
func (f *fakeCols) ReorderPinned(_ context.Context, r *v1.ReorderPinnedRequest) (*v1.ReorderPinnedResponse, error) {
	f.pinned = r.Ids
	return &v1.ReorderPinnedResponse{}, nil
}
func (f *fakeCols) ExportCollections(_ context.Context, r *v1.ExportCollectionsRequest) (*v1.ExportCollectionsResponse, error) {
	return &v1.ExportCollectionsResponse{Collections: int32(len(r.Ids)), Scripts: 7}, nil
}
func (f *fakeCols) PreviewImportCollections(context.Context, *v1.PreviewImportCollectionsRequest) (*v1.PreviewImportCollectionsResponse, error) {
	return &v1.PreviewImportCollectionsResponse{Token: "tok", ExpiresMs: 9,
		Collections: []*v1.CollectionImportItem{{Collection: &v1.Collection{Id: "c", Name: "C"}, State: "conflicto_nombre", ConflictsWith: "d"}},
		Scripts:     []*v1.ImportItem{{Script: &v1.Script{Id: "a", Name: "A"}, State: "nuevo"}}, Warnings: []string{"aviso"}}, nil
}
func (f *fakeCols) ApplyImportCollections(_ context.Context, r *v1.ApplyImportCollectionsRequest) (*v1.ApplyImportCollectionsResponse, error) {
	f.apply = r
	return &v1.ApplyImportCollectionsResponse{ScriptsCreated: 1, ScriptsReplaced: 2, ScriptsRenamed: 3, ScriptsSkipped: 4,
		CollectionsCreated: 5, CollectionsReplaced: 6, CollectionsRenamed: 7, CollectionsMerged: 8, CollectionsSkipped: 9, Warnings: []string{"w"}}, nil
}

func (f *fakeCols) ImportTemplate(_ context.Context, r *v1.ImportTemplateRequest) (*v1.ImportTemplateResponse, error) {
	return &v1.ImportTemplateResponse{Json: "{" + r.Kind + "}"}, nil
}
func (f *fakeCols) ImportFormat(_ context.Context, r *v1.ImportFormatRequest) (*v1.ImportFormatResponse, error) {
	return &v1.ImportFormatResponse{Fields: []*v1.FormatField{{Name: r.Kind + ".x", Type: "texto", Required: true, Example: `"e"`, Description: "d"}}}, nil
}

func TestCollectionsBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeCols{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterScriptsServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	cols, err := b.ListCollections()
	if err != nil || len(cols) != 2 || cols[1].ID != "x" || cols[1].Order != 1 || len(cols[1].ScriptIDs) != 2 || cols[1].CreatedMs != 3 || cols[0].ScriptIDs == nil {
		t.Fatalf("lista = %+v err = %v (las listas van como [] y no como null)", cols, err)
	}
	if g, err := b.GetCollection("zz"); err != nil || g.ID != "zz" {
		t.Fatalf("get = %+v %v", g, err)
	}
	if s, err := b.SaveCollection("", "Nueva", "d"); err != nil || s.Name != "Nueva" || f.save.Collection.Description != "d" || f.save.Collection.Id != "" {
		t.Fatalf("save = %+v got = %+v err = %v", s, f.save, err)
	}
	if err := b.DeleteCollection("x"); err != nil {
		t.Fatal(err)
	}
	if err := b.ReorderCollections([]string{"x", "favoritos"}); err != nil || len(f.reorder) != 2 || f.reorder[0] != "x" {
		t.Fatalf("reorder = %v %v", f.reorder, err)
	}
	if c, err := b.SetCollectionScripts("x", []string{"a", "lib-b"}); err != nil || len(c.ScriptIDs) != 2 || f.set.Id != "x" || f.set.ScriptIds[1] != "lib-b" {
		t.Fatalf("set = %+v got = %+v err = %v", c, f.set, err)
	}
	if err := b.SetScriptPinned("p", true); err != nil || f.pin.Id != "p" || !f.pin.Pinned {
		t.Fatalf("pin = %+v %v", f.pin, err)
	}
	if p, err := b.ListPinnedScripts(); err != nil || len(p) != 1 || !p[0].Pinned || len(p[0].Collections) != 1 || p[0].Commands == nil {
		t.Fatalf("fijados = %+v %v", p, err)
	}
	if err := b.ReorderPinnedScripts([]string{"p", "q"}); err != nil || len(f.pinned) != 2 {
		t.Fatalf("reorder pinned = %v %v", f.pinned, err)
	}
	if r, err := b.ExportCollections([]string{"x", "y"}, "/tmp/c.json", true); err != nil || r.Collections != 2 || r.Scripts != 7 {
		t.Fatalf("export = %+v %v", r, err)
	}
	p, err := b.PreviewCollectionsImport("/tmp/c.json")
	if err != nil || p.Token != "tok" || p.ExpiresMs != 9 || len(p.Collections) != 1 || p.Collections[0].State != "conflicto_nombre" || p.Collections[0].ConflictsWith != "d" ||
		len(p.Scripts) != 1 || p.Scripts[0].Script.ID != "a" || len(p.Warnings) != 1 {
		t.Fatalf("preview = %+v err = %v", p, err)
	}
	if j, err := b.ImportTemplate("colecciones"); err != nil || j != "{colecciones}" {
		t.Fatalf("plantilla = %q %v", j, err)
	}
	if fs, err := b.ImportFormat("scripts"); err != nil || len(fs) != 1 || fs[0] != (FormatFieldDTO{"scripts.x", "texto", true, `"e"`, "d"}) {
		t.Fatalf("formato = %+v %v", fs, err)
	}
	r, err := b.ApplyCollectionsImport("tok", []ImportDecisionDTO{{ScriptID: "a", Action: "omitir"}}, []ImportDecisionDTO{{ScriptID: "c", Action: "renombrar"}})
	want := CollectionsImportResultDTO{1, 2, 3, 4, 5, 6, 7, 8, 9, []string{"w"}}
	if err != nil || r.CollectionsMerged != want.CollectionsMerged || r.ScriptsSkipped != 4 || r.CollectionsCreated != 5 || len(r.Warnings) != 1 ||
		len(f.apply.ScriptDecisions) != 1 || f.apply.ScriptDecisions[0].ScriptId != "a" || f.apply.CollectionDecisions[0].ScriptId != "c" || f.apply.CollectionDecisions[0].Action != "renombrar" {
		t.Fatalf("apply = %+v got = %+v err = %v", r, f.apply, err)
	}
}
