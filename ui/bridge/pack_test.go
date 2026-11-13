package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakePack struct {
	v1.UnimplementedPackServiceServer
}

func (fakePack) Install(_ context.Context, r *v1.PackServiceInstallRequest) (*v1.PackServiceInstallResponse, error) {
	if !r.AllowUnsigned {
		return nil, status.Error(codes.FailedPrecondition, "sin firma")
	}
	return &v1.PackServiceInstallResponse{ReplacedVersion: "0.9.0", Pack: &v1.PackInfo{Id: r.Path, Version: "1.0.0", Hidden: map[bool][]string{true: {"replace"}}[r.ReplaceHidden]}}, nil
}

func (fakePack) List(context.Context, *v1.PackServiceListRequest) (*v1.PackServiceListResponse, error) {
	return &v1.PackServiceListResponse{Packs: []*v1.PackInfo{{Id: "oom/ios-xe", Version: "1.0.0", Official: true, PlaybookCount: 52, ScriptCount: 52,
		Name: "<b>IOS-XE</b>", Shadowed: []string{"ios-xe/x"}}}}, nil
}

func (fakePack) Show(_ context.Context, r *v1.PackServiceShowRequest) (*v1.PackServiceShowResponse, error) {
	return &v1.PackServiceShowResponse{Pack: &v1.PackInfo{Id: r.Id}, Readme: "# <script>x</script>\n"}, nil
}

func (fakePack) Remove(context.Context, *v1.PackServiceRemoveRequest) (*v1.PackServiceRemoveResponse, error) {
	return &v1.PackServiceRemoveResponse{FavoritesRemoved: 2}, nil
}

func (fakePack) SetItems(_ context.Context, r *v1.PackServiceSetItemsRequest) (*v1.PackServiceSetItemsResponse, error) {
	return &v1.PackServiceSetItemsResponse{Pack: &v1.PackInfo{Id: r.PackId, Hidden: r.Hide}}, nil
}

func (fakePack) Inspect(_ context.Context, r *v1.PackServiceInspectRequest) (*v1.PackServiceInspectResponse, error) {
	return &v1.PackServiceInspectResponse{Pack: &v1.PackInfo{Id: r.Path}, ReplacedVersion: "0.9.0"}, nil
}

func TestPackBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterPackServiceServer(r, fakePack{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	if _, err := b.PackInstall("/x.mpack", false); err == nil {
		t.Fatal("sin confirmación debe fallar")
	} else {
		var be *Error
		if !errors.As(err, &be) || be.Code != "FailedPrecondition" {
			t.Fatalf("el error debe pasar por wrapErr: %#v", err)
		}
	}
	ins, err := b.PackInstall("/x.mpack", true)
	if err != nil || ins.Pack.ID != "/x.mpack" || ins.ReplacedVersion != "0.9.0" {
		t.Fatalf("%+v %v", ins, err)
	}
	l2, err := b.PackList()
	if err != nil || len(l2) != 1 || !l2[0].Official || l2[0].PlaybookCount != 52 || l2[0].Shadowed[0] != "ios-xe/x" {
		t.Fatalf("%+v %v", l2, err)
	}
	// El texto del paquete llega tal cual, como texto plano: el puente no lo interpreta ni lo escapa.
	if l2[0].Name != "<b>IOS-XE</b>" {
		t.Fatalf("nombre = %q", l2[0].Name)
	}
	sh, err := b.PackShow("oom/ios-xe")
	if err != nil || !strings.Contains(sh.Readme, "<script>") || sh.PlaybookIDs == nil || sh.ScriptIDs == nil {
		t.Fatalf("%+v %v", sh, err)
	}
	if n, err := b.PackRemove("oom/ios-xe"); err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if p, err := b.PackSetItems("oom/ios-xe", []string{"ios-xe/x"}, nil); err != nil || p.ID != "oom/ios-xe" || len(p.Hidden) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := b.PackSetItems("oom/ios-xe", nil, []string{"ios-xe/x"}); err != nil || p.Hidden == nil {
		t.Fatalf("hidden nunca es null: %+v %v", p, err)
	}
	if ins, err := b.PackInstallHiding("/y.mpack", true, []string{"a"}, true); err != nil || ins.Pack.ID != "/y.mpack" || len(ins.Pack.Hidden) != 1 { // replace_hidden viaja
		t.Fatalf("%+v %v", ins, err)
	}
	if in, err := b.PackInspect("/z.mpack", true); err != nil || in.Pack.ID != "/z.mpack" || in.ReplacedVersion != "0.9.0" || in.PlaybookIDs == nil || in.ScriptIDs == nil {
		t.Fatalf("%+v %v", in, err)
	}
	j, _ := json.Marshal(PackInfoDTO{Platforms: strs(nil), Shadowed: strs(nil), Hidden: strs(nil)})
	if !strings.Contains(string(j), `"platforms":[]`) || !strings.Contains(string(j), `"shadowed":[]`) || !strings.Contains(string(j), `"hidden":[]`) {
		t.Fatalf("json = %s", j)
	}
}
