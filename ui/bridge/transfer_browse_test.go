package bridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

type fakeBrowse struct {
	v1.UnimplementedTransferServiceServer
	block chan struct{} // GetMany espera aquí tras el primer archivo hasta que lo cancelen
}

func (fakeBrowse) Browse(ctx context.Context, r *v1.BrowseRequest) (*v1.BrowseResponse, error) {
	if strings.HasPrefix(r.Url, "tftp://coded") {
		return nil, service.Err(ctx, codes.Unimplemented, "xfer.no_listing.tftp", i18n.A("proto", "tftp"))
	}
	if strings.HasPrefix(r.Url, "tftp://") {
		return nil, status.Error(codes.Unimplemented, "este servidor no permite listar: TFTP no tiene comando para listar carpetas")
	}
	if strings.HasPrefix(r.Url, "ftp://roto") {
		return nil, status.Error(codes.Unavailable, "sin conexión")
	}
	return &v1.BrowseResponse{Path: r.Path, Method: "mlsd", Truncated: true, Entries: []*v1.RemoteEntry{
		{Name: "backups", Type: "dir", Size: -1, ModifiedMs: 5},
		{Name: "r1.cfg", Type: "file", Size: 12, Perms: "rw-r--r--", Downloadable: true},
	}}, nil
}

func (fakeBrowse) GetStream(r *v1.GetStreamRequest, st v1.TransferService_GetStreamServer) error {
	if strings.Contains(r.Request.Url, "falla") {
		return status.Error(codes.Unavailable, "se cayó")
	}
	st.Send(&v1.GetStreamResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_Progress{Progress: &v1.TransferProgress{Count: 1, Name: "a.bin", Bytes: 50, Total: 100, BytesPerSec: 1000}}}})
	st.Send(&v1.GetStreamResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_File{File: &v1.FileResult{Name: "a.bin", Ok: true, Result: &v1.TransferResult{Path: "/d/a.bin", Bytes: 100}}}}})
	return nil
}

func (fakeBrowse) PutStream(r *v1.PutStreamRequest, st v1.TransferService_PutStreamServer) error {
	st.Send(&v1.PutStreamResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_File{File: &v1.FileResult{Name: r.Request.Name, Ok: true, Result: &v1.TransferResult{Bytes: 7}}}}})
	return nil
}

func (f fakeBrowse) GetMany(r *v1.GetManyRequest, st v1.TransferService_GetManyServer) error {
	st.Send(&v1.GetManyResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_File{File: &v1.FileResult{Index: 0, Name: r.Names[0], Ok: true, Result: &v1.TransferResult{Bytes: 1}}}}})
	if f.block != nil {
		<-st.Context().Done() // espera la cancelación
		return status.FromContextError(st.Context().Err()).Err()
	}
	st.Send(&v1.GetManyResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_File{File: &v1.FileResult{Index: 1, Name: r.Names[1], Error: "no existe"}}}})
	st.Send(&v1.GetManyResponse{Event: &v1.TransferEvent{Event: &v1.TransferEvent_Done{Done: &v1.BatchSummary{Ok: 1, Failed: 1}}}})
	return nil
}

func newBrowseBridge(t *testing.T, f fakeBrowse) (*Bridge, *recorder) {
	t.Helper()
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterTransferServiceServer(r, f) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	return b, rec
}

func TestTransferBrowseBridge(t *testing.T) {
	b, _ := newBrowseBridge(t, fakeBrowse{})
	l, err := b.TransferBrowse(TransferBrowseDTO{URL: "ftp://10.0.0.1/", Path: "/pub"})
	if err != nil || !l.Listable || l.Path != "/pub" || len(l.Entries) != 2 || l.Entries[0].Type != "dir" || l.Entries[1].Size != 12 || !l.Entries[1].Downloadable || !l.Truncated || l.Method != "mlsd" {
		t.Fatalf("l = %+v err = %v", l, err)
	}
	// TFTP: no es una falla, es «no lista», con el motivo para mostrarlo
	l, err = b.TransferBrowse(TransferBrowseDTO{URL: "tftp://10.0.0.1/"})
	if err != nil || l.Listable || !strings.Contains(l.Reason, "este servidor no permite listar") || l.Entries == nil {
		t.Fatalf("tftp: %+v %v", l, err)
	}
	// con código del catálogo, el puente pasa el código y su metadata
	l, err = b.TransferBrowse(TransferBrowseDTO{URL: "tftp://coded/"})
	if err != nil || l.Listable || l.ReasonCode != "xfer.no_listing.tftp" || l.ReasonArgs["proto"] != "tftp" {
		t.Fatalf("con código: %+v %v", l, err)
	}
	// un error de verdad sí es error
	if _, err = b.TransferBrowse(TransferBrowseDTO{URL: "ftp://roto/"}); err == nil {
		t.Fatal("la falla de conexión debe llegar como error")
	}
}

func TestTransferAsyncBridge(t *testing.T) {
	b, rec := newBrowseBridge(t, fakeBrowse{})
	id, err := b.TransferGetAsync(TransferGetDTO{URL: "ftp://10.0.0.1/a.bin"})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `transfer:progress {"bytes":50,"bytesPerSec":1000,"count":1,"index":0,"name":"a.bin","runId":"`+id+`","total":100}`)
	rec.waitFor(t, `transfer:file {"index":0,"name":"a.bin","ok":true,"result":{"path":"/d/a.bin","bytes":100,"md5":"","sha256":"","verified":"","seconds":0,"report":""},"runId":"`+id+`"}`)
	rec.waitFor(t, `transfer:finished {"runId":"`+id+`"}`)
	id, _ = b.TransferGetAsync(TransferGetDTO{URL: "ftp://10.0.0.1/falla"})
	rec.waitFor(t, `transfer:finished {"error":"rpc error: code = Unavailable desc = se cayó","errorInfo":{"code":"Unavailable","metadata":{},"reason":""},"runId":"`+id+`"}`)
	id, _ = b.TransferPutAsync(TransferPutDTO{URL: "ftp://10.0.0.1/x", FromDir: "/f", Name: "r1.cfg"})
	rec.waitFor(t, `transfer:finished {"runId":"`+id+`"}`)
}

func TestTransferGetManyBridge(t *testing.T) {
	b, rec := newBrowseBridge(t, fakeBrowse{})
	id, err := b.TransferGetMany(TransferGetManyDTO{URL: "ftp://10.0.0.1/", Names: []string{"a.cfg", "b.cfg"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `transfer:file {"error":"no existe","index":1,"name":"b.cfg","ok":false,"runId":"`+id+`"}`)
	rec.waitFor(t, `transfer:finished {"failed":1,"ok":1,"runId":"`+id+`"}`)
}

func TestTransferCancelBridge(t *testing.T) {
	b, rec := newBrowseBridge(t, fakeBrowse{block: make(chan struct{})})
	id, err := b.TransferGetMany(TransferGetManyDTO{URL: "ftp://10.0.0.1/", Names: []string{"a.cfg", "b.cfg"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `transfer:file {"index":0,"name":"a.cfg","ok":true,"result":{"path":"","bytes":1,"md5":"","sha256":"","verified":"","seconds":0,"report":""},"runId":"`+id+`"}`)
	if err := b.TransferCancel(id); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `transfer:finished {"canceled":true,"runId":"`+id+`"}`)
	if err := b.TransferCancel(id); err == nil {
		t.Fatal("cancelar dos veces debe avisar que ya terminó")
	}
}
