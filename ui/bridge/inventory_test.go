package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeInventory struct {
	v1.UnimplementedInventoryServiceServer
	put *v1.PutDeviceRequest
	dec []*v1.ImportHostDecision
	exp *v1.ExportHostsRequest
	pre *v1.PreviewImportHostsRequest
	req *v1.ListDevicesRequest
}

func (f *fakeInventory) ListDevices(_ context.Context, r *v1.ListDevicesRequest) (*v1.ListDevicesResponse, error) {
	f.req = r
	if r.ManualOnly { // los hosts con sus valores, sin fusionar
		return &v1.ListDevicesResponse{Devices: []*v1.Device{{Id: "abc", Name: "CORE", Hostname: "CORE", Target: &v1.Target{Address: "10.0.0.5"}, Profile: &v1.DeviceProfile{Port: 2222},
			Folder: "Lab", Tags: []string{"core"}, CredentialId: "cid", CredentialLabel: "admin", Notes: "n"}}}, nil
	}
	return &v1.ListDevicesResponse{Warnings: []string{"q=" + r.Query}, Devices: []*v1.Device{
		{Id: "10.0.0.1", Hostname: "SW1", Platform: "ios-xe", LastSeenMs: 99, Sources: []string{"patrol", "flota"}, Target: &v1.Target{Address: "10.0.0.1"}},
		{Id: "nombre:SW9", Hostname: "SW9"},
		{Id: "abc", Name: "CORE", Hostname: "CORE", Platform: "nx-os", Sources: []string{"flota", "manual"}, Target: &v1.Target{Address: "10.0.0.5"}, Profile: &v1.DeviceProfile{Port: 2222},
			Folder: "Lab", Tags: []string{"core"}, CredentialId: "cid", CredentialLabel: "admin", Notes: "n"},
	}}, nil
}
func (f *fakeInventory) PutDevice(_ context.Context, r *v1.PutDeviceRequest) (*v1.PutDeviceResponse, error) {
	f.put = r
	return &v1.PutDeviceResponse{Id: "nuevo", Warnings: []string{"bóveda cerrada"}}, nil
}
func (f *fakeInventory) DeleteDevice(context.Context, *v1.DeleteDeviceRequest) (*v1.DeleteDeviceResponse, error) {
	return &v1.DeleteDeviceResponse{}, nil
}
func (f *fakeInventory) ExportHosts(_ context.Context, r *v1.ExportHostsRequest) (*v1.ExportHostsResponse, error) {
	f.exp = r
	return &v1.ExportHostsResponse{Count: 2, Warnings: []string{"w"}}, nil
}
func (f *fakeInventory) PreviewImportHosts(_ context.Context, r *v1.PreviewImportHostsRequest) (*v1.PreviewImportHostsResponse, error) {
	f.pre = r
	return &v1.PreviewImportHostsResponse{Token: "tok", ExpiresMs: 9, Warnings: []string{"aviso"}, Format: "csv",
		Errors: []*v1.ImportHostError{{Line: 14, Field: "address", Reason: "inválida"}}, Items: []*v1.ImportHostItem{
			{Host: &v1.Device{Name: "A", Target: &v1.Target{Address: "10.0.0.1"}, Profile: &v1.DeviceProfile{Port: 22}, CredentialLabel: "admin"}, Key: "10.0.0.1:22", State: "conflicto", Reason: "nombre", ConflictsWith: "x", CredentialMissing: true},
		}}, nil
}
func (f *fakeInventory) ApplyImportHosts(_ context.Context, r *v1.ApplyImportHostsRequest) (*v1.ApplyImportHostsResponse, error) {
	f.dec = r.Decisions
	return &v1.ApplyImportHostsResponse{Created: 1, Replaced: 2, Renamed: 3, Skipped: 4, Invalid: 5}, nil
}
func (f *fakeInventory) HostsImportTemplate(_ context.Context, r *v1.HostsImportTemplateRequest) (*v1.HostsImportTemplateResponse, error) {
	return &v1.HostsImportTemplateResponse{Format: r.Format, Filename: "hosts-plantilla." + r.Format, Content: "name,address\n"}, nil
}
func (f *fakeInventory) HostsImportFormat(context.Context, *v1.HostsImportFormatRequest) (*v1.HostsImportFormatResponse, error) {
	return &v1.HostsImportFormatResponse{MaxRows: 1000, MaxBytes: 5 << 20, Fields: []*v1.HostField{{Name: "name", Type: "texto", Required: true, Example: "SW", Description: "d"}}}, nil
}

func TestInventoryBridge(t *testing.T) {
	f := &fakeInventory{}
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterInventoryServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	r, err := b.ListDevices("sw")
	if err != nil || r.Warnings[0] != "q=sw" || len(r.Devices) != 3 {
		t.Fatalf("r = %+v err = %v", r, err)
	}
	if a := r.Devices[0]; a.Address != "10.0.0.1" || a.Hostname != "SW1" || a.LastSeenMs != 99 || len(a.Sources) != 2 {
		t.Fatalf("SW1 = %+v", a)
	}
	if s := r.Devices[1]; s.Address != "" || s.Sources == nil {
		t.Fatalf("SW9 = %+v (las listas van como [] y no como null)", s)
	}
	if m := r.Devices[2]; m.ID != "abc" || m.Name != "CORE" || m.Port != 2222 || m.Folder != "Lab" || len(m.Tags) != 1 || m.CredentialID != "cid" || m.CredentialLabel != "admin" || m.Notes != "n" {
		t.Fatalf("manual = %+v", m)
	}
	if a := r.Devices[0]; a.Tags == nil || a.Port != 0 {
		t.Fatalf("SW1 = %+v (las etiquetas van como [])", a)
	}

	// la libreta: solo los hosts manuales, con filtros
	hs, err := b.ListHosts("co", "Lab", "core")
	if err != nil || len(hs) != 1 || hs[0].ID != "abc" || hs[0].Address != "10.0.0.5" || hs[0].Port != 2222 || hs[0].Tags[0] != "core" || hs[0].Platform != "" || !f.req.ManualOnly || f.req.Folder != "Lab" || f.req.Tag != "core" || f.req.Query != "co" {
		t.Fatalf("hosts = %+v req = %+v err = %v", hs, f.req, err)
	}
	res, err := b.SaveHost(HostDTO{Name: "N", Address: "10.0.0.9", Port: 22, Platform: "ios", Folder: "F", Tags: []string{"t"}, CredentialID: "cid", CredentialLabel: "ignorada", Notes: "x"})
	p := f.put.Device
	if err != nil || res.ID != "nuevo" || len(res.Warnings) != 1 || p.Name != "N" || p.Target.Address != "10.0.0.9" || p.Profile.Port != 22 || p.CredentialId != "cid" || p.CredentialLabel != "" || p.Tags[0] != "t" {
		t.Fatalf("save = %+v put = %+v err = %v (la etiqueta es de solo lectura)", res, p, err)
	}
	if err := b.DeleteHost("abc"); err != nil {
		t.Fatal(err)
	}
	ex, err := b.ExportHosts([]string{"a"}, "/tmp/h.json", true, "csv")
	if err != nil || ex.Count != 2 || len(ex.Warnings) != 1 || !f.exp.Overwrite || f.exp.Ids[0] != "a" || f.exp.Format != "csv" || f.exp.Path != "/tmp/h.json" {
		t.Fatalf("export = %+v err = %v", ex, err)
	}
	pv, err := b.PreviewHostsImport("/tmp/h.json", "csv")
	if err != nil || pv.Token != "tok" || pv.ExpiresMs != 9 || pv.Format != "csv" || f.pre.Format != "csv" || len(pv.Errors) != 1 || pv.Errors[0] != (HostImportErrorDTO{Line: 14, Field: "address", Reason: "inválida"}) || len(pv.Warnings) != 1 || len(pv.Items) != 1 {
		t.Fatalf("preview = %+v err = %v", pv, err)
	}
	if it := pv.Items[0]; it.Key != "10.0.0.1:22" || it.State != "conflicto" || it.Reason != "nombre" || it.ConflictsWith != "x" || !it.CredentialMissing || it.Host.Name != "A" || it.Host.CredentialLabel != "admin" || it.Host.Tags == nil {
		t.Fatalf("item = %+v", it)
	}
	ap, err := b.ApplyHostsImport("tok", []HostDecisionDTO{{Key: "10.0.0.1:22", Action: "omitir"}})
	if err != nil || ap != (HostsImportResultDTO{1, 2, 3, 4, 5}) || len(f.dec) != 1 || f.dec[0].Key != "10.0.0.1:22" || f.dec[0].Action != "omitir" {
		t.Fatalf("apply = %+v dec = %v err = %v", ap, f.dec, err)
	}
	tp, err := b.HostsImportTemplate("json")
	if err != nil || tp.Format != "json" || tp.Filename != "hosts-plantilla.json" || tp.Content == "" {
		t.Fatalf("plantilla = %+v err = %v", tp, err)
	}
	ff, err := b.HostsImportFormat()
	if err != nil || ff.MaxRows != 1000 || ff.MaxBytes != 5<<20 || len(ff.Fields) != 1 || ff.Fields[0] != (HostFieldDTO{Name: "name", Type: "texto", Required: true, Example: "SW", Description: "d"}) {
		t.Fatalf("formato = %+v err = %v", ff, err)
	}
}
