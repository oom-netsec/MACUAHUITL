package core

import (
	"os"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
)

// El sha256 es obligatorio en Install y en Import con confirm, y se compara con el archivo leído.
func TestPackInstallExigeSha256(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	path := writeMpack(t, packtest.IOSXE(t))
	pv, err := pk.Inspect(ctx(t), &v1.PackServiceInspectRequest{Path: path})
	if err != nil || len(pv.Sha256) != 64 {
		t.Fatalf("inspect no da el sha256: %+v %v", pv, err)
	}
	_, err = pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: path})
	if r, _ := reasonOf(err); r != "pack.err.install.sha256_missing" {
		t.Fatalf("sin sha256: %v", err)
	}
	_, err = pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: path, Sha256: strings.Repeat("0", 64)})
	if r, _ := reasonOf(err); r != "pack.err.install.changed" {
		t.Fatalf("otro sha256: %v", err)
	}
	if l, err := pk.List(ctx(t), &v1.PackServiceListRequest{}); err != nil || len(l.Packs) != 0 {
		t.Fatalf("instaló sin sha256 válido: %v %v", l, err)
	}
	if _, err := pk.Install(ctx(t), &v1.PackServiceInstallRequest{Path: path, Sha256: strings.ToUpper(pv.Sha256)}); err != nil {
		t.Fatal(err)
	}
}

func TestPackImportConfirmExigeSha256(t *testing.T) {
	h := newHarness(t, nil)
	pk := v1.NewPackServiceClient(h.conn)
	path := hostile(t, func(map[string][]byte) {})
	_, err := pk.Import(ctx(t), &v1.PackServiceImportRequest{Path: path, Confirm: true})
	if r, _ := reasonOf(err); r != "pack.err.import.sha256_missing" {
		t.Fatalf("%v", err)
	}
	if es, _ := os.ReadDir(h.p.Config + "/playbooks"); len(es) != 0 {
		t.Fatal("aplicó sin suma")
	}
}

// withSum pone en la solicitud el sha256 del archivo de Path, como lo haría la vista previa; sin archivo la deja igual.
func withSum(t *testing.T, r *v1.PackServiceInstallRequest) *v1.PackServiceInstallRequest {
	t.Helper()
	if b, err := os.ReadFile(r.Path); err == nil {
		r.Sha256 = pack.SHA256(b)
	}
	return r
}

func withImportSum(t *testing.T, r *v1.PackServiceImportRequest) *v1.PackServiceImportRequest {
	t.Helper()
	if b, err := os.ReadFile(r.Path); err == nil {
		r.Sha256 = pack.SHA256(b)
	}
	return r
}
