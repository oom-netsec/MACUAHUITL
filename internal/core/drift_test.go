package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// driftDir arma una carpeta de Patrol: SW1 deriva entre r1 y r2, SW2 no, SW3 solo tiene r2.
func driftDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	read := func(n string) string {
		b, err := os.ReadFile("../drift/testdata/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	put := func(dev string, round int, name, cfg string) {
		d := filepath.Join(dir, dev)
		os.MkdirAll(d, 0o755)
		hdr := "===== 2026-11-06T10:00:00Z · show version =====\nCisco IOS XE\n===== 2026-11-06T10:00:01Z · show running-config =====\n"
		os.WriteFile(filepath.Join(d, name), []byte(hdr+cfg), 0o600)
	}
	put("SW1_192.0.2.1", 1, "r001_20261106-100000.txt", read("ronda1.txt"))
	put("SW1_192.0.2.1", 2, "r002_20261106-110000.txt", read("ronda2.txt"))
	put("SW2_192.0.2.2", 1, "r001_20261106-100000.txt", "hostname SW2\n")
	put("SW2_192.0.2.2", 2, "r002_20261106-110000.txt", "hostname SW2\n")
	put("SW3_192.0.2.3", 2, "r002_20261106-110000.txt", "hostname SW3\n")
	return dir
}

func TestDriftEntreRondas(t *testing.T) {
	h := newHarness(t, nil)
	dc := v1.NewDriftServiceClient(h.conn)
	dir := driftDir(t)
	r, err := dc.Drift(ctx(t), &v1.DriftRequest{Job: dir})
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Devices []struct {
			Device         string
			From, To       int
			Added, Removed int
		}
		Warnings []string
	}
	if err := json.Unmarshal([]byte(r.Report.Json), &rep); err != nil || len(rep.Devices) != 2 {
		t.Fatalf("json %v: %s", err, r.Report.Json)
	}
	if d := rep.Devices[0]; d.Device != "SW1_192.0.2.1" || d.From != 1 || d.To != 2 || d.Added != 5 || d.Removed != 3 {
		t.Errorf("SW1 = %+v", d)
	}
	if d := rep.Devices[1]; d.Added+d.Removed != 0 {
		t.Errorf("SW2 sin deriva = %+v", d)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "SW3") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
	if !strings.Contains(r.Report.Text, "+ description PC-01-NUEVA") || !strings.Contains(r.Report.Text, "1 de 2 equipos con deriva") {
		t.Errorf("texto: %s", r.Report.Text)
	}
	if !strings.Contains(h.auditText(t), `"action":"drift.run"`) {
		t.Error("no quedó en la bitácora")
	}
	// Una ronda concreta y un filtro de equipo.
	if r, err = dc.Drift(ctx(t), &v1.DriftRequest{Job: dir, Round: 2, Device: "sw2"}); err != nil || strings.Contains(r.Report.Text, "SW1") {
		t.Fatalf("filtro: %v %s", err, r.GetReport().GetText())
	}
}

func TestDriftRechazaEntradaMala(t *testing.T) {
	h := newHarness(t, nil)
	dc := v1.NewDriftServiceClient(h.conn)
	if _, err := dc.Drift(ctx(t), &v1.DriftRequest{Job: "no-existe"}); status.Code(err) != codes.NotFound {
		t.Errorf("trabajo desconocido: %v", err)
	}
	if _, err := dc.Drift(ctx(t), &v1.DriftRequest{Job: t.TempDir()}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("carpeta vacía: %v", err)
	}
	if _, err := dc.Drift(ctx(t), &v1.DriftRequest{Job: driftDir(t), Round: 1}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("la ronda 1 no tiene anterior: %v", err)
	}
}

// El manifest dice que Patrol enmascaró secretos: un cambio de enable secret no se vería, y el informe lo avisa.
// Los avisos del paquete (aquí, un zip dañado) pasan al informe.
func TestDriftAvisaDeSecretosEnmascaradosYAvisosDelPaquete(t *testing.T) {
	h := newHarness(t, nil)
	dc := v1.NewDriftServiceClient(h.conn)
	dir := driftDir(t)
	r, err := dc.Drift(ctx(t), &v1.DriftRequest{Job: dir})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Report.Text, "secretos") || strings.Contains(r.Report.Json, `"masked":true`) {
		t.Errorf("sin manifest no hay aviso: %s", r.Report.Text)
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"masked":true}`), 0o600)
	os.WriteFile(filepath.Join(dir, "dañado.zip"), []byte("no es un zip"), 0o600)
	r, err = dc.Drift(ctx(t), &v1.DriftRequest{Job: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Report.Text, "los cambios en secretos no son visibles porque el trabajo enmascara secretos") || !strings.Contains(r.Report.Json, `"masked":true`) {
		t.Errorf("sin aviso de enmascarado: %s", r.Report.Text)
	}
	if !strings.Contains(r.Report.Text, "dañado.zip") {
		t.Errorf("sin los avisos del paquete: %s", r.Report.Text)
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"masked":false}`), 0o600)
	if r, _ = dc.Drift(ctx(t), &v1.DriftRequest{Job: dir}); strings.Contains(r.Report.Text, "enmascara") {
		t.Errorf("enmascarado apagado no avisa: %s", r.Report.Text)
	}
}
