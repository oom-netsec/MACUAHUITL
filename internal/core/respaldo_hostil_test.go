package core

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// estadoBoveda es la bóveda viva byte a byte y lo que hay en su carpeta: nada a medias, ningún temporal.
func estadoBoveda(t *testing.T, h *harness) (string, []string) {
	t.Helper()
	b, err := os.ReadFile(h.core.vaultPath())
	if err != nil {
		t.Fatal(err)
	}
	es, _ := os.ReadDir(filepath.Dir(h.core.vaultPath()))
	var nombres []string
	for _, e := range es {
		nombres = append(nombres, e.Name())
	}
	return string(b), nombres
}

func mismoEstado(t *testing.T, h *harness, b0 string, n0 []string, ctxto string) {
	t.Helper()
	b, n := estadoBoveda(t, h)
	if b != b0 || len(n) != len(n0) {
		t.Fatalf("%s: la bóveda cambió (archivos %v -> %v)", ctxto, n0, n)
	}
	if p, _ := h.pendientes(); p != 0 {
		t.Fatalf("%s: quedó una vista previa", ctxto)
	}
}

func TestRespaldoHostilNoTocaLaBoveda(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b0, n0 := estadoBoveda(t, h)
	hostil := filepath.Join(t.TempDir(), "h.mcvault")
	prueba := func(nombre string, b []byte) {
		t.Helper()
		if err := os.WriteFile(hostil, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := h.preview(t, hostil)
		if c := status.Code(err); c != codes.InvalidArgument {
			t.Fatalf("%s: %v", nombre, err)
		}
		mismoEstado(t, h, b0, n0, nombre)
	}
	for n := 0; n < len(raw); n++ {
		prueba("truncado", raw[:n])
	}
	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), raw...)
		f(b)
		return b
	}
	prueba("versión", mut(func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 2) }))
	prueba("n gigante", mut(func(b []byte) { binary.BigEndian.PutUint32(b[107:111], 0xFFFFFFFF) }))
	prueba("l gigante", mut(func(b []byte) { binary.BigEndian.PutUint32(b[139:143], 0xFFFFFFFF) }))
	prueba("cola", append(append([]byte(nil), raw...), 1, 2, 3))
}

// Una llave SSH inválida dentro del respaldo no se valida ni al exportar ni al importar (solo transport/ssh.go:69 la parsea al
// conectar): entra tal cual y la importación sigue siendo todo o nada. Documenta el estado actual.
func TestRespaldoHostilLlaveSSHInvalidaEntraSinValidar(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	mala := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncada")
	if _, err := h.core.vault.Put(vault.Credential{Label: "k", Username: "u", SSHKey: secret.New(append([]byte(nil), mala...))}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "r.mcvault")
	if r, err := h.export(t, path, true); err != nil || r.Count != 2 {
		t.Fatalf("export: %+v %v", r, err)
	}
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if ap, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token}); err != nil || ap.Created != 2 {
		t.Fatalf("apply: %+v %v", ap, err)
	}
}

// Si la escritura falla al aplicar, la bóveda queda igual byte a byte y sin temporales.
func TestRespaldoHostilEscrituraFallidaDejaLaBovedaIgual(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("necesita quitar el permiso de escritura a la carpeta")
	}
	_, path := bovedaConRespaldo(t, nil)
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	b0, n0 := estadoBoveda(t, o)
	dir := filepath.Dir(o.core.vaultPath())
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token}); err == nil {
		t.Fatal("debía fallar")
	}
	os.Chmod(dir, 0o700)
	b, n := estadoBoveda(t, o)
	if b != b0 || len(n) != len(n0) {
		t.Fatalf("la bóveda cambió: %v -> %v", n0, n)
	}
	if l := o.labels(t); len(l) != 0 {
		t.Fatalf("quedó a medias en memoria: %v", l)
	}
}
