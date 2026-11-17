package core

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

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

// headerLen es el largo de la cabecera de un .mcvault (internal/vault/format.go) hasta el contador de entradas.
const headerLen = 111

func mismosNombres(a, b []string) bool {
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func mismoEstado(t *testing.T, h *harness, b0 string, n0 []string, ctxto string) {
	t.Helper()
	b, n := estadoBoveda(t, h)
	if b != b0 || !mismosNombres(n, n0) {
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
	prueba("n gigante", mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen-4:headerLen], 0xFFFFFFFF) }))
	prueba("l gigante", mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen+28:headerLen+32], 0xFFFFFFFF) }))
	prueba("cola", append(append([]byte(nil), raw...), 1, 2, 3))
}

// Un respaldo con una llave SSH que no parsea (testdata/llave-invalida.mcvault: «buena» con contraseña y «rota» con una llave
// truncada, armado antes de la validación) falla la vista previa ENTERA con la etiqueta culpable y no deja nada a medias.
func TestRespaldoHostilLlaveSSHInvalidaRechazaElImport(t *testing.T) {
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	b0, n0 := estadoBoveda(t, o)
	fix, _ := filepath.Abs(filepath.Join("testdata", "llave-invalida.mcvault"))
	_, err := o.preview(t, fix)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), `"rota"`) {
		t.Fatalf("preview: %v", err)
	}
	mismoEstado(t, o, b0, n0, "llave inválida")
}

// Una llave inválida tampoco entra por PutCredential (gRPC): no se importan llaves por ahí.
func TestPutCredentialSigueSinAceptarLlaves(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	_, err := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "k", Username: "u", SshPrivateKey: []byte("x")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

// Muchas entradas chicas: la vista previa las rechaza antes de descifrar (cada secreto pide páginas bloqueadas y memguard entraba en
// pánico con unas 700), sin dejar vista previa ni tocar la bóveda; y exportarlas no entra en pánico.
func TestRespaldoHostilMuchasEntradasChicasRechazaSinPanico(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	for i := 0; i < 700; i += 50 {
		var cs []vault.Credential
		for j := i; j < i+50; j++ {
			cs = append(cs, vault.Credential{Label: fmt.Sprintf("c%04d", j), Username: "u", Password: secret.New([]byte("p"))})
		}
		_, err := h.core.vault.PutBatch(cs)
		for _, c := range cs {
			c.Password.Destroy()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "r.mcvault")
	if r, err := h.export(t, path, true); err != nil || r.Count != 701 {
		t.Fatalf("export: %+v %v", r, err)
	}
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	b0, n0 := estadoBoveda(t, o)
	if _, err := o.preview(t, path); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("preview: %v", err)
	}
	mismoEstado(t, o, b0, n0, "demasiadas")
}

// Las vistas previas pendientes comparten un presupuesto de memoria bloqueada: al pedir más de lo que cabe, la más vieja cede.
func TestRespaldoStoreReservaCedeLasViejas(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil)
	now := time.Now()
	st := &h.core.respaldos
	if _, err := h.preview(t, path); err != nil {
		t.Fatal(err)
	}
	if n, _ := h.pendientes(); n != 1 {
		t.Fatalf("pendientes = %d", n)
	}
	st.reserve(respaldoBudget, now)
	defer st.release(respaldoBudget)
	if n, _ := h.pendientes(); n != 0 {
		t.Fatalf("la vista previa no cedió: %d", n)
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
	if b != b0 || !mismosNombres(n, n0) {
		t.Fatalf("la bóveda cambió: %v -> %v", n0, n)
	}
	if l := o.labels(t); len(l) != 0 {
		t.Fatalf("quedó a medias en memoria: %v", l)
	}
}
