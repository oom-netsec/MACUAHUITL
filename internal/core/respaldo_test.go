package core

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

const fraseResp = "frase-del-respaldo-XYZ"

// reloj es un reloj de prueba que solo avanza cuando se le pide.
type reloj struct{ ns atomic.Int64 }

func newReloj() *reloj {
	r := &reloj{}
	r.ns.Store(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).UnixNano())
	return r
}
func (r *reloj) now() time.Time         { return time.Unix(0, r.ns.Load()).UTC() }
func (r *reloj) avanza(d time.Duration) { r.ns.Add(int64(d)) }

func (h *harness) put(t *testing.T, label, user, pass string) {
	t.Helper()
	if _, err := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: label, Username: user, Password: []byte(pass), EnableSecret: []byte("EN-" + pass)}); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) export(t *testing.T, path string, confirm bool) (*v1.ExportBackupResponse, error) {
	t.Helper()
	return h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: path, Passphrase: []byte(fraseResp), Confirm: confirm})
}

// bovedaConRespaldo deja una bóveda viva con 3 credenciales, una entrada reservada y un respaldo exportado.
func bovedaConRespaldo(t *testing.T, mut func(*Options)) (*harness, string) {
	t.Helper()
	h := newHarness(t, mut)
	h.ready(t) // "lab" / MARKER-PW
	h.put(t, "core", "USR-CORE", "PW-CORE")
	h.put(t, "borde", "USR-BORDE", "PW-BORDE")
	if _, err := service.BackupKey(h.core.vault, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "r.mcvault")
	r, err := h.export(t, path, true)
	if err != nil || r.Count != 3 {
		t.Fatalf("export: %+v %v", r, err)
	}
	return h, path
}

func (h *harness) preview(t *testing.T, path string) (*v1.PreviewBackupImportResponse, error) {
	t.Helper()
	return h.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: path, Passphrase: []byte(fraseResp)})
}

func estados(r *v1.PreviewBackupImportResponse) map[string]string {
	m := map[string]string{}
	for _, i := range r.Items {
		m[i.Label] = i.State
	}
	return m
}

func (h *harness) labels(t *testing.T) map[string]string { // etiqueta -> contraseña
	t.Helper()
	out := map[string]string{}
	infos, err := h.core.vault.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range infos {
		c, err := h.core.vault.Get(i.ID)
		if err != nil {
			t.Fatal(err)
		}
		out[i.Label] = string(c.Password.Bytes())
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
	}
	return out
}

func (h *harness) pendientes() (n int, destruidos int) {
	h.core.respaldos.mu.Lock()
	defer h.core.respaldos.mu.Unlock()
	for _, p := range h.core.respaldos.pend {
		n++
		for _, c := range p.creds {
			if c.Password.Empty() && c.Enable.Empty() {
				destruidos++
			}
		}
	}
	return
}

func itemID(t *testing.T, r *v1.PreviewBackupImportResponse, label string) string {
	t.Helper()
	for _, i := range r.Items {
		if i.Label == label {
			return i.Id
		}
	}
	t.Fatalf("sin item %q", label)
	return ""
}

func sinSecretos(t *testing.T, texto string, prohibidos ...string) {
	t.Helper()
	for _, p := range prohibidos {
		if strings.Contains(texto, p) {
			t.Fatalf("aparece %q en:\n%s", p, texto)
		}
	}
}

func TestRespaldoIdaYVuelta(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("archivo: %v %v", fi, err)
	}
	// Bóveda vacía distinta: importa las 3.
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	pr, err := o.preview(t, path)
	if err != nil || len(pr.Items) != 3 {
		t.Fatalf("preview: %+v %v", pr, err)
	}
	for _, i := range pr.Items {
		if i.State != "nueva" || i.Username == "" || i.Id == "" {
			t.Fatalf("item %+v", i)
		}
	}
	ap, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token})
	if err != nil || ap.Created != 3 || ap.Replaced+ap.Renamed+ap.Skipped+ap.Same != 0 {
		t.Fatalf("apply: %+v %v", ap, err)
	}
	got := o.labels(t)
	if len(got) != 3 || got["lab"] != "MARKER-PW" || got["core"] != "PW-CORE" || got["borde"] != "PW-BORDE" {
		t.Fatalf("labels = %v", got)
	}
	// De nuevo: las 3 ya son iguales.
	pr2, _ := o.preview(t, path)
	for l, s := range estados(pr2) {
		if s != "igual" {
			t.Fatalf("%s = %s", l, s)
		}
	}
	ap2, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr2.Token})
	if err != nil || ap2.Same != 3 || ap2.Created != 0 {
		t.Fatalf("apply2: %+v %v", ap2, err)
	}
	if len(o.labels(t)) != 3 {
		t.Fatal("duplicó credenciales iguales")
	}
	// Auditoría sin secretos, usuarios ni frase; con acciones, ruta y conteos.
	for _, hh := range []*harness{h, o} {
		a := hh.auditText(t)
		sinSecretos(t, a, "MARKER", "PW-CORE", "PW-BORDE", "EN-", "USR-", fraseResp, "otra-maestra", "HMAC")
	}
	if a := h.auditText(t); !strings.Contains(a, `"action":"vault.respaldo.exportar"`) || !strings.Contains(a, path) || !strings.Contains(a, "3 credentials") {
		t.Fatalf("audit export:\n%s", a)
	}
	if a := o.auditText(t); !strings.Contains(a, `"action":"vault.respaldo.importar"`) || !strings.Contains(a, "3 new") {
		t.Fatalf("audit import:\n%s", a)
	}
}

func TestRespaldoExportRechazos(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	dir := t.TempDir()
	ruta := filepath.Join(dir, "r.mcvault")
	exp := func(path, frase string, confirm bool) error {
		_, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: path, Passphrase: []byte(frase), Confirm: confirm})
		return err
	}
	for name, tc := range map[string]struct {
		err  error
		want codes.Code
	}{
		"sin confirmar": {exp(ruta, fraseResp, false), codes.FailedPrecondition},
		"corta":         {exp(ruta, "corta", true), codes.InvalidArgument},
		"igual maestra": {exp(ruta, "maestra", true), codes.InvalidArgument},
		"relativa":      {exp("r.mcvault", fraseResp, true), codes.InvalidArgument},
	} {
		if status.Code(tc.err) != tc.want {
			t.Fatalf("%s: %v", name, tc.err)
		}
		if tc.err != nil {
			sinSecretos(t, tc.err.Error(), fraseResp)
		}
	}
	if err := exp(ruta, fraseResp, false); !strings.Contains(err.Error(), "todas tus credenciales") {
		t.Fatalf("mensaje de confirmación: %v", err)
	}
	if _, err := os.Stat(ruta); err == nil {
		t.Fatal("creó el archivo sin que valiera la petición")
	}
	// Igual a la maestra con 12 o más caracteres: se compara con la bóveda viva sin cerrarla.
	h2 := newHarness(t, nil)
	h2.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("maestra-larga-123")})
	if _, err := h2.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: ruta, Passphrase: []byte("maestra-larga-123"), Confirm: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("misma frase: %v", err)
	}
	if h2.core.vault.Unlocked() == false {
		t.Fatal("comparar cambió el estado de la bóveda")
	}
	// Existente sin overwrite; con overwrite sí.
	if err := exp(ruta, fraseResp, true); err != nil {
		t.Fatal(err)
	}
	if err := exp(ruta, fraseResp, true); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("existente: %v", err)
	}
	if _, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: ruta, Passphrase: []byte(fraseResp), Confirm: true, Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	// Cerrada.
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	if err := exp(filepath.Join(dir, "otro"), fraseResp, true); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("cerrada: %v", err)
	}
}

func TestRespaldoPreviewErrores(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil)
	ajeno := filepath.Join(t.TempDir(), "x.mcvault")
	os.WriteFile(ajeno, []byte(strings.Repeat("no soy un respaldo ", 20)), 0o600)
	_, err := h.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: ajeno, Passphrase: []byte(fraseResp)})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "no es un respaldo de bóveda de MACUAHUITL") {
		t.Fatalf("ajeno: %v", err)
	}
	_, err = h.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: path, Passphrase: []byte("incorrecta-incorrecta")})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "frase del respaldo") {
		t.Fatalf("frase: %v", err)
	}
	sinSecretos(t, err.Error(), "incorrecta-incorrecta")
	// La frase maestra no abre el respaldo.
	if _, err = h.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: path, Passphrase: []byte("maestra")}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("maestra: %v", err)
	}
	if _, err = h.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: "relativa", Passphrase: []byte(fraseResp)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("relativa: %v", err)
	}
	if _, err = h.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: filepath.Join(t.TempDir(), "no"), Passphrase: []byte(fraseResp)}); status.Code(err) != codes.NotFound {
		t.Fatalf("inexistente: %v", err)
	}
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	if _, err = h.preview(t, path); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("cerrada: %v", err)
	}
	if n, _ := h.pendientes(); n != 0 {
		t.Fatal("quedó una vista previa")
	}
}

func TestRespaldoEstadosYDecisiones(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil)
	// Bóveda destino: "lab" igual, "core" con otra contraseña, "borde" no existe.
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	if _, err := o.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "lab", Username: "admin", Password: []byte("MARKER-PW"), EnableSecret: []byte("MARKER-EN")}); err != nil {
		t.Fatal(err)
	}
	o.put(t, "core", "USR-CORE", "OTRA")
	_ = h
	apply := func(tok string, dec ...*v1.VaultBackupDecision) (*v1.ApplyBackupImportResponse, error) {
		return o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: tok, Decisions: dec})
	}
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if e := estados(pr); e["lab"] != "igual" || e["core"] != "conflicto_etiqueta" || e["borde"] != "nueva" || len(e) != 3 {
		t.Fatalf("estados = %v", e)
	}
	core := itemID(t, pr, "core")
	// Conflicto sin decisión, acción desconocida, id desconocido y repetida: el token se conserva.
	for name, dec := range map[string][]*v1.VaultBackupDecision{
		"sin decisión": nil,
		"acción mala":  {{Id: core, Action: "fusionar"}},
		"id ajeno":     {{Id: core, Action: "omitir"}, {Id: "zz", Action: "omitir"}},
		"repetida":     {{Id: core, Action: "omitir"}, {Id: core, Action: "omitir"}},
	} {
		if _, err := apply(pr.Token, dec...); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: %v", name, err)
		}
		if got := o.labels(t); len(got) != 2 {
			t.Fatalf("%s: aplicó algo: %v", name, got)
		}
	}
	// Renombrar.
	ap, err := apply(pr.Token, &v1.VaultBackupDecision{Id: core, Action: "renombrar"})
	if err != nil || ap.Created != 1 || ap.Renamed != 1 || ap.Same != 1 || ap.Replaced != 0 {
		t.Fatalf("renombrar: %+v %v", ap, err)
	}
	if got := o.labels(t); len(got) != 4 || got["core"] != "OTRA" || got["core (importada)"] != "PW-CORE" || got["borde"] != "PW-BORDE" {
		t.Fatalf("labels = %v", got)
	}
	// Renombrar otra vez: la etiqueta ya existe y se numera.
	pr, _ = o.preview(t, path)
	if _, err := apply(pr.Token, &v1.VaultBackupDecision{Id: itemID(t, pr, "core"), Action: "renombrar"}); err != nil {
		t.Fatal(err)
	}
	if got := o.labels(t); len(got) != 5 || got["core (importada 2)"] != "PW-CORE" {
		t.Fatalf("labels = %v", got)
	}
	// Omitir.
	pr, _ = o.preview(t, path)
	ap, err = apply(pr.Token, &v1.VaultBackupDecision{Id: itemID(t, pr, "core"), Action: "omitir"})
	if err != nil || ap.Skipped != 1 || ap.Created != 0 || len(o.labels(t)) != 5 {
		t.Fatalf("omitir: %+v %v", ap, err)
	}
	// Reemplazar.
	pr, _ = o.preview(t, path)
	ap, err = apply(pr.Token, &v1.VaultBackupDecision{Id: itemID(t, pr, "core"), Action: "reemplazar"})
	if err != nil || ap.Replaced != 1 || ap.Created != 0 {
		t.Fatalf("reemplazar: %+v %v", ap, err)
	}
	if got := o.labels(t); len(got) != 5 || got["core"] != "PW-CORE" {
		t.Fatalf("labels = %v", got)
	}
	a := o.auditText(t)
	sinSecretos(t, a, "PW-CORE", "OTRA", "USR-", fraseResp, "EN-")
	if !strings.Contains(a, "=replace") || !strings.Contains(a, "=rename") {
		t.Fatalf("la auditoría no trae las decisiones:\n%s", a)
	}
}

func TestRespaldoReservadaSeOmite(t *testing.T) {
	_, path := bovedaConRespaldo(t, nil)
	// Un archivo de bóveda con una entrada reservada: se ve como «reservada» y no se importa.
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	res := filepath.Join(t.TempDir(), "viva.mcv")
	copyReservada(t, res)
	pr, err := o.vault.PreviewBackupImport(ctx(t), &v1.PreviewBackupImportRequest{Path: res, Passphrase: []byte("maestra-de-prueba")})
	if err != nil {
		t.Fatal(err)
	}
	if e := estados(pr); e["macuahuitl:llave-de-respaldos"] != "reservada" || e["x"] != "nueva" || len(e) != 2 {
		t.Fatalf("estados = %v", e)
	}
	ap, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token})
	if err != nil || ap.Created != 1 || ap.Skipped != 1 {
		t.Fatalf("apply: %+v %v", ap, err)
	}
	if got := o.labels(t); len(got) != 1 || got["x"] != "p" {
		t.Fatalf("labels = %v", got)
	}
	_ = path
}

func TestRespaldoTokenUnSoloUsoYVence(t *testing.T) {
	clk := newReloj()
	_, path := bovedaConRespaldo(t, nil)
	o := newHarness(t, func(o *Options) { o.Now = clk.now; o.IdleLock = 24 * time.Hour })
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	apply := func(tok string) error {
		_, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: tok})
		return err
	}
	pr, _ := o.preview(t, path)
	if pr.ExpiresMs != clk.now().Add(10*time.Minute).UnixMilli() {
		t.Fatalf("vence en %d", pr.ExpiresMs)
	}
	// En paralelo solo una aplicación gana.
	var wg sync.WaitGroup
	var oks atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if apply(pr.Token) == nil {
				oks.Add(1)
			}
		}()
	}
	wg.Wait()
	if oks.Load() != 1 || len(o.labels(t)) != 3 {
		t.Fatalf("ganaron %d, credenciales %d", oks.Load(), len(o.labels(t)))
	}
	if err := apply(pr.Token); status.Code(err) != codes.NotFound {
		t.Fatalf("reuso: %v", err)
	}
	// Vencido: se rechaza y se borra lo descifrado.
	pr, _ = o.preview(t, path)
	clk.avanza(10*time.Minute + time.Second)
	if err := apply(pr.Token); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("vencido: %v", err)
	}
	if n, _ := o.pendientes(); n != 0 {
		t.Fatal("quedó la vista previa vencida")
	}
	// Vencido sin que nadie aplique: otra vista previa o el barrido lo borran.
	pr, _ = o.preview(t, path)
	n, _ := o.pendientes()
	if n != 1 {
		t.Fatalf("pendientes %d", n)
	}
	var guardadas []string
	o.core.respaldos.mu.Lock()
	for _, p := range o.core.respaldos.pend {
		guardadas = append(guardadas, string(p.creds[0].Password.Bytes()))
	}
	o.core.respaldos.mu.Unlock()
	clk.avanza(11 * time.Minute)
	o.core.respaldos.sweep(clk.now())
	if n, _ := o.pendientes(); n != 0 {
		t.Fatal("el barrido no borró la vencida")
	}
	_ = guardadas
}

func TestRespaldoBorraDescifradoAlAplicarYAlCerrar(t *testing.T) {
	_, path := bovedaConRespaldo(t, nil)
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	// La vista previa guarda las credenciales; al aplicar se destruyen.
	pr, _ := o.preview(t, path)
	o.core.respaldos.mu.Lock()
	var creds []interface{ Empty() bool }
	for _, p := range o.core.respaldos.pend {
		for _, c := range p.creds {
			if c.Password.Empty() {
				t.Fatal("la vista previa no guardó el secreto")
			}
			creds = append(creds, c.Password)
		}
	}
	o.core.respaldos.mu.Unlock()
	if len(creds) != 3 {
		t.Fatalf("guardadas %d", len(creds))
	}
	if _, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token}); err != nil {
		t.Fatal(err)
	}
	for _, c := range creds {
		if !c.Empty() {
			t.Fatal("quedó un secreto en memoria tras aplicar")
		}
	}
	// Al cerrar la bóveda (por cualquier vía) también se borran; aplicar con ella cerrada da FailedPrecondition.
	for name, cerrar := range map[string]func(){
		"botón":     func() { o.vault.Lock(ctx(t), &v1.LockRequest{}) },
		"sistema":   func() { o.core.OnLock() },
		"suspender": func() { o.core.OnSleep() },
	} {
		pr, err := o.preview(t, path)
		if err != nil {
			t.Fatal(name, err)
		}
		cerrar()
		if n, _ := o.pendientes(); n != 0 {
			t.Fatalf("%s: quedó la vista previa", name)
		}
		if _, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token}); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := o.vault.Unlock(ctx(t), &v1.UnlockRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
			t.Fatal(err)
		}
	}
}

// copyReservada arma una bóveda con una entrada reservada y una normal, para ver cómo se clasifican.
func copyReservada(t *testing.T, path string) {
	t.Helper()
	v, err := vault.Create(path, []byte("maestra-de-prueba"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []vault.Credential{
		{Label: "macuahuitl:llave-de-respaldos", Username: "hmac", Password: secret.New([]byte("HMAC")), Enable: secret.New(nil), SSHKey: secret.New(nil)},
		{Label: "x", Username: "u", Password: secret.New([]byte("p")), Enable: secret.New(nil), SSHKey: secret.New(nil)},
	} {
		if _, err := v.Put(c); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSameCredCompraraCadaCampo(t *testing.T) {
	mk := func(user, pw, en, key string) vault.Credential {
		return vault.Credential{Label: "x", Username: user, Password: secret.New([]byte(pw)), Enable: secret.New([]byte(en)), SSHKey: secret.New([]byte(key))}
	}
	if !sameCred(mk("u", "p", "e", "k"), mk("u", "p", "e", "k")) {
		t.Fatal("iguales no coinciden")
	}
	for name, otra := range map[string]vault.Credential{
		"usuario": mk("v", "p", "e", "k"), "password": mk("u", "q", "e", "k"), "enable": mk("u", "p", "f", "k"), "llave": mk("u", "p", "e", "l"),
	} {
		if sameCred(mk("u", "p", "e", "k"), otra) {
			t.Fatalf("difiere en %s y se tomó por igual", name)
		}
	}
}

// Con la bóveda cerrada exportar no revela si la frase es la maestra: mismo error, y sin registro de unlock fallido.
func TestRespaldoExportCerradaNoEsOraculo(t *testing.T) {
	h := newHarness(t, nil)
	h.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("maestra-larga-123")})
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	var msgs []string
	for _, f := range []string{"maestra-larga-123", "otra-frase-larga-1"} {
		_, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: filepath.Join(t.TempDir(), "r.mcvault"), Passphrase: []byte(f), Confirm: true})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%q: %v", f, err)
		}
		msgs = append(msgs, err.Error())
	}
	if msgs[0] != msgs[1] {
		t.Fatalf("errores distintos:\n%s\n%s", msgs[0], msgs[1])
	}
}

// Un respaldo no puede pisar la bóveda viva, su .bak ni nada dentro de la carpeta de datos del núcleo, ni por enlaces.
func TestRespaldoExportRechazaLaCarpetaDeDatos(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	vp := h.core.vaultPath()
	antes, err := os.ReadFile(vp)
	if err != nil {
		t.Fatal(err)
	}
	fuera := t.TempDir()
	enlaceDir := filepath.Join(fuera, "datos")
	if err := os.Symlink(h.p.Data, enlaceDir); err != nil {
		t.Fatal(err)
	}
	enlaceArchivo := filepath.Join(fuera, "vault.mcvault")
	if err := os.Symlink(vp, enlaceArchivo); err != nil {
		t.Fatal(err)
	}
	for name, dst := range map[string]string{
		"la bóveda":           vp,
		"su .bak":             vp + ".bak",
		"otro archivo":        filepath.Join(h.p.Data, "otro.mcvault"),
		"subcarpeta":          filepath.Join(h.p.Data, "sub", "x.mcvault"),
		"enlace a la carpeta": filepath.Join(enlaceDir, "x.mcvault"),
		"enlace al archivo":   enlaceArchivo,
	} {
		for _, ow := range []bool{false, true} {
			_, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: dst, Passphrase: []byte(fraseResp), Confirm: true, Overwrite: ow})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "carpeta de datos") {
				t.Fatalf("%s (overwrite=%v): %v", name, ow, err)
			}
		}
	}
	if despues, _ := os.ReadFile(vp); string(despues) != string(antes) {
		t.Fatal("la bóveda viva cambió")
	}
	if _, err := os.Stat(filepath.Join(h.p.Data, "otro.mcvault")); err == nil {
		t.Fatal("escribió dentro de la carpeta de datos")
	}
	// Fuera de la carpeta de datos sí.
	r, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: filepath.Join(fuera, "ok.mcvault"), Passphrase: []byte(fraseResp), Confirm: true})
	if err != nil || r.Count != 1 || r.NoPermissions {
		t.Fatalf("fuera: %+v %v", r, err)
	}
}

// Dos «reemplazar» hacia la misma credencial local son una decisión mala: error, nada escrito y el token sigue vivo.
func TestRespaldoDosReemplazosAlMismoDestino(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	h.put(t, "dup", "u1", "PW-UNO")
	h.put(t, "dup", "u2", "PW-DOS")
	path := filepath.Join(t.TempDir(), "d.mcvault")
	if _, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: path, Passphrase: []byte(fraseResp), Confirm: true}); err != nil {
		t.Fatal(err)
	}
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	o.put(t, "dup", "uX", "LOCAL")
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	var dups []string
	for _, i := range pr.Items {
		if i.Label == "dup" {
			if i.State != "conflicto_etiqueta" {
				t.Fatalf("estado %s", i.State)
			}
			dups = append(dups, i.Id)
		}
	}
	if len(dups) != 2 {
		t.Fatalf("dups = %v", dups)
	}
	_, err = o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token, Decisions: []*v1.VaultBackupDecision{{Id: dups[0], Action: "reemplazar"}, {Id: dups[1], Action: "reemplazar"}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("dos reemplazos: %v", err)
	}
	if got := o.labels(t); got["dup"] != "LOCAL" || len(got) != 1 {
		t.Fatalf("escribió algo: %v", got)
	}
	ap, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token, Decisions: []*v1.VaultBackupDecision{{Id: dups[0], Action: "reemplazar"}, {Id: dups[1], Action: "renombrar"}}})
	if err != nil || ap.Replaced != 1 || ap.Renamed != 1 {
		t.Fatalf("corregida: %+v %v", ap, err)
	}
}

// Una credencial del respaldo «igual» a la local y otra «reemplazar» hacia esa misma: el informe mentiría, se rechaza.
func TestRespaldoIgualYReemplazoAlMismoDestino(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	h.put(t, "dup", "u1", "PW-UNO")
	h.put(t, "dup", "u2", "PW-DOS")
	path := filepath.Join(t.TempDir(), "d.mcvault")
	if _, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: path, Passphrase: []byte(fraseResp), Confirm: true}); err != nil {
		t.Fatal(err)
	}
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	o.put(t, "dup", "u1", "PW-UNO")
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	var conflicto string
	for _, i := range pr.Items {
		if i.Label == "dup" && i.State == "conflicto_etiqueta" {
			conflicto = i.Id
		}
	}
	if conflicto == "" {
		t.Fatalf("sin conflicto: %v", estados(pr))
	}
	_, err = o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token, Decisions: []*v1.VaultBackupDecision{{Id: conflicto, Action: "reemplazar"}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("igual + reemplazo: %v", err)
	}
	if got := o.labels(t); got["dup"] != "PW-UNO" || len(got) != 1 {
		t.Fatalf("escribió algo: %v", got)
	}
}
