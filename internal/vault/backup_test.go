package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

const frase = "frase del respaldo 1"

// vaultConDatos tiene 3 credenciales normales y 1 reservada.
func vaultConDatos(t *testing.T) *Vault {
	t.Helper()
	v, _ := newVault(t)
	for _, c := range []Credential{
		cred("core", "PW-CORE", "EN-CORE"),
		cred("borde", "PW-BORDE", ""),
		{Label: "llave", Username: "ops", Password: secret.New(pw("")), SSHKey: secret.New(pw("-----KEY-----"))},
		{Label: ReservedPrefix + "llave-de-respaldos", Username: "hmac", Password: secret.New(pw("HMAC-SECRETO"))},
	} {
		if _, err := v.Put(c); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func rutaRespaldo(t *testing.T) string { return filepath.Join(t.TempDir(), "r.mcvault") }

func TestWriteBackupIdaYVuelta(t *testing.T) {
	v := vaultConDatos(t)
	dst := rutaRespaldo(t)
	n, err := WriteBackup(v, dst, pw(frase), false)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, err := OpenBackup(dst, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	all, err := b.ListAll()
	if err != nil || len(all) != 3 {
		t.Fatalf("%v %v", all, err)
	}
	for _, i := range all {
		if Reserved(i.Label) {
			t.Fatal("la reservada viajó al respaldo")
		}
		c, err := b.Get(i.ID)
		if err != nil {
			t.Fatal(err)
		}
		if i.Label == "core" && (string(c.Password.Bytes()) != "PW-CORE" || string(c.Enable.Bytes()) != "EN-CORE" || c.Username != "admin") {
			t.Fatalf("core distinta: %+v", c)
		}
		if i.Label == "llave" && string(c.SSHKey.Bytes()) != "-----KEY-----" {
			t.Fatal("llave SSH distinta")
		}
	}
	if raw, _ := os.ReadFile(dst); bytes.Contains(raw, []byte("PW-CORE")) || bytes.Contains(raw, []byte("core")) {
		t.Fatal("el archivo trae texto en claro")
	}
}

func TestBackupTieneDEKYSalPropias(t *testing.T) {
	v := vaultConDatos(t)
	dst := rutaRespaldo(t)
	if _, err := WriteBackup(v, dst, pw(frase), false); err != nil {
		t.Fatal(err)
	}
	b, err := OpenBackup(dst, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	if b.hdr.VaultID == v.hdr.VaultID || b.hdr.Salt == v.hdr.Salt || b.hdr.DEKCipher == v.hdr.DEKCipher || bytes.Equal(b.dek.Bytes(), v.dek.Bytes()) {
		t.Fatal("el respaldo reutiliza identidad, sal o DEK de la bóveda viva")
	}
	if b.Params() != v.Params() {
		t.Fatalf("parámetros %+v != %+v", b.Params(), v.Params())
	}
	if _, err := OpenBackup(dst, pw("maestra")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("la maestra abrió el respaldo: %v", err)
	}
}

func TestWriteBackupRechazos(t *testing.T) {
	v := vaultConDatos(t)
	for name, tc := range map[string]struct {
		phrase string
		want   error
	}{
		"corta":   {"once chars!", ErrShortPhrase},
		"vacía":   {"", ErrShortPhrase},
		"maestra": {"maestra", ErrShortPhrase},
	} {
		dst := rutaRespaldo(t)
		if _, err := WriteBackup(v, dst, pw(tc.phrase), false); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Stat(dst); err == nil {
			t.Fatalf("%s: dejó archivo", name)
		}
	}
	// Igual a la maestra (con 12 o más caracteres).
	long, _ := Create(filepath.Join(t.TempDir(), "v.mcv"), pw("maestra-larga-123"), testParams)
	long.Put(cred("x", "p", ""))
	if _, err := WriteBackup(long, rutaRespaldo(t), pw("maestra-larga-123"), false); !errors.Is(err, ErrSamePhrase) {
		t.Fatalf("misma frase: %v", err)
	}
	if !long.Unlocked() {
		t.Fatal("comparar la frase cambió el estado de la bóveda")
	}
	v.Lock()
	if _, err := WriteBackup(v, rutaRespaldo(t), pw(frase), false); !errors.Is(err, ErrLocked) {
		t.Fatalf("cerrada: %v", err)
	}
}

func TestMatchesNoCambiaEstado(t *testing.T) {
	v, p := newVault(t)
	v.Lock()
	if v.Matches(pw("otra")) || !v.Matches(pw("maestra")) {
		t.Fatal("comparación incorrecta")
	}
	if v.Unlocked() {
		t.Fatal("Matches abrió la bóveda")
	}
	c, _ := Open(p) // nunca desbloqueada
	if !c.Matches(pw("maestra")) || c.Unlocked() || !c.dek.Empty() {
		t.Fatal("Matches dejó la DEK en memoria")
	}
	m := pw("maestra")
	c.Matches(m)
	if string(m) != "maestra" {
		t.Fatal("Matches borró el argumento que debe borrar quien llama")
	}
}

func TestWriteBackupArchivo(t *testing.T) {
	v := vaultConDatos(t)
	dir := t.TempDir()
	dst := filepath.Join(dir, "r.mcvault")
	if _, err := WriteBackup(v, dst, pw(frase), false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo %v", fi.Mode())
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Fatalf("quedaron restos: %v", es)
	}
	before, _ := os.ReadFile(dst)
	if _, err := WriteBackup(v, dst, pw(frase), false); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("sin overwrite: %v", err)
	}
	if after, _ := os.ReadFile(dst); !bytes.Equal(before, after) {
		t.Fatal("pisó el archivo sin overwrite")
	}
	if _, err := WriteBackup(v, dst, pw(frase), true); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(dst); bytes.Equal(before, after) {
		t.Fatal("overwrite no reemplazó")
	}
	if es, _ := os.ReadDir(dir); len(es) != 1 {
		t.Fatalf("quedaron restos: %v", es)
	}
}

func TestWriteBackupNoSigueSymlinks(t *testing.T) {
	v := vaultConDatos(t)
	dir := t.TempDir()
	objetivo := filepath.Join(dir, "objetivo")
	os.WriteFile(objetivo, []byte("intacto"), 0o600)
	enlace := filepath.Join(dir, "enlace.mcvault")
	os.Symlink(objetivo, enlace)
	if _, err := WriteBackup(v, enlace, pw(frase), false); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("sin overwrite: %v", err)
	}
	if _, err := WriteBackup(v, enlace, pw(frase), true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(objetivo); string(b) != "intacto" {
		t.Fatal("escribió a través del enlace")
	}
	if fi, _ := os.Lstat(enlace); !fi.Mode().IsRegular() {
		t.Fatal("el enlace no fue reemplazado por el archivo")
	}
	// Una carpeta no se reemplaza.
	sub := filepath.Join(dir, "carpeta")
	os.Mkdir(sub, 0o700)
	if _, err := WriteBackup(v, sub, pw(frase), true); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("carpeta: %v", err)
	}
}

func TestOpenBackupArchivoAjeno(t *testing.T) {
	v := vaultConDatos(t)
	buen := rutaRespaldo(t)
	WriteBackup(v, buen, pw(frase), false)
	raw, _ := os.ReadFile(buen)
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"texto":      []byte("esto no es un respaldo, solo texto de más de ciento once bytes para pasar el largo mínimo del encabezado....................."),
		"json":       []byte(`{"a":1}`),
		"vacío":      {},
		"truncado":   raw[:len(raw)-20],
		"encabezado": raw[:50],
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, content, 0o600)
		if _, err := OpenBackup(p, pw(frase)); !errors.Is(err, ErrNotBackup) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := OpenBackup(dir, pw(frase)); !errors.Is(err, ErrNotBackup) {
		t.Fatalf("carpeta: %v", err)
	}
	if _, err := OpenBackup(filepath.Join(dir, "no-existe"), pw(frase)); err == nil || errors.Is(err, ErrNotBackup) {
		t.Fatalf("inexistente debe ser otro error: %v", err)
	}
	if _, err := OpenBackup(buen, pw("frase incorrecta!!")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("frase: %v", err)
	}
	f := pw(frase)
	OpenBackup(buen, f)
	if f[0] != 0 {
		t.Fatal("la frase no se puso en ceros")
	}
}

func TestPutBatchTodoONada(t *testing.T) {
	v, p := newVault(t)
	a, _ := v.Put(cred("a", "1", ""))
	antes, _ := os.ReadFile(p)
	_, err := v.PutBatch([]Credential{cred("b", "2", ""), {ID: "ffffffffffffffffffffffffffffffff", Label: "x", Password: secret.New(nil)}})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if now, _ := os.ReadFile(p); !bytes.Equal(antes, now) {
		t.Fatal("persistió un lote fallido")
	}
	if l, _ := v.List(); len(l) != 1 {
		t.Fatalf("lista %v", l)
	}
	ids, err := v.PutBatch([]Credential{cred("b", "2", ""), {ID: a, Label: "a2", Password: secret.New(pw("3"))}})
	if err != nil || len(ids) != 2 || ids[1] != a {
		t.Fatalf("%v %v", ids, err)
	}
	l, _ := v.List()
	if len(l) != 2 {
		t.Fatalf("lista %v", l)
	}
}

func TestOnLockSeLlama(t *testing.T) {
	v, _ := newVault(t)
	n := 0
	v.OnLock(func() { n++ })
	v.Lock()
	if n != 1 {
		t.Fatalf("Lock llamó %d", n)
	}
	v.Unlock(pw("maestra"))
	v.LockAll()
	if n != 2 {
		t.Fatalf("LockAll llamó %d", n)
	}
}

// Con la bóveda cerrada, exportar no debe servir de oráculo de la maestra: frase igual y distinta dan el mismo error.
func TestWriteBackupCerradaNoEsOraculoDeLaMaestra(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "v.mcv"), pw("maestra-larga-123"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	v.Put(cred("x", "p", ""))
	v.Lock()
	var msgs []string
	for _, f := range []string{"maestra-larga-123", "otra-frase-larga-1", "corta"} {
		_, err := WriteBackup(v, rutaRespaldo(t), pw(f), false)
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("%q: %v", f, err)
		}
		msgs = append(msgs, err.Error())
	}
	if msgs[0] != msgs[1] || msgs[1] != msgs[2] {
		t.Fatalf("errores distintos: %q", msgs)
	}
}

// Matches deriva fuera del lock: un Lock() concurrente no espera al Argon2.
func TestMatchesNoRetieneElLockDuranteArgon2(t *testing.T) {
	v, _ := newVault(t)
	entro, suelta := make(chan struct{}), make(chan struct{})
	old := deriveFn
	deriveFn = func(m, s []byte, p Params) *secret.Secret {
		close(entro)
		<-suelta
		return old(m, s, p)
	}
	defer func() { deriveFn = old }()
	hecho := make(chan bool)
	go func() { hecho <- v.Matches(pw("maestra")) }()
	select {
	case <-entro:
	case <-time.After(5 * time.Second):
		t.Fatal("Matches no derivó")
	}
	locked := make(chan struct{})
	go func() { v.Lock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		close(suelta)
		t.Fatal("Lock esperó al Argon2 de Matches")
	}
	close(suelta)
	if !<-hecho {
		t.Fatal("Matches debió coincidir")
	}
}

func TestOpenBackupTopeDeEntradas(t *testing.T) {
	v := vaultConDatos(t)
	dst := rutaRespaldo(t)
	WriteBackup(v, dst, pw(frase), false)
	raw, _ := os.ReadFile(dst)
	h, _, err := parseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	con := func(n int) string {
		es := make([]rawEntry, n)
		for i := range es {
			es[i] = rawEntry{CT: make([]byte, 16)}
		}
		p := filepath.Join(t.TempDir(), "m.mcvault")
		os.WriteFile(p, marshalFile(h, es), 0o600)
		return p
	}
	if _, err := OpenBackup(con(MaxBackupEntries+1), pw(frase)); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("pasado del tope: %v", err)
	}
	if b, err := OpenBackup(con(MaxBackupEntries), pw(frase)); err != nil {
		t.Fatalf("en el tope: %v", err)
	} else {
		b.LockAll()
	}
}

// No se escribe un respaldo que luego OpenBackup no aceptaría.
func TestWriteBackupParametrosTopeAbrir(t *testing.T) {
	old := SealMaxMemoryKiB
	defer func() { SealMaxMemoryKiB = old }()
	v := vaultConDatos(t)
	SealMaxMemoryKiB = testParams.MemoryKiB - 1
	dst := rutaRespaldo(t)
	if _, err := WriteBackup(v, dst, pw(frase), false); !errors.Is(err, ErrBackupParams) {
		t.Fatalf("memoria: %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("dejó archivo")
	}
	SealMaxMemoryKiB = old
	hilos, err := Create(filepath.Join(t.TempDir(), "h.mcv"), pw("maestra"), Params{MemoryKiB: testParams.MemoryKiB, Iterations: 1, Threads: 9})
	if err != nil {
		t.Fatal(err)
	}
	hilos.Put(cred("x", "p", ""))
	if _, err := WriteBackup(hilos, rutaRespaldo(t), pw(frase), false); !errors.Is(err, ErrBackupParams) {
		t.Fatalf("hilos: %v", err)
	}
}

// Una memoria vfat no admite chmod: el respaldo sigue (ya va cifrado) y se avisa; otro error de chmod sí falla.
func TestWriteBackupSinPermisos(t *testing.T) {
	v := vaultConDatos(t)
	old := chmod
	defer func() { chmod = old }()
	for name, e := range map[string]error{"EPERM": &os.PathError{Op: "chmod", Err: os.ErrPermission}, "ENOTSUP": &os.PathError{Op: "chmod", Err: errors.ErrUnsupported}} {
		chmod = func(*os.File, os.FileMode) error { return e }
		dst := rutaRespaldo(t)
		n, warn, err := WriteBackupWarn(v, dst, pw(frase), false)
		if err != nil || n != 3 || !warn {
			t.Fatalf("%s: n=%d warn=%v err=%v", name, n, warn, err)
		}
		if _, err := OpenBackup(dst, pw(frase)); err != nil {
			t.Fatalf("%s: el respaldo no abre: %v", name, err)
		}
	}
	chmod = func(*os.File, os.FileMode) error {
		return &os.PathError{Op: "chmod", Err: errors.New("input/output error")}
	}
	dst := rutaRespaldo(t)
	if _, warn, err := WriteBackupWarn(v, dst, pw(frase), false); err == nil || warn {
		t.Fatalf("EIO debía fallar: warn=%v err=%v", warn, err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("dejó archivo tras el fallo")
	}
	// Con permisos que funcionan no hay aviso.
	chmod = old
	if _, warn, err := WriteBackupWarn(v, rutaRespaldo(t), pw(frase), false); err != nil || warn {
		t.Fatalf("normal: warn=%v err=%v", warn, err)
	}
	// La bóveda viva sigue siendo estricta: un chmod que falla con EPERM la hace fallar.
	chmod = func(*os.File, os.FileMode) error { return &os.PathError{Op: "chmod", Err: os.ErrPermission} }
	if _, err := Create(filepath.Join(t.TempDir(), "estricta.mcv"), pw("maestra"), testParams); err == nil {
		t.Fatal("la bóveda viva toleró un chmod fallido")
	}
}
