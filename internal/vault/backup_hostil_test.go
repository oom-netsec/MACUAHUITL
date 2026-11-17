package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// respaldoChico escribe un respaldo válido de una sola credencial y devuelve su ruta y sus bytes.
func respaldoChico(t *testing.T) (string, []byte) {
	t.Helper()
	v, _ := newVault(t)
	if _, err := v.Put(cred("a", "p", "")); err != nil {
		t.Fatal(err)
	}
	dst := rutaRespaldo(t)
	if _, err := WriteBackup(v, dst, pw(frase), false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	return dst, raw
}

func abrirBytes(t *testing.T, raw []byte) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "h.mcvault")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := OpenBackup(p, pw(frase))
	if err == nil {
		b.LockAll()
	}
	return err
}

func TestBackupHostilVersionYLongitudes(t *testing.T) {
	_, raw := respaldoChico(t)
	mut := func(f func(b []byte)) []byte {
		b := bytes.Clone(raw)
		f(b)
		return b
	}
	casos := map[string][]byte{
		"versión 0":             mut(func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 0) }),
		"versión 2":             mut(func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 2) }),
		"versión 65535":         mut(func(b []byte) { binary.BigEndian.PutUint16(b[4:6], 0xFFFF) }),
		"n gigante":             mut(func(b []byte) { binary.BigEndian.PutUint32(b[107:111], 0xFFFFFFFF) }),
		"n mayor al real":       mut(func(b []byte) { binary.BigEndian.PutUint32(b[107:111], 2) }),
		"n cero y cola":         mut(func(b []byte) { binary.BigEndian.PutUint32(b[107:111], 0) }),
		"l gigante":             mut(func(b []byte) { binary.BigEndian.PutUint32(b[139:143], 0xFFFFFFFF) }),
		"l menor a la etiqueta": mut(func(b []byte) { binary.BigEndian.PutUint32(b[139:143], 15) }),
		"cola basura":           append(bytes.Clone(raw), 0xAA),
		"magia distinta":        mut(func(b []byte) { b[0] = 'X' }),
	}
	for name, b := range casos {
		var antes, despues runtime.MemStats
		runtime.ReadMemStats(&antes)
		err := abrirBytes(t, b)
		runtime.ReadMemStats(&despues)
		if !errors.Is(err, ErrNotBackup) {
			t.Errorf("%s: err = %v, quería ErrNotBackup", name, err)
		}
		if d := despues.TotalAlloc - antes.TotalAlloc; d > 32<<20 {
			t.Errorf("%s: reservó %d bytes", name, d)
		}
	}
}

func TestBackupHostilTruncadoEnCadaOffset(t *testing.T) {
	_, raw := respaldoChico(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "t.mcvault")
	for n := 0; n < len(raw); n++ {
		if err := os.WriteFile(p, raw[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenBackup(p, pw(frase)); !errors.Is(err, ErrNotBackup) {
			t.Fatalf("truncado a %d de %d: %v", n, len(raw), err)
		}
	}
	if err := abrirBytes(t, raw); err != nil { // el completo sí abre
		t.Fatal(err)
	}
}

func TestBackupHostilVaultIDAlteradoNoAutentica(t *testing.T) {
	_, raw := respaldoChico(t)
	b := bytes.Clone(raw)
	b[6] ^= 0xFF // el id de bóveda va en los datos asociados de la DEK y de cada entrada
	if err := abrirBytes(t, b); !errors.Is(err, ErrWrongPassword) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestBackupHostilArchivoMayorAlTope(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grande.mcvault")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, maxBackupBytes+1); err != nil { // disperso: no ocupa disco
		t.Fatal(err)
	}
	if _, err := OpenBackup(p, pw(frase)); !errors.Is(err, ErrNotBackup) {
		t.Fatalf("err = %v", err)
	}
}

// Un respaldo con un campo de 9 MiB dentro del cifrado (la frase la pone quien lo arma) no debe tumbar el proceso: memguard
// entra en pánico si no puede bloquear la memoria (RLIMIT_MEMLOCK), así que el límite por campo se aplica al descifrar.
func TestBackupHostilCampoEnormeDentroDelCifrado(t *testing.T) {
	_, raw := respaldoChico(t)
	p := filepath.Join(t.TempDir(), "e.mcvault")
	os.WriteFile(p, raw, 0o600)
	b, err := OpenBackup(p, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 0, 9<<20+64)
	for i := 0; i < plainFields; i++ {
		n := 1
		if i == 2 {
			n = 9 << 20
		}
		plain = binary.BigEndian.AppendUint32(plain, uint32(n))
		plain = append(plain, make([]byte, n)...)
	}
	e := &b.entries[0]
	e.CT = b.aead.Seal(nil, e.Nonce[:], plain, b.entryAAD(e.ID))
	if err := os.WriteFile(p, marshalFile(b.hdr, b.entries), 0o600); err != nil {
		t.Fatal(err)
	}
	b.LockAll()
	b, err = OpenBackup(p, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	defer b.LockAll()
	if _, err := b.ListAll(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, quería ErrCorrupt", err)
	}
}

func TestPutRechazaCampoMayorAlTope(t *testing.T) {
	v, _ := newVault(t)
	grande := bytes.Repeat([]byte{'x'}, MaxFieldBytes+1)
	for name, c := range map[string]Credential{
		"etiqueta": {Label: string(grande), Password: secret.New(pw("p"))},
		"usuario":  {Label: "a", Username: string(grande), Password: secret.New(pw("p"))},
		"password": {Label: "a", Password: secret.New(bytes.Clone(grande))},
		"llave":    {Label: "a", SSHKey: secret.New(bytes.Clone(grande))},
	} {
		if _, err := v.Put(c); !errors.Is(err, ErrFieldTooLong) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if l, _ := v.List(); len(l) != 0 {
		t.Fatalf("quedó algo: %v", l)
	}
	if _, err := v.Put(Credential{Label: "ok", Password: secret.New(bytes.Clone(grande[:MaxFieldBytes]))}); err != nil {
		t.Fatalf("en el tope debe entrar: %v", err)
	}
}

// Documenta el estado actual: la llave SSH no se valida ni en Put ni al abrir un respaldo; solo transport/ssh.go:69 la
// parsea al conectar. Una privada inválida viaja entera y no rompe nada a medias.
func TestBackupHostilLlaveSSHInvalidaViajaSinValidar(t *testing.T) {
	v, _ := newVault(t)
	malas := [][]byte{[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncada"), {0, 1, 2, 0xFF}, bytes.Repeat([]byte("A"), 1<<16)}
	for _, k := range malas {
		if _, err := v.Put(Credential{Label: "k" + string(rune('a'+len(k)%20)), Username: "u", SSHKey: secret.New(bytes.Clone(k))}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	dst := rutaRespaldo(t)
	n, err := WriteBackup(v, dst, pw(frase), false)
	if err != nil || n != len(malas) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, err := OpenBackup(dst, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	b.LockAll()
}
