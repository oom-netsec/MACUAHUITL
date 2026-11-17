package vault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
		"n gigante":             mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen-4:headerLen], 0xFFFFFFFF) }),
		"n mayor al real":       mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen-4:headerLen], 2) }),
		"n cero y cola":         mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen-4:headerLen], 0) }),
		"l gigante":             mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen+28:headerLen+32], 0xFFFFFFFF) }),
		"l menor a la etiqueta": mut(func(b []byte) { binary.BigEndian.PutUint32(b[headerLen+28:headerLen+32], 15) }),
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

// Un respaldo con un campo enorme dentro del cifrado (la frase la pone quien lo arma) no debe tumbar el proceso: memguard entra en
// pánico si no puede bloquear la memoria (RLIMIT_MEMLOCK). Uno de 200 KiB pasa la cota de memoria pero no el tope por campo
// (ErrFieldTooLong, no «dañado»); uno de 9 MiB ya lo rechaza la cota antes de descifrar nada.
func TestBackupHostilCampoEnormeDentroDelCifrado(t *testing.T) {
	for _, c := range []struct {
		n    int
		want error
	}{{200 << 10, ErrFieldTooLong}, {9 << 20, ErrBackupTooLarge}} {
		_, raw := respaldoChico(t)
		p := filepath.Join(t.TempDir(), "e.mcvault")
		os.WriteFile(p, raw, 0o600)
		b, err := OpenBackup(p, pw(frase))
		if err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, 0, c.n+64)
		for i := 0; i < plainFields; i++ {
			n := 1
			if i == 2 {
				n = c.n
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
		if c.want == ErrBackupTooLarge {
			if !errors.Is(err, c.want) {
				t.Fatalf("%d: err = %v", c.n, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.ListAll(); !errors.Is(err, c.want) {
			t.Fatalf("%d: err = %v, quería %v", c.n, err, c.want)
		}
		b.LockAll()
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
		"enable":   {Label: "a", Password: secret.New(pw("p")), Enable: secret.New(bytes.Clone(grande))},
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

// Una llave privada que x/crypto/ssh no parsea no entra: ni por Put ni al exportar (la frontera es el import, que usa el mismo
// PutBatch). El error nombra la credencial culpable y no deja nada a medias.
func TestPutRechazaLlaveSSHInvalida(t *testing.T) {
	v, _ := newVault(t)
	malas := [][]byte{[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntruncada"), {0, 1, 2, 0xFF}, bytes.Repeat([]byte("A"), 1<<16)}
	for _, k := range malas {
		_, err := v.Put(Credential{Label: "mala", Username: "u", SSHKey: secret.New(bytes.Clone(k))})
		if !errors.Is(err, ErrKeyInvalid) || !strings.Contains(err.Error(), `"mala"`) {
			t.Fatalf("err = %v", err)
		}
	}
	// En un lote, una mala tumba todo.
	_, err := v.PutBatch([]Credential{cred("buena", "p", ""), {Label: "k", SSHKey: secret.New(pw("xx"))}})
	if !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("err = %v", err)
	}
	if l, _ := v.List(); len(l) != 0 {
		t.Fatalf("quedó algo: %v", l)
	}
}

// Las llaves que crea la propia bóveda (GenerateKey, RegenerateKey, fase 44) pasan la validación.
func TestLlavesGeneradasPasanLaValidacion(t *testing.T) {
	v, _ := newVault(t)
	id, _, err := v.GenerateKey("g", "u")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.RegenerateKey(id); err != nil {
		t.Fatal(err)
	}
	dst := rutaRespaldo(t)
	if n, err := WriteBackup(v, dst, pw(frase), false); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, err := OpenBackup(dst, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	defer b.LockAll()
	infos, _ := b.ListAll()
	c, err := b.Get(infos[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.SSHKey.Destroy()
	if err := ValidateKey("g", c.SSHKey); err != nil {
		t.Fatal(err)
	}
}

// La reversa pendiente del asistente vive en una entrada reservada con el running-config entero: pasa de 64 KiB.
func TestPutReservedAceptaMasDelTope(t *testing.T) {
	v, _ := newVault(t)
	grande := bytes.Repeat([]byte{'x'}, 200<<10)
	if err := v.PutReserved(Credential{Label: ReservedPrefix + "prueba", Password: secret.New(bytes.Clone(grande))}); err != nil {
		t.Fatalf("PutReserved: %v", err)
	}
	c, err := v.GetReserved(ReservedPrefix + "prueba")
	if err != nil || !bytes.Equal(c.Password.Bytes(), grande) {
		t.Fatalf("GetReserved: %v", err)
	}
	c.Password.Destroy()
	if _, err := v.Put(Credential{Label: "u", Password: secret.New(bytes.Clone(grande))}); !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("el usuario sí lleva el tope: %v", err)
	}
}

// Una bóveda ya guardada con un campo de más de 64 KiB (escrita como antes del tope) sigue funcionando entera.
func TestBovedaConCampoMayorAlTopeSigueFuncionando(t *testing.T) {
	v, p := newVault(t)
	if _, err := v.Put(cred("chica", "p", "")); err != nil {
		t.Fatal(err)
	}
	grande := Credential{Label: "grande", Username: "u", Password: secret.New(bytes.Repeat([]byte{'x'}, 100<<10))}
	plain := encodePlain(grande)
	grande.Password.Destroy()
	var e rawEntry
	e.ID[0] = 7
	e.Nonce[0] = 9
	e.CT = v.aead.Seal(nil, e.Nonce[:], plain, v.entryAAD(e.ID)) // salta putBatchLocked, como la versión anterior
	v.entries = append(v.entries, e)
	if err := v.persistReplacingBak(); err != nil {
		t.Fatal(err)
	}
	v.LockAll()
	v = reopen(t, p)
	defer v.LockAll()
	infos, err := v.List()
	if err != nil || len(infos) != 2 {
		t.Fatalf("List: %v %v", infos, err)
	}
	if all, err := v.ListAll(); err != nil || len(all) != 2 {
		t.Fatalf("ListAll: %v %v", all, err)
	}
	dst := rutaRespaldo(t)
	if n, err := WriteBackup(v, dst, pw(frase), false); err != nil || n != 2 {
		t.Fatalf("export: n=%d %v", n, err)
	}
	// Ese respaldo ya es ajeno al abrirlo: el tope estricto da un error claro, no «dañado».
	b, err := OpenBackup(dst, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ListAll(); !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("ListAll del respaldo: %v", err)
	}
	b.LockAll()
	var id string
	for _, i := range infos {
		if i.Label == "grande" {
			id = i.ID
		}
	}
	if err := v.Delete(id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if l, _ := v.List(); len(l) != 1 {
		t.Fatalf("quedan %v", l)
	}
}

// poblar mete n credenciales chicas por lotes (cada secreto abierto ocupa memoria bloqueada: no retener todos a la vez).
func poblar(t *testing.T, v *Vault, n int) {
	t.Helper()
	for i := 0; i < n; i += 50 {
		var cs []Credential
		for j := i; j < min(i+50, n); j++ {
			cs = append(cs, cred(fmt.Sprintf("c%04d", j), "p", ""))
		}
		_, err := v.PutBatch(cs)
		for _, c := range cs {
			c.Password.Destroy()
			c.Enable.Destroy()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Muchas entradas chicas: cada una pide unas páginas de memoria bloqueada aunque su texto sea de bytes. OpenBackup lo rechaza antes
// de descifrar nada (antes, memguard entraba en pánico en la vista previa).
func TestOpenBackupRechazaPorMemoriaBloqueada(t *testing.T) {
	v, _ := newVault(t)
	poblar(t, v, 700)
	dst := rutaRespaldo(t)
	if n, err := WriteBackup(v, dst, pw(frase), false); err != nil || n != 700 {
		t.Fatalf("export de 700 (de a trozos, sin pánico): n=%d %v", n, err)
	}
	if _, err := OpenBackup(dst, pw(frase)); !errors.Is(err, ErrBackupTooLarge) {
		t.Fatalf("err = %v", err)
	}
	// Un respaldo de unos cientos sí cabe.
	v2, _ := newVault(t)
	poblar(t, v2, 250)
	dst2 := rutaRespaldo(t)
	if _, err := WriteBackup(v2, dst2, pw(frase), false); err != nil {
		t.Fatal(err)
	}
	b, err := OpenBackup(dst2, pw(frase))
	if err != nil {
		t.Fatalf("250 debían caber: %v", err)
	}
	if got := b.LockedBound(); got > MaxBackupLockedBytes {
		t.Fatalf("cota %d", got)
	}
	b.LockAll()
}

// Pocas entradas de 3×64 KiB: la cota por páginas también las rechaza antes de descifrar.
func TestOpenBackupRechazaCamposGrandesPorMemoriaBloqueada(t *testing.T) {
	v, _ := newVault(t)
	f := bytes.Repeat([]byte{'x'}, MaxFieldBytes)
	for i := 0; i < 43; i++ {
		c := Credential{Label: fmt.Sprintf("g%02d", i), Password: secret.New(bytes.Clone(f)), Enable: secret.New(bytes.Clone(f)), SSHKey: secret.New(bytes.Clone(f))}
		_, err := v.putBatch([]Credential{c}, false, false) // salta la llave: aquí solo importa el tamaño
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
		if err != nil {
			t.Fatal(err)
		}
	}
	dst := rutaRespaldo(t)
	if _, err := WriteBackup(v, dst, pw(frase), false); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(dst, pw(frase)); !errors.Is(err, ErrBackupTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

// llaveECDSAPEM es una llave privada válida que no es ed25519 OpenSSH (como las de antes de la fase 44): x/crypto/ssh la parsea y
// PublicKey la da por no soportada.
func llaveECDSAPEM(testing.TB) []byte { return nuevaLlaveECDSA() }

var llaveDePrueba = nuevaLlaveECDSA()

func nuevaLlaveECDSA() []byte {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
