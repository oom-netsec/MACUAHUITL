package vault

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

var testParams = Params{MemoryKiB: 8192, Iterations: 1, Threads: 1}

func TestMain(m *testing.M) {
	MinMemoryKiB = 8192
	os.Exit(m.Run())
}

func pw(s string) []byte { return []byte(s) }

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.mcv")
	v, err := Create(p, pw("maestra"), testParams)
	if err != nil {
		t.Fatal(err)
	}
	return v, p
}

func cred(label, pass, enable string) Credential {
	return Credential{Label: label, Username: "admin", Password: secret.New(pw(pass)), Enable: secret.New(pw(enable))}
}

func reopen(t *testing.T, p string) *Vault {
	t.Helper()
	v, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(pw("maestra")); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCreateUnlockRoundTrip(t *testing.T) {
	v, p := newVault(t)
	id, err := v.Put(cred("core", "MARKER-PW", "MARKER-EN"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := reopen(t, p).Get(id)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	if string(c.Password.Bytes()) != "MARKER-PW" || string(c.Enable.Bytes()) != "MARKER-EN" || c.Label != "core" || c.Username != "admin" || c.ID != id {
		t.Fatalf("mismatch: %+v", c)
	}
	if !c.SSHKey.Empty() {
		t.Fatal("ssh key should be empty")
	}
}

func TestWrongPassword(t *testing.T) {
	_, p := newVault(t)
	v, _ := Open(p)
	if err := v.Unlock(pw("otra")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyPassword(t *testing.T) {
	if _, err := Create(filepath.Join(t.TempDir(), "v"), []byte{}, testParams); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Create: %v", err)
	}
	v, p := newVault(t)
	if err := v.ChangeMasterPassword(pw("maestra"), []byte{}); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Change: %v", err)
	}
	o, _ := Open(p)
	if err := o.Unlock([]byte{}); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Unlock: %v", err)
	}
}

func TestWeakParamsRejected(t *testing.T) {
	_, err := Create(filepath.Join(t.TempDir(), "v"), pw("x"), Params{MemoryKiB: 4096, Iterations: 1, Threads: 1})
	if !errors.Is(err, ErrWeakParams) {
		t.Fatalf("err = %v", err)
	}
}

func TestTamperEveryHeaderByte(t *testing.T) {
	_, p := newVault(t)
	orig, _ := os.ReadFile(p)
	for off := 0; off < headerLen; off++ {
		b := bytes.Clone(orig)
		b[off] ^= 1
		os.WriteFile(p, b, 0o600)
		v, err := Open(p)
		if err == nil {
			err = v.Unlock(pw("maestra"))
		}
		if err == nil {
			t.Errorf("offset %d: tampered vault opened", off)
		}
	}
}

func TestTamperEntry(t *testing.T) {
	v, p := newVault(t)
	id, _ := v.Put(cred("a", "x", ""))
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 1
	os.WriteFile(p, b, 0o600)
	if _, err := reopen(t, p).Get(id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestSwapEntryIDs(t *testing.T) {
	v, p := newVault(t)
	a, _ := v.Put(cred("a", "x", ""))
	bID, _ := v.Put(cred("b", "y", ""))
	raw, _ := os.ReadFile(p)
	_, entries, err := parseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].ID, entries[1].ID = entries[1].ID, entries[0].ID
	h, _, _ := parseFile(raw)
	os.WriteFile(p, marshalFile(h, entries), 0o600)
	w := reopen(t, p)
	for _, id := range []string{a, bID} {
		if _, err := w.Get(id); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Get(%s) err = %v, want ErrCorrupt", id, err)
		}
	}
}

func TestChangeMasterPassword(t *testing.T) {
	v, p := newVault(t)
	id, _ := v.Put(cred("a", "x", ""))
	if err := v.ChangeMasterPassword(pw("maestra"), pw("nueva")); err != nil {
		t.Fatal(err)
	}
	o, _ := Open(p)
	if err := o.Unlock(pw("maestra")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old password: %v", err)
	}
	o, _ = Open(p)
	if err := o.Unlock(pw("nueva")); err != nil {
		t.Fatal(err)
	}
	c, err := o.Get(id)
	if err != nil || string(c.Password.Bytes()) != "x" {
		t.Fatalf("get after change: %v", err)
	}
}

func TestChangeMasterPasswordWrongOld(t *testing.T) {
	v, _ := newVault(t)
	if err := v.ChangeMasterPassword(pw("mala"), pw("nueva")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	v, p := newVault(t)
	v.Put(cred("a", "MARKER-PW", ""))
	v.Put(cred("b", "otra", ""))
	for _, f := range []string{p, p + ".bak"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{"MARKER-PW", base64.StdEncoding.EncodeToString(pw("MARKER-PW")), hex.EncodeToString(pw("MARKER-PW")), "maestra"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains %q", f, needle)
			}
		}
	}
}

func TestFilePerms(t *testing.T) {
	v, p := newVault(t)
	v.Put(cred("a", "x", ""))
	for _, f := range []string{p, p + ".bak"} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o", f, fi.Mode().Perm())
		}
	}
}

func TestLockedOperations(t *testing.T) {
	_, p := newVault(t)
	v, _ := Open(p)
	if _, err := v.Get("x"); !errors.Is(err, ErrLocked) {
		t.Errorf("Get: %v", err)
	}
	if _, err := v.Put(cred("a", "x", "")); !errors.Is(err, ErrLocked) {
		t.Errorf("Put: %v", err)
	}
	if _, err := v.List(); !errors.Is(err, ErrLocked) {
		t.Errorf("List: %v", err)
	}
	if err := v.Delete("x"); !errors.Is(err, ErrLocked) {
		t.Errorf("Delete: %v", err)
	}
}

func TestMasterPasswordWiped(t *testing.T) {
	_, p := newVault(t)
	v, _ := Open(p)
	m := pw("maestra")
	if err := v.Unlock(m); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m, make([]byte, len(m))) {
		t.Fatalf("master password not wiped: %q", m)
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	_, p := newVault(t)
	if _, err := Create(p, pw("x"), testParams); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestListAndDelete(t *testing.T) {
	v, _ := newVault(t)
	a, _ := v.Put(cred("a", "x", "en"))
	v.Put(cred("b", "y", ""))
	l, err := v.List()
	if err != nil || len(l) != 2 {
		t.Fatalf("list = %v, %v", l, err)
	}
	if err := v.Delete(a); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
	if err := v.Delete(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestPutReplaces(t *testing.T) {
	v, p := newVault(t)
	id, _ := v.Put(cred("a", "x", ""))
	c := cred("a2", "z", "")
	c.ID = id
	if got, err := v.Put(c); err != nil || got != id {
		t.Fatalf("replace: %s %v", got, err)
	}
	r, _ := reopen(t, p).Get(id)
	if string(r.Password.Bytes()) != "z" || r.Label != "a2" {
		t.Fatalf("not replaced: %+v", r)
	}
}

func TestConcurrentPutGet(t *testing.T) {
	v, _ := newVault(t)
	id, _ := v.Put(cred("a", "x", ""))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				if _, err := v.Put(cred(fmt.Sprint(i), "p", "")); err != nil {
					t.Error(err)
				}
			} else if c, err := v.Get(id); err != nil {
				t.Error(err)
			} else {
				c.Password.Destroy()
			}
		}(i)
	}
	wg.Wait()
}

func TestCalibrateNeverBelowDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("deriva con 256 MiB")
	}
	p := Calibrate(1)
	if p != DefaultParams {
		t.Fatalf("Calibrate(1ns) = %+v, want %+v", p, DefaultParams)
	}
}

func TestBakNotOpenableWithOldPassword(t *testing.T) {
	v, p := newVault(t)
	v.Put(cred("a", "x", ""))
	if err := v.ChangeMasterPassword(pw("maestra"), pw("nueva")); err != nil {
		t.Fatal(err)
	}
	b, err := Open(p + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Unlock(pw("maestra")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf(".bak still opens with the old password: %v", err)
	}
}

func TestEncodePlainSingleAllocation(t *testing.T) {
	c := Credential{Label: "l", Username: "u", Password: secret.New(pw("p")), SSHKey: secret.New(bytes.Repeat([]byte("k"), 3000))}
	if n := testing.AllocsPerRun(10, func() { wipe(encodePlain(c)) }); n != 1 {
		t.Fatalf("encodePlain allocations = %v, want 1 (each extra one leaves unwiped plaintext)", n)
	}
}

func TestOneAEADPerDEKLifetime(t *testing.T) {
	builds := 0
	orig := newAEAD
	newAEAD = func(k []byte) (cipher.AEAD, error) { builds++; return orig(k) }
	defer func() { newAEAD = orig }()
	_, p := newVault(t)
	v, _ := Open(p)
	v.Unlock(pw("maestra"))
	builds = 0
	id, _ := v.Put(cred("a", "x", ""))
	for i := 0; i < 5; i++ {
		c, _ := v.Get(id)
		c.Password.Destroy()
	}
	v.List()
	if builds != 0 {
		t.Fatalf("DEK key schedule rebuilt %d times after unlock", builds)
	}
}

// Las entradas reservadas del sistema (la llave de las fichas de respaldo) no son credenciales de conexión.
func TestReservedEntriesAreNeitherListedNorUsableAsCredentials(t *testing.T) {
	v, _ := newVault(t)
	if _, err := v.Put(cred("core", "pw", "en")); err != nil {
		t.Fatal(err)
	}
	kid, err := v.Put(Credential{Label: ReservedPrefix + "llave", Username: "hmac", Password: secret.New(pw("LLAVE"))})
	if err != nil {
		t.Fatal(err)
	}
	infos, err := v.List()
	if err != nil || len(infos) != 1 || infos[0].Label != "core" {
		t.Fatalf("List no muestra lo reservado: %+v %v", infos, err)
	}
	if _, err := v.Get(kid); !errors.Is(err, ErrReserved) {
		t.Fatalf("Get de una entrada reservada: %v", err)
	}
	c, err := v.GetReserved(ReservedPrefix + "llave")
	if err != nil || string(c.Password.Bytes()) != "LLAVE" {
		t.Fatalf("GetReserved: %v", err)
	}
	c.Password.Destroy()
	if _, err := v.GetReserved(ReservedPrefix + "otra"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sin esa entrada: %v", err)
	}
	if _, err := v.GetReserved("core"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetReserved solo da las reservadas: %v", err)
	}
}

// La entrada reservada no se puede sobrescribir ni borrar por su ID: sin la llave los respaldos firmados dejan de poder restaurarse.
func TestReservedEntryCannotBeOverwrittenOrDeletedByID(t *testing.T) {
	v, _ := newVault(t)
	kid, err := v.Put(Credential{Label: ReservedPrefix + "llave", Username: "hmac", Password: secret.New(pw("LLAVE"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(Credential{ID: kid, Label: "normal", Username: "x", Password: secret.New(pw("otra"))}); !errors.Is(err, ErrReserved) {
		t.Errorf("Put con el ID de la reservada: %v", err)
	}
	if err := v.Delete(kid); !errors.Is(err, ErrReserved) {
		t.Errorf("Delete de la reservada: %v", err)
	}
	c, err := v.GetReserved(ReservedPrefix + "llave")
	if err != nil || string(c.Password.Bytes()) != "LLAVE" {
		t.Fatalf("la llave debía seguir disponible: %v", err)
	}
	c.Password.Destroy()
	// Una credencial normal se sigue pudiendo reemplazar y borrar.
	id, _ := v.Put(cred("core", "pw", "en"))
	if _, err := v.Put(Credential{ID: id, Label: "core2", Username: "admin", Password: secret.New(pw("nueva"))}); err != nil {
		t.Errorf("reemplazar una normal: %v", err)
	}
	if err := v.Delete(id); err != nil {
		t.Errorf("borrar una normal: %v", err)
	}
}

// Borrar una credencial no la deja viva en el respaldo hasta la siguiente escritura.
func TestDeleteReescribeElBak(t *testing.T) {
	v, p := newVault(t)
	a, _ := v.Put(cred("a", "x", ""))
	v.Put(cred("b", "y", ""))
	if err := v.Delete(a); err != nil {
		t.Fatal(err)
	}
	b, err := Open(p + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Unlock(pw("maestra")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(a); !errors.Is(err, ErrNotFound) {
		t.Fatalf("la credencial borrada sigue en el .bak: %v", err)
	}
	if l, err := b.List(); err != nil || len(l) != 1 {
		t.Fatalf("el .bak debía conservar la otra: %v %v", l, err)
	}
}
