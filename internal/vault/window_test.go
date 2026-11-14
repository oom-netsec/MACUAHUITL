package vault

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func armedVault(t *testing.T) (*Vault, *fakeClock, string, string) {
	t.Helper()
	v, _ := newVault(t)
	clk := &fakeClock{t: time.Date(2026, 11, 3, 23, 0, 0, 0, time.UTC)}
	v.SetClock(clk.now)
	a, _ := v.Put(cred("a", "pa", ""))
	b, _ := v.Put(cred("b", "pb", ""))
	return v, clk, a, b
}

func TestArmMax96h(t *testing.T) {
	v, clk, a, _ := armedVault(t)
	if err := v.Arm("j", clk.t.Add(96*time.Hour), []string{a}); err != nil {
		t.Fatalf("96h: %v", err)
	}
	if err := v.Arm("j", clk.t.Add(96*time.Hour+time.Second), []string{a}); !errors.Is(err, ErrWindowTooLong) {
		t.Fatalf("96h+1s: %v", err)
	}
	if err := v.Arm("j", clk.t, []string{a}); !errors.Is(err, ErrWindowTooLong) {
		t.Fatalf("now: %v", err)
	}
}

func TestArmUnknownCredential(t *testing.T) {
	v, clk, _, _ := armedVault(t)
	if err := v.Arm("j", clk.t.Add(time.Hour), []string{"00"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestLockKeepsArmedOnly(t *testing.T) {
	v, clk, a, b := armedVault(t)
	if err := v.Arm("j1", clk.t.Add(time.Hour), []string{a}); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if c, err := v.Get(a); err != nil || string(c.Password.Bytes()) != "pa" {
		t.Fatalf("Get(a) = %v", err)
	}
	if _, err := v.Get(b); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get(b) = %v", err)
	}
	if _, err := v.List(); !errors.Is(err, ErrLocked) {
		t.Fatalf("List = %v", err)
	}
	if _, err := v.Put(cred("c", "x", "")); !errors.Is(err, ErrLocked) {
		t.Fatalf("Put = %v", err)
	}
	if err := v.Arm("j2", clk.t.Add(time.Hour), []string{a}); !errors.Is(err, ErrLocked) {
		t.Fatalf("Arm while locked = %v", err)
	}
}

func TestWindowExpiresAtUntil(t *testing.T) {
	v, clk, a, _ := armedVault(t)
	v.Arm("j1", clk.t.Add(time.Hour), []string{a})
	v.Lock()
	clk.advance(time.Hour)
	if _, err := v.Get(a); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get at until = %v", err)
	}
	if w := v.Windows(); len(w) != 0 {
		t.Fatalf("windows = %v", w)
	}
}

func TestDEKDestroyedAfterLastWindow(t *testing.T) {
	v, clk, a, b := armedVault(t)
	v.Arm("j1", clk.t.Add(time.Hour), []string{a})
	v.Lock()
	clk.advance(2 * time.Hour)
	v.Windows()
	if !v.dek.Empty() {
		t.Fatal("DEK still in memory after last window expired")
	}
	if err := v.Unlock(pw("maestra")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(b); err != nil {
		t.Fatalf("Get(b) after re-unlock = %v", err)
	}
}

func TestLockWithoutWindowsDropsDEK(t *testing.T) {
	v, _, _, _ := armedVault(t)
	v.Lock()
	if !v.dek.Empty() {
		t.Fatal("DEK still in memory")
	}
}

func TestLockAllDropsWindows(t *testing.T) {
	v, clk, a, _ := armedVault(t)
	v.Arm("j1", clk.t.Add(time.Hour), []string{a})
	v.LockAll()
	if _, err := v.Get(a); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get = %v", err)
	}
	if len(v.Windows()) != 0 || !v.dek.Empty() {
		t.Fatal("LockAll left state behind")
	}
}

func TestDisarm(t *testing.T) {
	v, clk, a, _ := armedVault(t)
	v.Arm("j1", clk.t.Add(time.Hour), []string{a})
	v.Lock()
	v.Disarm("j1")
	if _, err := v.Get(a); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get after disarm = %v", err)
	}
	if !v.dek.Empty() {
		t.Fatal("DEK kept after last window disarmed")
	}
}

func TestDeletedCredentialInWindow(t *testing.T) {
	v, clk, a, b := armedVault(t)
	v.Arm("j1", clk.t.Add(time.Hour), []string{a, b})
	if err := v.Delete(b); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if _, err := v.Get(b); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(b) = %v", err)
	}
	if _, err := v.Get(a); err != nil {
		t.Fatalf("Get(a) = %v", err)
	}
}

func TestArmRequiresUnlocked(t *testing.T) {
	v, clk, a, _ := armedVault(t)
	v.Lock()
	if err := v.Arm("j", clk.t.Add(time.Hour), []string{a}); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnlockWithWrongPasswordWhileArmed(t *testing.T) {
	v, clk, a, b := armedVault(t)
	v.Arm("j1", clk.t.Add(time.Hour), []string{a})
	v.Lock()
	if err := v.Unlock(pw("mala")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.Get(b); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get(b) = %v", err)
	}
}

func TestArmRejectsEmptyCredentials(t *testing.T) {
	v, clk, _, _ := armedVault(t)
	if err := v.Arm("j", clk.t.Add(time.Hour), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty window kept the DEK alive for nothing: %v", err)
	}
}

func TestWindowsReturnsCopies(t *testing.T) {
	v, clk, a, b := armedVault(t)
	v.Arm("j", clk.t.Add(time.Hour), []string{a})
	w := v.Windows()
	w[0].CredentialIDs[0] = b
	v.Lock()
	if _, err := v.Get(b); !errors.Is(err, ErrLocked) {
		t.Fatal("caller widened a live window through the returned slice")
	}
}

func TestUnlockedAccessor(t *testing.T) {
	v, clk, a, _ := armedVault(t)
	if !v.Unlocked() {
		t.Fatal("fresh vault should be unlocked")
	}
	v.Arm("j", clk.t.Add(time.Hour), []string{a})
	v.Lock()
	if v.Unlocked() {
		t.Fatal("locked with a window must not report unlocked")
	}
}

// El reloj monotónico de Linux no avanza con el sistema suspendido: una ventana con lectura monotónica seguiría
// vigente al despertar. La ventana y la comparación usan solo la hora de pared.
func TestVentanaSinLecturaMonotonica(t *testing.T) {
	v, _, a, _ := armedVault(t)
	v.SetClock(time.Now) // el reloj real trae lectura monotónica
	if err := v.Arm("j", time.Now().Add(time.Hour), []string{a}); err != nil {
		t.Fatal(err)
	}
	ws := v.Windows()
	if len(ws) != 1 || strings.Contains(ws[0].Until.String(), "m=") {
		t.Fatalf("la ventana guarda lectura monotónica: %v", ws)
	}
}
