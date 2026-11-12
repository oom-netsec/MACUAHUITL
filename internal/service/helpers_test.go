package service

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// Revisión final: el receptor syslog siempre tiene duración máxima.
func TestSyslogDurationIsCapped(t *testing.T) {
	for in, want := range map[int32]time.Duration{0: time.Hour, 30: 30 * time.Second, 999999: 24 * time.Hour} {
		if got := SyslogDuration(in); got != want {
			t.Errorf("SyslogDuration(%d) = %v, want %v", in, got, want)
		}
	}
}

// La llave que firma las fichas de los respaldos vive en la bóveda y se crea la primera vez.
func TestBackupKeyIsCreatedOnceAndStaysInTheVault(t *testing.T) {
	vault.MinMemoryKiB = 8192
	v, err := vault.Create(filepath.Join(t.TempDir(), "v.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.LockAll)
	if _, err := BackupKey(v, false); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("sin crear, no inventa una llave: %v", err)
	}
	k1, err := BackupKey(v, true)
	if err != nil || len(k1) != 32 {
		t.Fatalf("k1=%d err=%v", len(k1), err)
	}
	k2, err := BackupKey(v, true)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("la segunda vez devuelve la misma llave: %v", err)
	}
	if infos, _ := v.List(); len(infos) != 0 {
		t.Errorf("la llave es una entrada reservada: no sale en la lista de credenciales: %v", infos)
	}
	v.LockAll()
	if _, err := BackupKey(v, true); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("con la bóveda cerrada no hay llave: %v", err)
	}
}
