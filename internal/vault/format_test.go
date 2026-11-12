package vault

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	var h header
	rand.Read(h.VaultID[:])
	rand.Read(h.Salt[:])
	rand.Read(h.DEKNonce[:])
	rand.Read(h.DEKCipher[:])
	h.Params = Params{MemoryKiB: 8192, Iterations: 2, Threads: 3}
	b := marshalFile(h, nil)
	if len(b) != headerLen {
		t.Fatalf("len = %d, want %d", len(b), headerLen)
	}
	got, entries, err := parseFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != h || len(entries) != 0 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestParseGarbage(t *testing.T) {
	random := make([]byte, headerLen)
	rand.Read(random)
	hugeN := marshalFile(header{Params: Params{8192, 1, 1}}, nil)
	binary.BigEndian.PutUint32(hugeN[107:], 1<<31)
	for name, b := range map[string][]byte{
		"empty": {}, "10B": make([]byte, 10), "random": random, "hugeN": hugeN,
	} {
		p := filepath.Join(t.TempDir(), "v.mcv")
		os.WriteFile(p, b, 0o600)
		if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err = %v, want ErrCorrupt", name, err)
		}
	}
}

func TestParseRejectsHostileParams(t *testing.T) {
	for _, p := range []Params{
		{MemoryKiB: 4194305, Iterations: 1, Threads: 1},
		{MemoryKiB: 8192, Iterations: 0, Threads: 1},
		{MemoryKiB: 8192, Iterations: 11, Threads: 1},
		{MemoryKiB: 8192, Iterations: 1, Threads: 0},
		{MemoryKiB: 8192, Iterations: 1, Threads: 17},
	} {
		if _, _, err := parseFile(marshalFile(header{Params: p}, nil)); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%+v: err = %v, want ErrCorrupt", p, err)
		}
	}
}
