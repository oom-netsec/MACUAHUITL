package cli

import (
	"strings"
	"testing"
)

func TestAcceptKeys(t *testing.T) {
	fps, keys, err := AcceptKeys([]string{"SHA256:a"}, []string{"sw1:22"})
	if err != nil || len(fps) != 0 || len(keys) != 1 || keys[0].Host != "sw1:22" || keys[0].Fingerprint != "SHA256:a" {
		t.Fatalf("un destino: %v %v %v", fps, keys, err)
	}
	if _, _, err = AcceptKeys([]string{"SHA256:a"}, []string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "SHA256:a") {
		t.Fatalf("varios destinos: %v", err)
	}
	fps, keys, err = AcceptKeys([]string{"SHA256:a", "b:2222=SHA256:b"}, nil)
	if err != nil || len(fps) != 1 || len(keys) != 1 || keys[0].Host != "b:2222" {
		t.Fatalf("destinos que resuelve el núcleo: %v %v %v", fps, keys, err)
	}
	if _, keys, err = AcceptKeys([]string{"a=SHA256:a", "[::1]:22=SHA256:b"}, []string{"a", "b"}); err != nil || len(keys) != 2 {
		t.Fatalf("pares con varios destinos: %v %v", keys, err)
	}
	for _, bad := range []string{"", "=SHA256:a", "a="} {
		if _, _, err = AcceptKeys([]string{bad}, nil); err == nil {
			t.Errorf("%q debía fallar", bad)
		}
	}
	if got := HostPort("::1", 22) + HostPort("sw", 0); got != "[::1]:22sw" {
		t.Fatalf("HostPort = %q", got)
	}
}
