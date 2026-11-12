package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestNewWipesSource(t *testing.T) {
	src := []byte("hunter2")
	s := New(src)
	defer s.Destroy()
	if !bytes.Equal(src, make([]byte, 7)) {
		t.Fatalf("source not wiped: %q", src)
	}
}

func TestBytesRoundTrip(t *testing.T) {
	s := New([]byte("abc"))
	defer s.Destroy()
	if got := string(s.Bytes()); got != "abc" {
		t.Fatalf("Bytes() = %q", got)
	}
}

func TestDestroyIdempotent(t *testing.T) {
	s := New([]byte("abc"))
	s.Destroy()
	s.Destroy()
	if s.Bytes() != nil {
		t.Fatal("Bytes() after Destroy should be nil")
	}
	var n *Secret
	n.Destroy()
	if !n.Empty() {
		t.Fatal("nil Secret should be Empty")
	}
}

func TestEmpty(t *testing.T) {
	if !New(nil).Empty() || !New([]byte{}).Empty() {
		t.Fatal("empty input should be Empty")
	}
	if New([]byte("x")).Empty() {
		t.Fatal("non-empty reported Empty")
	}
}

func TestRedactionEverywhere(t *testing.T) {
	const marker = "MARKER-9f3a"
	s := New([]byte(marker))
	defer s.Destroy()
	wrap := struct{ P *Secret }{s}

	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("x", "p", s)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("x", "p", s)
	j, err := json.Marshal(wrap)
	if err != nil {
		t.Fatal(err)
	}

	outs := map[string]string{
		"Sprint":   fmt.Sprint(s),
		"verbs":    fmt.Sprintf("%v %s %+v %#v %q %x %X", s, s, s, s, s, s, s),
		"struct":   fmt.Sprintf("%+v %#v", wrap, wrap),
		"json":     string(j),
		"slogText": text.String(),
		"slogJSON": js.String(),
	}
	for name, out := range outs {
		if strings.Contains(out, marker) || strings.Contains(out, fmt.Sprintf("%x", marker)) {
			t.Errorf("%s leaked secret: %s", name, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s missing %s: %s", name, Redacted, out)
		}
	}
}
