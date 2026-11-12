package syslogd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
)

func TestFormats(t *testing.T) {
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	m := Message{Time: at, From: "192.0.2.1:514", Raw: "<189>1: %LINK-3-UPDOWN: Gi1 down", Text: "<189>1: %LINK-3-UPDOWN: Gi1 down", Facility: -1, Severity: -1}
	m.Mnemonic = "LINK-3-UPDOWN"
	cases := map[string]struct{ ext, want string }{
		"":      {".log", "2026-11-07T12:00:00Z 192.0.2.1:514 <189>1: %LINK-3-UPDOWN: Gi1 down\n"},
		"texto": {".log", "2026-11-07T12:00:00Z 192.0.2.1:514 <189>1: %LINK-3-UPDOWN: Gi1 down\n"},
		"crudo": {".log", "<189>1: %LINK-3-UPDOWN: Gi1 down\n"},
	}
	one := func(f string) (dir, name string) {
		dir = filepath.Join(t.TempDir(), "syslog")
		w, err := ingest.NewWriter(ingest.Sink{Dir: dir, Template: "syslog_{fecha}_{hora}", MaxFiles: 100, Format: f}, func() time.Time { return at })
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Write(m); err != nil {
			t.Fatal(err)
		}
		w.Close()
		es, _ := os.ReadDir(dir)
		if len(es) != 1 {
			t.Fatalf("%q: archivos %v", f, es)
		}
		return dir, es[0].Name()
	}
	for f, c := range cases {
		dir, name := one(f)
		if !strings.HasSuffix(name, c.ext) {
			t.Fatalf("%q: archivo %v", f, name)
		}
		got, _ := os.ReadFile(filepath.Join(dir, name))
		if string(got) != c.want {
			t.Errorf("%q: %q", f, got)
		}
	}
	dir, name := one("jsonl")
	if !strings.HasSuffix(name, ".jsonl") {
		t.Fatalf("jsonl: %v", name)
	}
	b, _ := os.ReadFile(filepath.Join(dir, name))
	var back Message
	if err := json.Unmarshal(b, &back); err != nil || back.Mnemonic != "LINK-3-UPDOWN" || back.From != "192.0.2.1:514" || !strings.HasSuffix(string(b), "}\n") {
		t.Fatalf("jsonl = %q (%v)", b, err)
	}
}
