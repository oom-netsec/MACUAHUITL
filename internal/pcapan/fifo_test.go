package pcapan

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

func TestAnalyzeFIFONoCuelga(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tubo")
	if err := sys.Mkfifo(p); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Analyze(context.Background(), p, Options{}); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("una FIFO debe rechazarse")
		}
	case <-time.After(time.Second):
		t.Fatal("Analyze se colgó con una FIFO")
	}
}
