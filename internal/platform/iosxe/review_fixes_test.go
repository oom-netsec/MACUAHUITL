package iosxe

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func TestEnableFailedIOSRePrompt(t *testing.T) {
	start := time.Now()
	_, err := open(t, simulator.Config{}, "mala", context.Background())
	if !errors.Is(err, platform.ErrEnableFailed) || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestEnableEmptySecret(t *testing.T) {
	start := time.Now()
	_, err := open(t, simulator.Config{}, "", context.Background())
	if !errors.Is(err, platform.ErrEnableFailed) || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestNoStaleOutputAfterTimeout(t *testing.T) {
	d, err := open(t, simulator.Config{SlowCommand: "show lento", SlowDelay: 300 * time.Millisecond}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), "show lento", 100*time.Millisecond); !errors.Is(err, platform.ErrPromptTimeout) {
		t.Fatalf("first run err = %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	out, err := d.Run(context.Background(), "show version", 2*time.Second)
	if err == nil {
		t.Fatalf("driver reused after timeout; got output %q", out.Text)
	}
}

func TestPumpExitsWhenDriverFails(t *testing.T) {
	r, w := io.Pipe()
	d := &driver{chunks: make(chan []byte, 1), readErr: make(chan error, 1), quit: make(chan struct{})}
	done := make(chan struct{})
	go func() { d.pump(r); close(done) }()
	d.fail(errors.New("x"))
	go func() {
		for i := 0; i < 10; i++ {
			w.Write(make([]byte, 4096))
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pump blocked after the driver failed")
	}
}
