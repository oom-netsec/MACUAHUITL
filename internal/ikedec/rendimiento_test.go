package ikedec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecodeRendimiento1MiB(t *testing.T) {
	fs, _ := filepath.Glob("testdata/*.txt")
	var b strings.Builder
	for b.Len() < 1<<20 {
		for _, f := range fs {
			x, _ := os.ReadFile(f)
			b.Write(x)
		}
	}
	t0 := time.Now()
	if _, err := DecodeContext(context.Background(), b.String()[:1<<20]); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > 8*time.Second {
		t.Fatalf("1 MiB tardó %v (máx 8 s bajo carga y -race; antes ~25 s)", d)
	}
}

func TestDecodeContextCancelado(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeContext(ctx, strings.Repeat("ISAKMP:(0): retransmitting phase 1 MM_KEY_EXCH\n", 1000)); err == nil {
		t.Fatal("se esperaba error de contexto cancelado")
	}
}

func TestDecodeTopeDeSAs(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxSAs+7; i++ {
		fmt.Fprintf(&b, "10.0.%d.%d 10.1.0.1 QM_IDLE 1001 ACTIVE\n", i/250, i%250)
	}
	r := Decode(b.String())
	if len(r.SAs) != maxSAs {
		t.Fatalf("SAs=%d, se esperaban %d", len(r.SAs), maxSAs)
	}
	for _, f := range r.Findings {
		if f.Code == "limite-sas" && strings.Contains(f.Explanation, "se omitieron 7 SAs IKE") {
			return
		}
	}
	t.Fatalf("falta el aviso de SAs omitidas: %+v", r.Findings)
}
