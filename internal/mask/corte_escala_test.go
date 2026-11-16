package mask

import (
	"strings"
	"testing"
	"time"
)

// El corte es lineal en segmentos y tramos: una línea 4 veces más grande tarda menos de 10 veces más.
func TestCorteLineal(t *testing.T) {
	best := func(n int) time.Duration {
		in := "%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:enable" + strings.Repeat(" ; key a", n) + "\n"
		min := time.Duration(1<<63 - 1)
		for range 3 {
			start := time.Now()
			Apply("nx-os", in)
			if d := time.Since(start); d < min {
				min = d
			}
		}
		return min
	}
	small, big := best(8000), best(32000) // ~64 KB y ~256 KB
	if big > 10*small {
		t.Fatalf("4 veces más segmentos tardó %v contra %v: no es lineal", big, small)
	}
	t.Logf("64KB %v, 256KB %v", small, big)
}
