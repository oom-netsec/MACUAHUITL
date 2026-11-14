package terminal

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// fuzzOps arma una secuencia de operaciones: [op][n][n bytes]… (op%3: 0 Input, 1 Output, 2 línea de syslog con marca).
func fuzzOps(parts ...string) []byte {
	var b []byte
	for i, p := range parts {
		b = append(b, byte((i+1)%2), byte(len(p)))
		b = append(b, p...)
	}
	return b
}

// FuzzRecorder: Input y Output intercalados. Nunca pánico ni cuelgue, y cada línea de syslog
// que el equipo emite aparece exactamente una vez en la grabación.
func FuzzRecorder(f *testing.F) {
	f.Add(fuzzOps("ciscoasa# ", "failover key Secret1\r", "failover key Secret1\r\n", "show clock\r", "show clock\r\n10:00\r\nciscoasa# "))
	f.Add(fuzzOps("SW1#", "enable\r", "Password: ", "hola\r", "SW1#"))
	f.Add(fuzzOps("-----BEGIN RSA PRIVATE KEY-----\r\nabc\r\n", "username u password 0 x\r"))
	f.Add(append(fuzzOps("SW1#", "show x\r"), 2, 0, 1, 3, 'a', '\n', 'b', 2, 0))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		done := make(chan string, 1)
		go func() {
			var sb strings.Builder
			r := NewRecorder(&sb, func() time.Time { return time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC) })
			marks := 0
			for len(data) >= 2 {
				op, n := data[0]%3, int(data[1])
				data = data[2:]
				if n > len(data) {
					n = len(data)
				}
				p := data[:n]
				data = data[n:]
				switch op {
				case 0:
					r.Input(p)
				case 1:
					r.Output(p)
				default:
					r.Output([]byte(fmt.Sprintf("\r\n%%ASA-5-111008: LOGMARK-%d-ZQX\r\n", marks)))
					marks++
				}
			}
			r.Close()
			out := sb.String()
			for i := 0; i < marks; i++ {
				if c := strings.Count(out, fmt.Sprintf("LOGMARK-%d-ZQX\n", i)); c != 1 {
					done <- fmt.Sprintf("LOGMARK-%d aparece %d veces en:\n%s", i, c, out)
					return
				}
			}
			done <- ""
		}()
		select {
		case msg := <-done:
			if msg != "" {
				t.Fatal(msg)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("el Recorder se colgó")
		}
	})
}
