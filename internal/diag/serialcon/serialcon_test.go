package serialcon

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestRecorderStampsEachLine(t *testing.T) {
	var b bytes.Buffer
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	r := NewRecorder(&b, func() time.Time { return now })
	r.Mark("abierto /dev/ttyUSB0 9600 8N1")
	io.WriteString(r, "Switch>sh")
	io.WriteString(r, "ow ver\r\nCisco IOS\r\n")
	r.Mark("BREAK")
	io.WriteString(r, "rommon 1 >")
	want := "2026-11-04T10:00:00.000Z ### abierto /dev/ttyUSB0 9600 8N1\n" +
		"2026-11-04T10:00:00.000Z Switch>show ver\n" +
		"2026-11-04T10:00:00.000Z Cisco IOS\n" +
		"2026-11-04T10:00:00.000Z ### BREAK\n" +
		"2026-11-04T10:00:00.000Z rommon 1 >"
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

// AuditString va junto a String: mismo formato de línea pero con la clave en inglés para la bitácora.
func TestConfigAuditString(t *testing.T) {
	c := Config{Baud: 9600, DataBits: 8, Parity: "n", StopBits: 1, Flow: "none"}
	if got, want := c.AuditString(), "9600 8N1 flow=none"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
