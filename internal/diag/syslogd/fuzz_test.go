package syslogd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

var syslogSeeds = []string{
	"<189>123: *Nov  4 10:00:00.123: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down",
	"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
	"<189>1: %SYS-5-CONFIG_I: Configured from console",
	"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\"] BOMAn application event",
	"<13>1 - - - - - -", "<191>", "<0>", "<192>x", "plain text", "", "<5>Jan  1 00:00:00 h a[1]: m", "\x1b[31m<1>1 a b c d e [x\\]]",
}

func FuzzParse(f *testing.F) {
	for _, s := range syslogSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		m := Parse(raw)
		if !utf8.ValidString(m.Raw) || !utf8.ValidString(m.Text) {
			t.Fatalf("UTF-8 inválido: %q", m.Raw)
		}
		if strings.ContainsFunc(m.Raw, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
			t.Fatalf("Raw con caracteres de control: %q", m.Raw)
		}
		if m.Facility < -1 || m.Facility > 23 || m.Severity < -1 || m.Severity > 7 || (m.Facility < 0) != (m.Severity < 0) {
			t.Fatalf("PRI fuera de rango: %d/%d", m.Facility, m.Severity)
		}
		// Text y los campos salen del propio mensaje: nunca texto inventado.
		for _, s := range []string{m.Text, m.Host, m.App, m.Mnemonic} {
			if !strings.Contains(m.Raw, s) && !(m.Format == "rfc5424" && s == m.Text) {
				t.Fatalf("%q no sale de %q", s, m.Raw)
			}
		}
		// La línea de salida es una sola, en cualquier formato (sin inyección de líneas al archivo).
		for _, fm := range []string{"", "crudo", "jsonl"} {
			l := m.Line(fm)
			if bytes.Count(l, []byte("\n")) != 1 || l[len(l)-1] != '\n' {
				t.Fatalf("%q: línea mal formada %q", fm, l)
			}
		}
		var back Message
		if err := json.Unmarshal(m.Line("jsonl"), &back); err != nil || back.Raw != m.Raw {
			t.Fatalf("jsonl no vuelve: %v", err)
		}
	})
}

// FuzzReadStream (con el tamaño de búfer de listenTCP): un flujo TCP arbitrario (conteo de octetos o líneas) no entra en pánico, termina y cada
// mensaje respeta el tope.
func FuzzReadStream(f *testing.F) {
	for _, s := range syslogSeeds {
		f.Add([]byte(s + "\n"))
		f.Add([]byte(strings.Repeat("9", 3) + " " + s))
	}
	f.Add([]byte("5 hello5 world\n\n\r\n99999999999 x"))
	f.Fuzz(func(t *testing.T, in []byte) {
		n := 0
		readStream(bufio.NewReaderSize(bytes.NewReader(in), MaxMessage+16), "x", func(_ string, msg []byte, _ bool) {
			if n++; len(msg) > MaxMessage {
				t.Fatalf("mensaje de %d bytes pasa el tope", len(msg))
			}
			if n > len(in)+1 {
				t.Fatalf("más mensajes (%d) que bytes (%d)", n, len(in))
			}
		})
	})
}

// Regresión del fuzz: «<-1>» daba Facility 0 y Severity -1 (Atoi acepta signo); el PRI son solo dígitos.
func TestParsePRISoloDigitos(t *testing.T) {
	for _, s := range []string{"<-1>x", "<+5>x", "<-0>x", "< 5>x", "<>x"} {
		if m := Parse([]byte(s)); m.Facility != -1 || m.Severity != -1 || m.Text != s {
			t.Errorf("%q: %+v", s, m)
		}
	}
	if m := Parse([]byte("<13>x")); m.Facility != 1 || m.Severity != 5 {
		t.Errorf("<13>: %+v", m)
	}
}
