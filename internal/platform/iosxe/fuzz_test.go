package iosxe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// sigWriter es lo que el driver cree que es el canal hacia el equipo: nunca bloquea y avisa de cada escritura.
type sigWriter chan struct{}

func (w sigWriter) Write(p []byte) (int, error) {
	select {
	case w <- struct{}{}:
	default:
	}
	return len(p), nil
}

// fakeDevice contesta con un trozo por cada escritura del driver (el primero, al abrir). Los trozos salen de los
// bytes del fuzz, separados por 0xFF; al acabarse cierra el flujo, salvo que silent lo deje callado.
func fakeDevice(chunks [][]byte, silent bool) (io.Reader, sigWriter, func()) {
	pr, pw := io.Pipe()
	sig, done := make(sigWriter, 1024), make(chan struct{})
	go func() {
		i := 0
		send := func() {
			if i < len(chunks) {
				pw.Write(chunks[i])
				i++
			} else if !silent {
				pw.Close()
			}
		}
		send()
		for {
			select {
			case <-sig:
				send()
			case <-done:
				return
			}
		}
	}()
	return pr, sig, func() { close(done); pr.Close() }
}

func FuzzDriver(f *testing.F) {
	join := func(parts ...string) []byte { return []byte(strings.Join(parts, "\xff")) }
	f.Add(join("\r\nSW1>", "Password: ", "\r\nSW1#", "terminal length 0\r\nSW1#", "terminal width 0\r\nSW1#",
		"show version\r\nCisco IOS XE\r\n --More-- \r\n\x08\x08        \x08\x08rest\r\nSW1#"), false)
	f.Add(join("\r\nSW1#", "\r\nSW1#", "\r\nSW1#", "show x\r\n% Invalid input detected at '^' marker.\r\nSW1#"), false)
	f.Add(join("\r\nciscoasa> ", "Password: ", "ciscoasa# ", "% Invalid input", "terminal pager 0\r\nciscoasa# ", "x\r\n<--- More --->\r\nciscoasa# "), false)
	f.Add(join("> ", "show version\r\n> ", "x"), false)
	f.Add(join("User: ", "Password: ", "(Cisco Controller) >", "x", "y"), true)
	f.Add(join("login: ", "New password: "), false)
	f.Add([]byte{}, true)
	old := ftdSettle
	ftdSettle = 20 * time.Millisecond // las pausas de FTD no deben dominar el tiempo de cada ejecución
	f.Cleanup(func() { ftdSettle = old })
	f.Fuzz(func(t *testing.T, data []byte, silent bool) {
		if len(data) > 64<<10 {
			return
		}
		chunks := bytes.Split(data, []byte{0xff})
		r, w, stop := fakeDevice(chunks, silent)
		defer stop()
		res := make(chan string, 1)
		go func() {
			d := New()
			defer d.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			if err := d.Open(ctx, r, w, secret.New([]byte("en"))); err != nil {
				res <- ""
				return
			}
			for _, cmd := range []string{"show version", "show clock"} {
				out, err := d.Run(ctx, cmd, 200*time.Millisecond)
				if err != nil {
					break
				}
				if out.Command != cmd || strings.Contains(out.Text, "\r") || strings.Contains(out.Text, "--More--") || strings.Contains(out.Text, "<--- More --->") {
					res <- fmt.Sprintf("salida sin limpiar: %+v", out)
					return
				}
			}
			res <- ""
		}()
		select {
		case m := <-res:
			if m != "" {
				t.Fatal(m)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Open/Run se colgaron más allá de su tope")
		}
	})
}
