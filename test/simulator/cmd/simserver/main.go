// Command simserver levanta el simulador SSH en 127.0.0.1 y espera. Solo para el job windows-e2e (tools/ci/windows-e2e.ps1):
// escribe «host:puerto» en -addrfile cuando ya escucha y no termina hasta que lo maten.
package main

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// tb cumple testing.TB fuera de una prueba: el simulador solo usa Helper, Fatal y Cleanup (los cierres mueren con el proceso).
type tb struct{ testing.TB }

func (tb) Helper()                   {}
func (tb) Cleanup(func())            {}
func (tb) Fatal(a ...any)            { fmt.Fprintln(os.Stderr, a...); os.Exit(1) }
func (tb) Fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func main() {
	transcripts := flag.String("transcripts", "", "carpeta de transcripciones (test/transcripts/ios-xe)")
	addrFile := flag.String("addrfile", "", "archivo donde escribir host:puerto al estar listo")
	flag.Parse()
	if *transcripts == "" || *addrFile == "" {
		fmt.Fprintln(os.Stderr, "uso: simserver -transcripts DIR -addrfile ARCHIVO")
		os.Exit(2)
	}
	addr, _ := simulator.Start(tb{}, simulator.Config{Hostname: "SW-LAB-01", Username: "admin", Password: "pw-lab", Enable: "en-lab", Transcripts: *transcripts})
	// Atómico: el script nunca lee un archivo a medio escribir.
	tmp := *addrFile + ".tmp"
	err := os.WriteFile(tmp, []byte(addr), 0o644)
	if err == nil {
		err = os.Rename(tmp, *addrFile)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	select {}
}
