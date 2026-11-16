package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Al abrir el canal el núcleo borra la causa de un arranque fallido anterior.
func TestRunBorraLaCausaAlAbrirElCanal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root")
	}
	d := t.TempDir()
	for k, v := range map[string]string{"XDG_RUNTIME_DIR": "run", "XDG_STATE_HOME": "state", "XDG_DATA_HOME": "data", "XDG_CONFIG_HOME": "cfg", "XDG_CACHE_HOME": "cache"} {
		os.MkdirAll(filepath.Join(d, v), 0o700)
		t.Setenv(k, filepath.Join(d, v))
	}
	t.Setenv("HOME", d)
	st := filepath.Join(d, "state", "macuahuitl")
	sys.WriteStartup(st, os.ErrInvalid)
	file := filepath.Join(st, sys.StartupName)
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("la prueba no armó el archivo: %v", err)
	}
	sig := make(chan os.Signal, 1) // absorbe la interrupción si llega antes de que run lo escuche
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	done := make(chan error, 1)
	go func() { done <- run(func() ([]i18n.Text, error) { return nil, nil }) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(file); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, statErr := os.Stat(file)
	// El archivo se borra al abrir el canal, antes de que run escuche las señales (core.New va después y con -race es
	// lento): se reenvía la interrupción hasta que run termine.
	p, _ := os.FindProcess(os.Getpid())
	stop := time.After(60 * time.Second)
	for finished := false; !finished; {
		p.Signal(os.Interrupt)
		select {
		case <-done:
			finished = true
		case <-time.After(200 * time.Millisecond):
		case <-stop:
			t.Fatal("run no terminó")
		}
	}
	if statErr == nil {
		t.Fatal("el archivo .startup sigue ahí tras abrir el canal")
	}
}
