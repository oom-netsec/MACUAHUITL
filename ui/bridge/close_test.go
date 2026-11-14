package bridge

import (
	"context"
	"testing"
)

func TestBusyCuentaLoQueSeCortaAlCerrar(t *testing.T) {
	b := New(nil, func(string, any) {})
	if Busy(b) {
		t.Fatal("sin nada en curso no debe avisar")
	}
	b.streams["job1"] = &stream{} // un trabajo de Patrol sigue en el núcleo: no cuenta
	if Busy(b) {
		t.Fatal("una suscripción de Patrol no corta nada al cerrar")
	}
	b.runs["r1"] = context.CancelFunc(func() {})
	if !Busy(b) {
		t.Fatal("una ejecución con stream se corta al cerrar")
	}
	delete(b.runs, "r1")
	b.assists["a1"] = &stream{}
	if !Busy(b) {
		t.Fatal("un cambio asistido en curso debe avisar")
	}
	delete(b.assists, "a1")
	b.terminals = map[string]*termSess{"t1": {}}
	if !Busy(b) {
		t.Fatal("una terminal abierta debe avisar")
	}
}

func TestCloseTextSigueElIdiomaDeLaInterfaz(t *testing.T) {
	b := New(nil, func(string, any) {})
	b.setLanguage("es")
	if got := CloseTextFor(b); got.Quit != "Cerrar igual" || got.Stay != "Cancelar" {
		t.Fatalf("es: %+v", got)
	}
	b.setLanguage("en")
	if got := CloseTextFor(b); got.Quit != "Close anyway" || got.Title != "Close MACUAHUITL?" {
		t.Fatalf("en: %+v", got)
	}
}
