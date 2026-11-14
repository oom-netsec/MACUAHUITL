package scripts_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
)

// Insert nunca reemplaza (el import del paquete personal); Put sí; los dos van por la misma lista de columnas.
func TestInsertNoReemplazaYPutSi(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	s := scripts.Script{ID: "u1", Name: "Uno", Tech: "l3", Platform: "ios", Description: "d", Commands: []string{"show clock"}, Tags: []string{"a"}, CreatedAt: at, UpdatedAt: at}
	if err := scripts.Insert(db, s); err != nil {
		t.Fatal(err)
	}
	s.Name = "Otro"
	if err := scripts.Insert(db, s); err == nil {
		t.Fatal("Insert reemplazó un ID repetido")
	}
	if err := scripts.Put(db, s); err != nil {
		t.Fatal(err)
	}
	got, err := scripts.GetUser(db, "u1")
	if err != nil || got.Name != "Otro" || got.Origin != scripts.OrigenUsuario || !got.CreatedAt.Equal(at) || len(got.Commands) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if l, err := scripts.LoadUser(db); err != nil || len(l) != 1 {
		t.Fatalf("%v %v", l, err)
	}
}
