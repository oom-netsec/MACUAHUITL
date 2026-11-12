package devices

import (
	"strings"
	"testing"
)

func TestCleanReglas(t *testing.T) {
	bueno := Host{Name: "SW-CORE", Address: "10.0.0.1", Platform: "ios-xe", Folder: "Lab 1", Tags: []string{"core", "dc-1"}, Notes: "uno\ndos"}
	h, err := Clean(bueno)
	if err != nil || h.Port != 22 {
		t.Fatalf("h = %+v err = %v (el puerto por defecto es 22)", h, err)
	}
	largo := strings.Repeat("a", 65)
	etiquetas := make([]string, 11)
	for i := range etiquetas {
		etiquetas[i] = "t" + string(rune('a'+i))
	}
	casos := []struct {
		nombre string
		mod    func(*Host)
		valido bool
	}{
		{"nombre de 64", func(h *Host) { h.Name = strings.Repeat("n", 64) }, true},
		{"nombre vacío", func(h *Host) { h.Name = "" }, false},
		{"nombre de 65", func(h *Host) { h.Name = largo }, false},
		{"nombre con espacio al borde", func(h *Host) { h.Name = " x" }, false},
		{"nombre con control", func(h *Host) { h.Name = "a\x00b" }, false},
		{"IPv6", func(h *Host) { h.Address = "2001:DB8::1" }, true},
		{"DNS", func(h *Host) { h.Address = "sw1.lab.example.com" }, true},
		{"DNS corto", func(h *Host) { h.Address = "sw1" }, true},
		{"dirección vacía", func(h *Host) { h.Address = "" }, false},
		{"dirección con espacio", func(h *Host) { h.Address = "10.0.0. 1" }, false},
		{"dirección con arroba", func(h *Host) { h.Address = "admin@10.0.0.1" }, false},
		{"dirección con esquema", func(h *Host) { h.Address = "ssh://10.0.0.1" }, false},
		{"dirección con puerto pegado", func(h *Host) { h.Address = "10.0.0.1:22" }, false},
		{"dirección con barra", func(h *Host) { h.Address = "sw1/x" }, false},
		{"IPv4 imposible", func(h *Host) { h.Address = "10.0.0.256" }, false},
		{"DNS con guion al inicio", func(h *Host) { h.Address = "-sw1.lab" }, false},
		{"DNS con guion bajo", func(h *Host) { h.Address = "sw_1.lab" }, false},
		{"IPv6 con zona", func(h *Host) { h.Address = "fe80::1%eth0" }, false},
		{"puerto 1", func(h *Host) { h.Port = 1 }, true},
		{"puerto 65535", func(h *Host) { h.Port = 65535 }, true},
		{"puerto 65536", func(h *Host) { h.Port = 65536 }, false},
		{"puerto negativo", func(h *Host) { h.Port = -1 }, false},
		{"sin plataforma", func(h *Host) { h.Platform = "" }, true},
		{"plataforma wlc", func(h *Host) { h.Platform = "wlc" }, true},
		{"plataforma fuera de la lista", func(h *Host) { h.Platform = "junos" }, false},
		{"carpeta de 48", func(h *Host) { h.Folder = strings.Repeat("c", 48) }, true},
		{"carpeta de 49", func(h *Host) { h.Folder = strings.Repeat("c", 49) }, false},
		{"carpeta con barra", func(h *Host) { h.Folder = "a/b" }, false},
		{"carpeta con espacio al borde", func(h *Host) { h.Folder = "a " }, false},
		{"10 etiquetas", func(h *Host) { h.Tags = etiquetas[:10] }, true},
		{"11 etiquetas", func(h *Host) { h.Tags = etiquetas }, false},
		{"etiqueta con mayúscula", func(h *Host) { h.Tags = []string{"Core"} }, false},
		{"etiqueta de 25", func(h *Host) { h.Tags = []string{strings.Repeat("a", 25)} }, false},
		{"etiqueta repetida", func(h *Host) { h.Tags = []string{"a", "a"} }, false},
		{"notas de 2000", func(h *Host) { h.Notes = strings.Repeat("ñ", 2000) }, true},
		{"notas de 2001", func(h *Host) { h.Notes = strings.Repeat("ñ", 2001) }, false},
		{"notas con control", func(h *Host) { h.Notes = "a\x07" }, false},
		{"credencial válida", func(h *Host) { h.CredentialID = strings.Repeat("ab", 16) }, true},
		{"credencial mal formada", func(h *Host) { h.CredentialID = "hunter2" }, false},
	}
	for _, c := range casos {
		h := bueno
		c.mod(&h)
		if _, err := Clean(h); (err == nil) != c.valido {
			t.Errorf("%s: err = %v", c.nombre, err)
		}
	}
	// canónico: IPv6 y DNS en minúsculas; la clave no distingue mayúsculas
	a, _ := Clean(Host{Name: "a", Address: "2001:DB8:0::1"})
	d, _ := Clean(Host{Name: "d", Address: "SW1.Lab"})
	if a.Address != "2001:db8::1" || d.Address != "sw1.lab" || Key(a) != "2001:db8::1:22" || NameKey("Ab") != NameKey("aB") {
		t.Fatalf("a = %q d = %q key = %q", a.Address, d.Address, Key(a))
	}
}
