package devices

import (
	"strings"
	"testing"
	"time"
)

func TestMergeFusionaPorDireccion(t *testing.T) {
	vista := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	found := []Device{
		{Address: "10.0.0.1", Hostname: "SW1", Platform: "ios", LastSeen: vista, Sources: []string{SrcPatrol, SrcFlota}},
		{Address: "10.0.0.2", Hostname: "SW2", Platform: "ios-xe", Sources: []string{SrcPatrol}},
		{Address: "", Hostname: "SW9", Sources: []string{SrcRespaldos}},
	}
	m1 := h("m1", "core", "10.0.0.1")
	m1.Platform = "nx-os"
	m2 := h("m2", "Acceso", "10.0.0.2")
	m2.Platform = ""
	m3 := h("m3", "solo-manual", "sw3.lab")
	m4 := h("m4", "core-p2", "10.0.0.1") // misma dirección, otro puerto: fila aparte
	m4.Port = 2222
	es := Merge(found, []Host{m4, m3, m2, m1})
	if len(es) != 5 {
		t.Fatalf("filas = %d: %+v", len(es), es)
	}
	// orden de siempre: IPv4 por valor, luego nombres DNS, al final lo que no tiene dirección
	var dir []string
	for _, e := range es {
		dir = append(dir, e.Address+"/"+e.Hostname)
	}
	if got := strings.Join(dir, " "); got != "10.0.0.1/core 10.0.0.1/core-p2 10.0.0.2/Acceso sw3.lab/solo-manual /SW9" {
		t.Fatalf("orden = %s", got)
	}
	// el nombre y la plataforma del manual mandan; la evidencia y las fuentes se conservan
	a := es[0]
	if a.Host == nil || a.Host.ID != "m1" || a.Platform != "nx-os" || !a.LastSeen.Equal(vista) || strings.Join(a.Sources, ",") != "patrol,flota,manual" {
		t.Fatalf("fusionado = %+v", a)
	}
	// sin plataforma en el manual se queda la descubierta
	if b := es[2]; b.Platform != "ios-xe" || strings.Join(b.Sources, ",") != "patrol,manual" {
		t.Fatalf("plataforma = %+v", b)
	}
	// el segundo manual con la misma dirección no se funde con la evidencia (ya la tomó el primero)
	if c := es[1]; c.Host.ID != "m4" || strings.Join(c.Sources, ",") != "manual" || c.LastSeen != (time.Time{}) {
		t.Fatalf("segundo = %+v", c)
	}
	if d := es[3]; d.Host.ID != "m3" || d.Sources[0] != SrcManual {
		t.Fatalf("solo manual = %+v", d)
	}
	if r := es[4]; r.Host != nil || r.Hostname != "SW9" {
		t.Fatalf("descubierto = %+v", r)
	}
	// sin hosts, la lista es la misma
	if sin := Merge(found, nil); len(sin) != 3 || sin[0].Host != nil || strings.Join(sin[0].Sources, ",") != "patrol,flota" {
		t.Fatalf("sin hosts = %+v", sin)
	}
	// la dirección descubierta se compara canónica (IPv6 en mayúsculas)
	if v6 := Merge([]Device{{Address: "2001:DB8::1", Hostname: "x", Sources: []string{SrcFlota}}}, []Host{h("m", "v6", "2001:db8::1")}); len(v6) != 1 || v6[0].Hostname != "v6" {
		t.Fatalf("v6 = %+v", v6)
	}
}

func TestFilterEntries(t *testing.T) {
	m1 := h("m1", "core", "10.0.0.1")
	m1.Tags = []string{"dc-1", "core"}
	m2 := h("m2", "acceso", "10.0.0.2")
	m2.Folder = "Oficina 2"
	es := Merge([]Device{{Address: "10.0.0.3", Hostname: "descubierto", Sources: []string{SrcFlota}}}, []Host{m1, m2})
	n := func(q, f, tag string) int { return len(FilterEntries(es, q, f, tag)) }
	if n("", "", "") != 3 || n("CORE", "", "") != 1 || n("10.0.0.", "", "") != 3 || n("oficina", "", "") != 1 || n("dc-1", "", "") != 1 {
		t.Fatalf("texto: %d %d %d %d %d", n("", "", ""), n("CORE", "", ""), n("10.0.0.", "", ""), n("oficina", "", ""), n("dc-1", "", ""))
	}
	if n("", "lab", "") != 1 || n("", "OFICINA 2", "") != 1 || n("", "nada", "") != 0 {
		t.Fatalf("carpeta: %d %d %d", n("", "lab", ""), n("", "OFICINA 2", ""), n("", "nada", ""))
	}
	if n("", "", "core") != 1 || n("", "", "dc") != 0 || n("core", "lab", "dc-1") != 1 || n("acceso", "lab", "") != 0 {
		t.Fatal("etiqueta o combinación")
	}
}
