package core

import (
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// La vista previa del import no compara contraseñas: una credencial del respaldo idéntica a la viva y otra con la misma
// etiqueta y otra contraseña salen igual («conflicto_etiqueta»). Si no, un respaldo armado con N candidatas probaría la
// contraseña de la viva sin la maestra.
func TestRespaldoPreviewNoComparaContrasenas(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil) // trae «core» con PW-CORE
	_ = h
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	o.put(t, "core", "USR-CORE", "PW-CORE") // idéntica (mismo usuario, contraseña y enable)
	o.put(t, "borde", "USR-BORDE", "OTRA")  // misma etiqueta, otra contraseña
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	e := estados(pr)
	if e["core"] != "conflicto_etiqueta" || e["borde"] != "conflicto_etiqueta" {
		t.Fatalf("estados = %v", e)
	}
	var tc, tb string
	for _, i := range pr.Items {
		switch i.Label {
		case "core":
			tc = i.TargetId
		case "borde":
			tb = i.TargetId
		}
	}
	if tc == "" || tb == "" {
		t.Fatalf("target_id vacío: %q %q", tc, tb)
	}
}
