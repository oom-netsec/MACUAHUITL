package devices

import (
	"strings"
	"testing"
)

func h(id, name, addr string) Host {
	x, err := Clean(Host{ID: id, Name: name, Address: addr, Platform: "ios-xe", Folder: "lab", CreatedAt: ahora, UpdatedAt: ahora})
	if err != nil {
		panic(err)
	}
	return x
}

func estados(items []Item) string {
	var s []string
	for _, it := range items {
		s = append(s, it.Estado+"/"+it.Motivo)
	}
	return strings.Join(s, " ")
}

func TestPlanEstados(t *testing.T) {
	guardados := []Host{h("a", "uno", "10.0.0.1"), h("b", "dos", "10.0.0.2"), h("c", "tres", "10.0.0.3")}
	distinto := h("", "uno", "10.0.0.1")
	distinto.Notes = "otra"
	port2 := h("", "uno-p2", "10.0.0.1")
	port2.Port = 2222
	entrante := []Host{
		h("", "uno", "10.0.0.1"),    // igual
		distinto,                    // misma dirección y puerto, otros datos
		h("", "DOS", "10.0.0.99"),   // mismo nombre, otra dirección
		h("", "nuevo", "10.0.0.50"), // nuevo
		port2,                       // mismo host, otro puerto: nuevo
		h("", "tres", "10.0.0.3"),   // igual
		h("", "cuatro", "10.0.0.2"), // dirección de «dos» con otro nombre: conflicto de dirección
	}
	it := Plan(entrante, guardados)
	if got := estados(it); got != "igual/ conflicto/direccion conflicto/nombre nuevo/ nuevo/ igual/ conflicto/direccion" {
		t.Fatalf("estados = %s", got)
	}
	if it[1].Con != "a" || it[2].Con != "b" || it[6].Con != "b" || it[3].Con != "" {
		t.Fatalf("con = %q %q %q", it[1].Con, it[2].Con, it[6].Con)
	}
	// la dirección manda sobre el nombre cuando chocan las dos con hosts distintos
	if it := Plan([]Host{h("", "dos", "10.0.0.1")}, guardados); it[0].Motivo != MotivoDireccion || it[0].Con != "a" {
		t.Fatalf("doble choque: %+v", it[0])
	}
	// otra credencial es otra cosa
	cred := h("", "uno", "10.0.0.1")
	cred.CredentialID = strings.Repeat("ab", 16)
	if it := Plan([]Host{cred}, guardados); it[0].Estado != Conflicto {
		t.Fatalf("credencial distinta = %v", it[0].Estado)
	}
}

func dec(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestApplyDecisiones(t *testing.T) {
	guardados := []Host{h("a", "uno", "10.0.0.1"), h("b", "dos", "10.0.0.2")}
	cambiado := h("", "uno-nuevo", "10.0.0.1")
	cambiado.Notes = "x"
	choqueNombre := h("", "Dos", "10.0.0.20")
	items := Plan([]Host{h("", "tres", "10.0.0.3"), cambiado, choqueNombre}, guardados)

	// faltan decisiones: no se escribe nada
	if _, err := Apply(items, dec(), guardados, ahora); err == nil || !strings.Contains(err.Error(), "falta") {
		t.Fatalf("sin decisión: %v", err)
	}
	r, err := Apply(items, dec("10.0.0.1:22", Reemplazar, "10.0.0.20:22", Renombrar), guardados, ahora)
	if err != nil || r.Created != 1 || r.Replaced != 1 || r.Renamed != 1 || r.Skipped != 0 || len(r.Writes) != 3 {
		t.Fatalf("r = %+v err = %v", r, err)
	}
	byName := map[string]Host{}
	for _, w := range r.Writes {
		byName[w.Name] = w
	}
	if w := byName["uno-nuevo"]; w.ID != "a" || w.Notes != "x" || !w.CreatedAt.Equal(ahora) || w.UpdatedAt.IsZero() {
		t.Fatalf("reemplazo = %+v", w)
	}
	if w := byName["Dos (importado)"]; w.ID == "" || w.ID == "b" || w.Address != "10.0.0.20" {
		t.Fatalf("renombrado = %+v", w)
	}
	if w := byName["tres"]; len(w.ID) != 32 || w.ID == "a" {
		t.Fatalf("nuevo = %+v", w)
	}
	// omitir vale para un conflicto y para un nuevo
	r, err = Apply(items, dec("10.0.0.1:22", Omitir, "10.0.0.20:22", Omitir, "10.0.0.3:22", Omitir), guardados, ahora)
	if err != nil || r.Skipped != 3 || len(r.Writes) != 0 {
		t.Fatalf("omitir: %+v %v", r, err)
	}
	// un «igual» se salta solo
	r, err = Apply(Plan([]Host{h("", "uno", "10.0.0.1")}, guardados), dec(), guardados, ahora)
	if err != nil || r.Skipped != 1 || len(r.Writes) != 0 {
		t.Fatalf("igual: %+v %v", r, err)
	}
}

func TestApplyRechazos(t *testing.T) {
	guardados := []Host{h("a", "uno", "10.0.0.1"), h("b", "dos", "10.0.0.2")}
	porDireccion := h("", "otro", "10.0.0.1")
	porNombre := h("", "dos", "10.0.0.20")
	nuevo := h("", "nuevo", "10.0.0.50")
	igual := h("", "uno", "10.0.0.1")
	casos := []struct {
		nombre  string
		entrada []Host
		d       map[string]string
		quiere  string
	}{
		{"acción desconocida", []Host{porNombre}, dec("10.0.0.20:22", "fusionar"), "desconocida"},
		{"clave que no está", []Host{porNombre}, dec("10.0.0.20:22", Omitir, "1.1.1.1:22", Omitir), "no están"},
		{"renombrar un choque de dirección", []Host{porDireccion}, dec("10.0.0.1:22", Renombrar), "solo"},
		{"reemplazar un nuevo", []Host{nuevo}, dec("10.0.0.50:22", Reemplazar), "solo se puede omitir"},
		{"renombrar un igual", []Host{igual}, dec("10.0.0.1:22", Renombrar), "solo se puede omitir"},
		// reemplazar por dirección con un nombre que ya tiene otro host dejaría dos con el mismo nombre
		{"nombre de otro", []Host{h("", "dos", "10.0.0.1")}, dec("10.0.0.1:22", Reemplazar), "dejaría"},
	}
	for _, c := range casos {
		if _, err := Apply(Plan(c.entrada, guardados), c.d, guardados, ahora); err == nil || !strings.Contains(err.Error(), c.quiere) {
			t.Errorf("%s: err = %v (quería %q)", c.nombre, err, c.quiere)
		}
	}
	// dos entradas que reemplazan al mismo guardado: «uno» por dirección y por nombre
	dosAUno := []Host{h("", "x", "10.0.0.1"), h("", "uno", "10.0.0.77")}
	if _, err := Apply(Plan(dosAUno, guardados), dec("10.0.0.1:22", Reemplazar, "10.0.0.77:22", Reemplazar), guardados, ahora); err == nil || !strings.Contains(err.Error(), "mismo") {
		t.Fatalf("doble reemplazo: %v", err)
	}
	// reemplazar por nombre mueve el host a la dirección del archivo
	r, err := Apply(Plan([]Host{h("", "dos", "10.0.0.9")}, guardados), dec("10.0.0.9:22", Reemplazar), guardados, ahora)
	if err != nil || r.Replaced != 1 || r.Writes[0].ID != "b" || r.Writes[0].Address != "10.0.0.9" {
		t.Fatalf("mover: %+v %v", r, err)
	}
	// el renombrado no toma el nombre de otro host del archivo
	entrante := []Host{h("", "dos", "10.0.0.20"), h("", "dos (importado)", "10.0.0.21")}
	r, err = Apply(Plan(entrante, guardados), dec("10.0.0.20:22", Renombrar), guardados, ahora)
	if err != nil || r.Writes[0].Name != "dos (importado 2)" {
		t.Fatalf("renombrado repetido: %+v %v", r.Writes, err)
	}
	// el renombrado recorta la base para no pasar de 64
	largo := h("", strings.Repeat("n", 64), "10.0.0.30")
	g2 := append([]Host{h("z", strings.Repeat("n", 64), "10.0.0.31")}, guardados...)
	r, err = Apply(Plan([]Host{largo}, g2), dec("10.0.0.30:22", Renombrar), g2, ahora)
	if err != nil || len([]rune(r.Writes[0].Name)) > MaxHostName || !strings.HasSuffix(r.Writes[0].Name, "(importado)") {
		t.Fatalf("recorte: %+v %v", r.Writes, err)
	}
}
