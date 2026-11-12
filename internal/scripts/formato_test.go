package scripts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var libMuestra = []Script{{ID: "lib-l2-stp", Name: "L2 · STP", Tech: "l2", Platform: "ios-xe", Commands: []string{"show spanning-tree"}, Tags: []string{}, Origin: OrigenBiblioteca}}

func TestPlantillaScriptsPasaElImport(t *testing.T) {
	b, err := Plantilla(KindScripts, libMuestra, ahora)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sha256") {
		t.Error("la plantilla no lleva sha256")
	}
	scs, avisos, err := ParseAvisos(b)
	if err != nil || len(scs) != 3 || len(avisos) != 1 || avisos[0] != AvisoSinSuma {
		t.Fatalf("parse: %d %v %v", len(scs), avisos, err)
	}
	var lectura, config, conTags int
	for _, s := range scs {
		switch {
		case len(s.Tags) > 0:
			conTags++
		case s.ReadOnly():
			lectura++
		default:
			config++
		}
	}
	if lectura != 1 || config != 1 || conTags != 1 {
		t.Errorf("lectura=%d config=%d con etiquetas=%d", lectura, config, conTags)
	}
	// determinista
	b2, _ := Plantilla(KindScripts, libMuestra, ahora)
	if string(b) != string(b2) {
		t.Error("la plantilla debe ser estable")
	}
}

func TestPlantillaColeccionesPasaElImport(t *testing.T) {
	b, err := Plantilla(KindColecciones, libMuestra, ahora)
	if err != nil {
		t.Fatal(err)
	}
	cols, scs, avisos, err := ParseColeccionesAvisos(b)
	if err != nil || len(cols) != 1 || len(scs) != 2 || len(avisos) != 1 || avisos[0] != AvisoSinSuma {
		t.Fatalf("parse: %v %v %v", cols, avisos, err)
	}
	var libs int
	for _, id := range cols[0].ScriptIDs {
		if IsLib(id) {
			libs++
			if id != "lib-l2-stp" {
				t.Errorf("el lib-* debe ser uno real de la biblioteca: %s", id)
			}
		}
	}
	if len(cols[0].ScriptIDs) != 3 || libs != 1 {
		t.Errorf("referencias = %v", cols[0].ScriptIDs)
	}
	if _, err := Plantilla(KindColecciones, nil, ahora); err == nil {
		t.Error("sin biblioteca no hay lib-* real que poner: debe fallar")
	}
	if _, err := Plantilla("otra", libMuestra, ahora); err == nil {
		t.Error("tipo desconocido debe fallar")
	}
}

// rutas recorre las etiquetas json de los tipos que valida el import, sin pasar por Campos.
func rutas(kind string) []string {
	out := []string{"formato", "version", "exportado", "sha256"}
	campos := func(prefijo string, t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			out = append(out, prefijo+strings.Split(t.Field(i).Tag.Get("json"), ",")[0])
		}
	}
	if kind == KindColecciones {
		out = append(out, "colecciones", "scripts")
		campos("colecciones[].", reflect.TypeOf(Coleccion{}))
	} else {
		out = append(out, "scripts")
	}
	campos("scripts[].", reflect.TypeOf(Script{}))
	return out
}

// Los campos salen de los mismos tipos que valida el import: si se agrega o quita uno, esta prueba falla.
func TestCamposCoincidenConLosTiposDelImport(t *testing.T) {
	for _, kind := range []string{KindScripts, KindColecciones} {
		cs, err := Campos(kind, libMuestra, ahora)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, c := range cs {
			got = append(got, c.Nombre)
			if c.Tipo == "" || c.Descripcion == "" || c.Ejemplo == "" {
				t.Errorf("%s/%s: campo incompleto %+v", kind, c.Nombre, c)
			}
		}
		want := rutas(kind)
		if len(got) != len(want) {
			t.Fatalf("%s: campos %v, tipos %v", kind, got, want)
		}
		seen := map[string]bool{}
		for _, g := range got {
			seen[g] = true
		}
		for _, w := range want {
			if !seen[w] {
				t.Errorf("%s: falta describir %s", kind, w)
			}
		}
	}
}

// «Obligatorio» se comprueba contra el validador de verdad: quitar un campo obligatorio rompe el import; uno opcional no.
func TestCamposObligatoriosCoincidenConElValidador(t *testing.T) {
	for _, kind := range []string{KindScripts, KindColecciones} {
		cs, _ := Campos(kind, libMuestra, ahora)
		tpl, _ := Plantilla(kind, libMuestra, ahora)
		for _, c := range cs {
			var doc map[string]any
			if err := json.Unmarshal(tpl, &doc); err != nil {
				t.Fatal(err)
			}
			if pre, campo, ok := strings.Cut(c.Nombre, "[]."); ok {
				delete(doc[pre].([]any)[0].(map[string]any), campo)
			} else {
				delete(doc, c.Nombre)
			}
			b, _ := json.Marshal(doc)
			var err error
			if kind == KindScripts {
				_, _, err = ParseAvisos(b)
			} else {
				_, _, _, err = ParseColeccionesAvisos(b)
			}
			if (err != nil) != c.Obligatorio {
				t.Errorf("%s/%s: obligatorio=%v pero quitarlo da error=%v", kind, c.Nombre, c.Obligatorio, err)
			}
		}
	}
}

func TestCamposDescribenLasListasCerradasYLosTopes(t *testing.T) {
	cs, _ := Campos(KindScripts, libMuestra, ahora)
	d := map[string]Campo{}
	for _, c := range cs {
		d[c.Nombre] = c
	}
	for _, v := range append(append([]string{}, Techs...), Platforms...) {
		if !strings.Contains(d["scripts[].tech"].Descripcion+d["scripts[].platform"].Descripcion, v) {
			t.Errorf("la descripción no lista %q", v)
		}
	}
	if d["formato"].Ejemplo != `"macuahuitl-scripts"` || d["version"].Ejemplo != "1" {
		t.Errorf("cabecera: %+v %+v", d["formato"], d["version"])
	}
	// el ejemplo de sha256 es la suma real de la plantilla
	b, _ := Plantilla(KindScripts, libMuestra, ahora)
	scs, _ := Parse(b)
	_, sum, _ := suma(scs)
	if d["sha256"].Ejemplo != `"`+sum+`"` || d["sha256"].Obligatorio {
		t.Errorf("sha256 = %+v", d["sha256"])
	}
	if !strings.Contains(d["scripts[].name"].Descripcion, "64") {
		t.Errorf("name no dice el tope: %s", d["scripts[].name"].Descripcion)
	}
	cc, _ := Campos(KindColecciones, libMuestra, ahora)
	for _, c := range cc {
		if c.Nombre == "formato" && c.Ejemplo != `"macuahuitl-colecciones"` {
			t.Errorf("formato de colecciones = %s", c.Ejemplo)
		}
	}
}
