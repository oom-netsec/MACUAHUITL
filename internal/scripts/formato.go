package scripts

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Plantilla y descripción de los archivos de import. Todo sale de los mismos tipos (archivo, archivoCol, Script,
// Coleccion), las mismas constantes y las mismas listas cerradas que validan el import: los nombres de campo se
// leen por reflexión de las etiquetas json, los ejemplos son los valores de la plantilla (que pasa el import) y las
// pruebas comprueban que lo «obligatorio» coincide con el validador. Si se agrega un campo sin describirlo, falla una prueba.

const (
	KindScripts     = "scripts"
	KindColecciones = "colecciones"
)

// Campo es un campo del archivo. Nombre es la ruta: «formato», «scripts[].name».
type Campo struct {
	Nombre, Tipo string // Tipo y Descripcion en es; TipoT y Desc dan los mismos textos en el idioma pedido
	Obligatorio  bool
	Ejemplo      string // JSON
	Descripcion  string
	TipoT, Desc  i18n.Text
}

// IDs fijos de la plantilla: así es estable y reimportarla dos veces da «igual».
const (
	idEjemplo1   = "5c6f0a1e9b7d4e2a8f3c1d0b6a4e9f21"
	idEjemplo2   = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	idEjemplo3   = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	idColEjemplo = "9d8c7b6a5f4e3d2c1b0a998877665544"
)

func ejemplos(now time.Time) []Script {
	mk := func(id, name, tech, plat, desc string, cmds, tags []string) Script {
		return Script{ID: id, Name: name, Tech: tech, Platform: plat, Description: desc, Commands: cmds, Tags: tags, Origin: OrigenUsuario, CreatedAt: now, UpdatedAt: now}
	}
	return []Script{
		mk(idEjemplo1, "Ejemplo · estado de interfaces", "diagnostico", "ios-xe", "Solo lectura: Patrol puede correrlo.",
			[]string{"! las lineas que empiezan con ! son comentario y no se escriben", "show ip interface brief", "show interfaces status"}, []string{}),
		mk(idEjemplo2, "Ejemplo · VLAN de acceso", "l2", "ios-xe", "Configura: la terminal lo inserta, no lo ejecuta.",
			[]string{"configure terminal", "vlan 10", "name USUARIOS", "end"}, []string{}),
		mk(idEjemplo3, "Ejemplo · vecinos con etiquetas", "gestion", "ios", "",
			[]string{"show cdp neighbors", "show lldp neighbors"}, []string{"cdp", "lldp", "vecinos"}),
	}
}

// datos arma el contenido de la plantilla; la colección usa dos scripts propios y el primer script real de la biblioteca.
func datos(kind string, lib []Script, now time.Time) (cols []Coleccion, scripts []Script, err error) {
	scripts = ejemplos(now)
	switch kind {
	case KindScripts:
		return nil, scripts, nil
	case KindColecciones:
		if len(lib) == 0 {
			return nil, nil, fmt.Errorf("no hay scripts en la biblioteca para el ejemplo")
		}
		c := Coleccion{ID: idColEjemplo, Name: "Ejemplo · revisión de acceso", Description: "Dos scripts propios y uno de la biblioteca, que viaja solo por ID.",
			ScriptIDs: []string{scripts[0].ID, lib[0].ID, scripts[1].ID}, CreatedAt: now, UpdatedAt: now}
		return []Coleccion{c}, scripts[:2], nil
	}
	return nil, nil, fmt.Errorf("tipo %q desconocido: scripts o colecciones", kind)
}

// Plantilla da el JSON de ejemplo de un archivo de import, con sangría y sin sha256 (opcional al importar).
func Plantilla(kind string, lib []Script, now time.Time) ([]byte, error) {
	cols, scripts, err := datos(kind, lib, now)
	if err != nil {
		return nil, err
	}
	scrRaw, err := json.Marshal(normaliza(scripts))
	if err != nil {
		return nil, err
	}
	exportado := now.UTC().Format(time.RFC3339)
	var v any
	if kind == KindScripts {
		v = archivo{Formato: Formato, Version: Version, Exportado: exportado, Scripts: scrRaw}
	} else {
		colRaw, err := json.Marshal(normalizaCol(cols))
		if err != nil {
			return nil, err
		}
		v = archivoCol{Formato: FormatoColecciones, Version: Version, Exportado: exportado, Colecciones: colRaw, Scripts: scrRaw}
	}
	return json.MarshalIndent(v, "", "  ")
}

type esquemaCampo struct {
	obligatorio bool
	desc        i18n.Text
}

func lista(l []string) string { return strings.Join(l, ", ") }

// esquema describe cada campo por su ruta; «kind:ruta» pisa a «ruta» cuando el campo se entiende distinto en un tipo.
// Los textos (scriptsfmt.desc.*) viven en el catálogo; aquí solo van las constantes que entran en ellos.
func esquema() map[string]esquemaCampo {
	d := func(k string, kv ...any) i18n.Text { return i18n.Tx("scriptsfmt.desc."+k, kv...) }
	return map[string]esquemaCampo{
		"formato":             {true, d("formato")},
		"version":             {true, d("version", "v", Version)},
		"exportado":           {false, d("exportado")},
		"sha256":              {false, d("sha256")},
		"scripts":             {true, d("scripts", "max", MaxImportScripts)},
		"colecciones":         {true, d("colecciones", "max", MaxColecciones)},
		"colecciones:scripts": {true, d("col_scripts")},

		"scripts[].id":                 {true, d("script_id")},
		"colecciones:scripts[].id":     {true, d("col_script_id")},
		"scripts[].name":               {true, d("name", "max", MaxName)},
		"scripts[].tech":               {true, d("one_of", "list", lista(Techs))},
		"scripts[].platform":           {true, d("one_of", "list", lista(Platforms))},
		"scripts[].description":        {false, d("description", "max", MaxDescription)},
		"scripts[].commands":           {true, d("commands", "max", MaxCommands, "len", MaxCommandLen)},
		"scripts[].tags":               {false, d("tags", "max", MaxTags)},
		"scripts[].origin":             {true, d("origin")},
		"colecciones:scripts[].origin": {true, d("col_origin")},
		"scripts[].created_at":         {false, d("script_created")},
		"scripts[].updated_at":         {false, d("script_updated")},

		"colecciones[].id":          {true, d("col_id")},
		"colecciones[].name":        {true, d("col_name", "max", MaxName, "fav", FavoritosNombre)},
		"colecciones[].description": {false, d("description", "max", MaxDescription)},
		"colecciones[].order":       {false, d("order")},
		"colecciones[].script_ids":  {false, d("script_ids", "max", MaxScriptsColeccion)},
		"colecciones[].created_at":  {false, d("col_created")},
		"colecciones[].updated_at":  {false, d("col_updated")},
	}
}

func tipoDe(t reflect.Type) i18n.Text {
	switch {
	case t == reflect.TypeOf(time.Time{}):
		return i18n.Tx("scriptsfmt.type.date")
	case t == reflect.TypeOf(json.RawMessage{}):
		return i18n.Tx("scriptsfmt.type.array")
	case t.Kind() == reflect.String:
		return i18n.Tx("scriptsfmt.type.text")
	case t.Kind() == reflect.Int:
		return i18n.Tx("scriptsfmt.type.int")
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		return i18n.Tx("scriptsfmt.type.text_list")
	}
	return i18n.Lit(t.String(), "")
}

func etiqueta(f reflect.StructField) string { return strings.Split(f.Tag.Get("json"), ",")[0] }

// Campos describe los campos del archivo (cabecera incluida) de un tipo de import.
func Campos(kind string, lib []Script, now time.Time) ([]Campo, error) {
	cols, scripts, err := datos(kind, lib, now)
	if err != nil {
		return nil, err
	}
	tpl, err := Plantilla(kind, lib, now)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(tpl, &doc); err != nil {
		return nil, err
	}
	sum := ""
	if kind == KindScripts {
		_, sum, err = suma(scripts)
	} else {
		_, _, sum, err = canonCol(cols, scripts)
	}
	if err != nil {
		return nil, err
	}
	ejemplo := func(ruta string) string {
		var v any
		if pre, campo, ok := strings.Cut(ruta, "[]."); ok {
			v = doc[pre].([]any)[0].(map[string]any)[campo]
		} else if ruta == "sha256" {
			v = sum
		} else {
			v = doc[ruta]
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	esq := esquema()
	var out []Campo
	add := func(ruta string, f reflect.StructField) error {
		e, ok := esq[kind+":"+ruta]
		if !ok {
			if e, ok = esq[ruta]; !ok {
				return fmt.Errorf("el campo %s no está descrito", ruta)
			}
		}
		tipo := tipoDe(f.Type)
		out = append(out, Campo{Nombre: ruta, Tipo: tipo.In(i18n.Es), TipoT: tipo, Obligatorio: e.obligatorio, Ejemplo: ejemplo(ruta), Descripcion: e.desc.In(i18n.Es), Desc: e.desc})
		return nil
	}
	cab := reflect.TypeOf(archivo{})
	elem := map[string]reflect.Type{"scripts": reflect.TypeOf(Script{})}
	if kind == KindColecciones {
		cab = reflect.TypeOf(archivoCol{})
		elem["colecciones"] = reflect.TypeOf(Coleccion{})
	}
	for i := 0; i < cab.NumField(); i++ {
		f := cab.Field(i)
		n := etiqueta(f)
		if err := add(n, f); err != nil {
			return nil, err
		}
		if t, ok := elem[n]; ok {
			for j := 0; j < t.NumField(); j++ {
				if err := add(n+"[]."+etiqueta(t.Field(j)), t.Field(j)); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}
