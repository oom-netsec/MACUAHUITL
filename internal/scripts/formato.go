package scripts

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
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
	Nombre, Tipo string
	Obligatorio  bool
	Ejemplo      string // JSON
	Descripcion  string
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
	desc        string
}

func lista(l []string) string { return strings.Join(l, ", ") }

// esquema describe cada campo por su ruta; «kind:ruta» pisa a «ruta» cuando el campo se entiende distinto en un tipo.
func esquema() map[string]esquemaCampo {
	nombre := fmt.Sprintf("De 1 a %d caracteres, sin espacios en los extremos ni caracteres de control. Único sin importar mayúsculas", MaxName)
	desc := fmt.Sprintf("Hasta %d caracteres", MaxDescription)
	return map[string]esquemaCampo{
		"formato":             {true, "Tipo de archivo; debe ser exactamente el de la plantilla"},
		"version":             {true, fmt.Sprintf("Versión del formato; solo se acepta la %d", Version)},
		"exportado":           {false, "Fecha del export (RFC 3339); informativa"},
		"sha256":              {false, "Suma SHA-256 (hex) del JSON canónico de los datos; protege contra un archivo dañado, no prueba quién lo hizo. Opcional: sin ella se valida campo por campo y la vista previa avisa"},
		"scripts":             {true, fmt.Sprintf("Arreglo de scripts, hasta %d", MaxImportScripts)},
		"colecciones":         {true, fmt.Sprintf("Arreglo de colecciones, hasta %d", MaxColecciones)},
		"colecciones:scripts": {true, "Arreglo con los scripts de usuario que las colecciones referencian (los de la biblioteca viajan solo por ID)"},

		"scripts[].id":                 {true, "32 caracteres hexadecimales (usuario) o «lib-<nombre>» (biblioteca). Sin repetir en el archivo"},
		"colecciones:scripts[].id":     {true, "32 caracteres hexadecimales; sin repetir en el archivo"},
		"scripts[].name":               {true, nombre},
		"scripts[].tech":               {true, "Una de: " + lista(Techs)},
		"scripts[].platform":           {true, "Una de: " + lista(Platforms)},
		"scripts[].description":        {false, desc},
		"scripts[].commands":           {true, fmt.Sprintf("De 1 a %d comandos de hasta %d caracteres, ASCII imprimible (sin tabuladores ni acentos). Una línea que empieza con «!» en la columna 0 es comentario", MaxCommands, MaxCommandLen)},
		"scripts[].tags":               {false, fmt.Sprintf("Hasta %d etiquetas, cada una de 1 a 24 caracteres entre minúsculas, dígitos y guion, sin repetir", MaxTags)},
		"scripts[].origin":             {true, "«usuario» o «biblioteca»; lo de biblioteca que no coincide con la local se importa como script del usuario"},
		"colecciones:scripts[].origin": {true, "Siempre «usuario»"},
		"scripts[].created_at":         {false, "Fecha de creación (RFC 3339); al importar se usa la del momento"},
		"scripts[].updated_at":         {false, "Fecha de edición (RFC 3339); al importar se usa la del momento"},

		"colecciones[].id":          {true, "32 caracteres hexadecimales, o «favoritos» (la colección por defecto, que se fusiona y nunca se reemplaza). Sin repetir en el archivo"},
		"colecciones[].name":        {true, nombre + "; «favoritos» se llama «" + FavoritosNombre + "»"},
		"colecciones[].description": {false, desc},
		"colecciones[].order":       {false, "Posición al exportar; al importar las nuevas quedan al final"},
		"colecciones[].script_ids":  {false, fmt.Sprintf("IDs de script en orden, sin repetir, hasta %d. Los de usuario deben viajar en «scripts»; un «lib-*» que la biblioteca local no trae se avisa y se omite", MaxScriptsColeccion)},
		"colecciones[].created_at":  {false, "Fecha de creación (RFC 3339)"},
		"colecciones[].updated_at":  {false, "Fecha de edición (RFC 3339)"},
	}
}

func tipoDe(t reflect.Type) string {
	switch {
	case t == reflect.TypeOf(time.Time{}):
		return "fecha RFC 3339"
	case t == reflect.TypeOf(json.RawMessage{}):
		return "arreglo"
	case t.Kind() == reflect.String:
		return "texto"
	case t.Kind() == reflect.Int:
		return "entero"
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.String:
		return "lista de texto"
	}
	return t.String()
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
		out = append(out, Campo{Nombre: ruta, Tipo: tipoDe(f.Type), Obligatorio: e.obligatorio, Ejemplo: ejemplo(ruta), Descripcion: e.desc})
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
