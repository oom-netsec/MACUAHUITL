package devices

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Formatos del archivo de import/export.
const (
	FormatJSON = "json"
	FormatCSV  = "csv"
)

// FieldSpec describe un campo del archivo de import. HostFields es la ÚNICA tabla de campos: de ella salen el
// encabezado del CSV, cómo se lee y se escribe cada celda, la plantilla y la descripción que ve la persona. Las
// claves del JSON son las de FileHost; una prueba comprueba que coinciden con esta tabla.
type FieldSpec struct {
	Name        string
	Type        string // texto, entero o lista (en CSV separada por «;», en JSON un arreglo)
	Required    bool
	Examples    [3]string // un valor por cada fila de la plantilla
	Description string
	get         func(FileHost) string
	set         func(*FileHost, string) error
}

func texto(p func(*FileHost) *string) (func(FileHost) string, func(*FileHost, string) error) {
	return func(h FileHost) string { return *p(&h) }, func(h *FileHost, v string) error { *p(h) = v; return nil }
}

func campo(name, tipo string, req bool, ej [3]string, desc string, p func(*FileHost) *string) FieldSpec {
	g, s := texto(p)
	return FieldSpec{Name: name, Type: tipo, Required: req, Examples: ej, Description: desc, get: g, set: s}
}

// HostFields, en el orden del encabezado del CSV.
var HostFields = []FieldSpec{
	campo("name", "texto", true, [3]string{"SW-CORE", "SW-ACC1", "AP-1"},
		"Nombre del host: 1 a 64 caracteres, sin espacios en los extremos. No se repite (sin importar mayúsculas).",
		func(h *FileHost) *string { return &h.Name }),
	campo("address", "texto", true, [3]string{"10.0.0.1", "10.0.0.2", "ap1.lab.example.com"},
		"IP o nombre DNS, sin usuario, esquema, puerto ni ruta. La dirección con el puerto no se repite.",
		func(h *FileHost) *string { return &h.Address }),
	{Name: "port", Type: "entero", Examples: [3]string{"22", "22", "2222"}, Description: "Puerto SSH, de 1 a 65535. Vacío = 22.",
		get: func(h FileHost) string {
			if h.Port == 0 {
				return ""
			}
			return strconv.Itoa(h.Port)
		},
		set: func(h *FileHost, v string) error {
			if v = strings.TrimSpace(v); v == "" {
				h.Port = 0
				return nil
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return i18n.New("hostfield.not_int", i18n.A("value", v))
			}
			h.Port = n
			return nil
		}},
	campo("platform", "texto", false, [3]string{"ios-xe", "nx-os", "wlc"},
		"Plataforma: "+strings.Join(HostPlatforms, ", ")+". Vacío = sin definir.",
		func(h *FileHost) *string { return &h.Platform }),
	campo("folder", "texto", false, [3]string{"Lab", "Lab", "Oficina"},
		"Carpeta de un solo nivel: 1 a 48 caracteres entre letras, números, espacio, _, . y -. Vacío = sin carpeta.",
		func(h *FileHost) *string { return &h.Folder }),
	{Name: "tags", Type: "lista", Examples: [3]string{"core;dc-1", "acceso", "wifi"},
		Description: "Hasta 10 etiquetas de 1 a 24 caracteres entre a-z, 0-9 y -. En CSV separadas por «;»; en JSON, un arreglo.",
		get:         func(h FileHost) string { return strings.Join(h.Tags, ";") },
		set: func(h *FileHost, v string) error {
			h.Tags = nil
			for _, t := range strings.Split(v, ";") {
				if t = strings.TrimSpace(t); t != "" {
					h.Tags = append(h.Tags, t)
				}
			}
			return nil
		}},
	campo("credential_label", "texto", false, [3]string{"admin lab", "", ""},
		"Etiqueta de una credencial de la bóveda local (nunca el usuario ni la contraseña). Si al importar no existe una con esa etiqueta, el host queda sin credencial.",
		func(h *FileHost) *string { return &h.CredentialLabel }),
	campo("notes", "texto", false, [3]string{"Piso 2", "", ""}, "Notas libres, hasta 2000 caracteres.",
		func(h *FileHost) *string { return &h.Notes }),
}

// HostsHeader es el encabezado fijo del CSV.
func HostsHeader() []string {
	out := make([]string, len(HostFields))
	for i, f := range HostFields {
		out[i] = f.Name
	}
	return out
}

// exampleHosts arma las filas de la plantilla pasando los ejemplos de la tabla por el mismo lector del import.
func exampleHosts() ([]FileHost, error) {
	var out []FileHost
	for i := range HostFields[0].Examples {
		cells := make([]string, len(HostFields))
		for j, f := range HostFields {
			cells[j] = f.Examples[i]
		}
		h, ferr := rowToHost(cells)
		if ferr != nil {
			return nil, fmt.Errorf("plantilla: fila %d: %s: %s", i+1, ferr.Field, ferr.Reason)
		}
		out = append(out, h)
	}
	return out, nil
}

// rowToHost lee las celdas (en el orden de la tabla) a un host del archivo, sin validar sus reglas.
func rowToHost(cells []string) (FileHost, *FieldError) {
	var h FileHost
	for i, f := range HostFields {
		if err := f.set(&h, cells[i]); err != nil {
			return h, &FieldError{Field: f.Name, Reason: err.Error(), Err: err}
		}
	}
	return h, nil
}

// Template da el archivo de ejemplo: el encabezado y tres filas válidas (en JSON, el archivo versionado sin suma).
func Template(format string, now time.Time) ([]byte, error) {
	hs, err := exampleHosts()
	if err != nil {
		return nil, err
	}
	switch format {
	case FormatCSV:
		return MarshalHostsCSV(hs)
	case FormatJSON:
		return marshalHosts(hs, now, false)
	}
	return nil, fmt.Errorf("formato %q: use csv o json", format)
}

// ImportFormat decide el formato del archivo: el pedido (csv o json) o, si no hay, la extensión de la ruta.
func ImportFormat(path, format string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" {
		f = strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	}
	if f != FormatCSV && f != FormatJSON {
		return "", i18n.New("hostfile.format_unknown", i18n.A("path", path))
	}
	return f, nil
}

// ParseImport lee un archivo de import en el formato dado (ver ImportFormat).
func ParseImport(format string, b []byte) (Parsed, error) {
	if format == FormatCSV {
		return ParseHostsCSV(b)
	}
	return ParseHosts(b)
}
