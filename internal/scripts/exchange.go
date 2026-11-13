package scripts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const (
	Formato          = "macuahuitl-scripts"
	Version          = 1
	MaxImportBytes   = 5 << 20
	MaxImportScripts = 1000
)

// archivo es el formato de export. sha256 es la suma del JSON canónico del arreglo scripts: protege contra
// un archivo corrupto, no prueba quién lo hizo (cualquiera puede recalcularla).
type archivo struct {
	Formato   string          `json:"formato"`
	Version   int             `json:"version"`
	Exportado string          `json:"exportado"`
	Scripts   json.RawMessage `json:"scripts"`
	SHA256    string          `json:"sha256,omitempty"` // opcional al importar
}

// normaliza deja las listas como arreglos (nunca null) para que el JSON canónico no dependa de cómo llegaron.
func normaliza(in []Script) []Script {
	out := make([]Script, len(in))
	for i, s := range in {
		s.Commands, s.Tags = nonNil(s.Commands), nonNil(s.Tags)
		out[i] = s
	}
	return out
}

func sha(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func suma(scripts []Script) (raw []byte, sum string, err error) {
	if raw, err = json.Marshal(normaliza(scripts)); err != nil {
		return nil, "", err
	}
	return raw, sha(raw), nil
}

// Marshal arma el archivo de export. Los favoritos no viajan: no son parte del script.
func Marshal(scripts []Script, now time.Time) ([]byte, error) {
	raw, sum, err := suma(scripts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(archivo{Formato: Formato, Version: Version, Exportado: now.UTC().Format(time.RFC3339), Scripts: raw, SHA256: sum})
}

// leerCabecera revisa tamaño, formato y versión. Primero solo la cabecera, sin modo estricto: una versión futura
// puede traer campos que esta no conoce. que es lo que contiene el archivo, para los mensajes.
func leerCabecera(b []byte, formato, que string) error {
	if len(b) > MaxImportBytes {
		return i18n.New("scripts.imp.too_big", nil)
	}
	var cab struct {
		Formato string `json:"formato"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&cab); err != nil {
		return i18n.Wrap("scripts.imp.not_file."+que, err, nil)
	}
	if cab.Formato != formato {
		return i18n.New("scripts.imp.format", i18n.A("got", cab.Formato, "want", formato))
	}
	if cab.Version != Version {
		return i18n.New("scripts.imp.version", i18n.A("got", cab.Version, "want", Version))
	}
	return nil
}

// decodifica lee un solo JSON, sin campos desconocidos y sin nada después.
func decodifica(b []byte, dst any, que string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return i18n.Wrap("scripts.imp.not_file."+que, err, nil)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return i18n.New("scripts.imp.trailing", nil)
	}
	return nil
}

func decodificaLista[T any](raw json.RawMessage, que string) ([]T, error) {
	var out []T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, i18n.Wrap("scripts.imp.unreadable."+que, err, nil)
	}
	return out, nil
}

// validaScripts normaliza cada script en su lugar y aplica las reglas de cada uno y que no haya IDs ni nombres repetidos.
func validaScripts(scripts []Script) error {
	ids, nombres := map[string]bool{}, map[string]bool{}
	for i, s := range normaliza(scripts) {
		scripts[i] = s
		if err := s.Validate(); err != nil {
			return i18n.Wrap("scripts.imp.script", err, i18n.A("n", i+1, "name", s.Name))
		}
		k := NameKey(s.Name)
		if ids[s.ID] || nombres[k] {
			return i18n.New("scripts.imp.script_dup", i18n.A("n", i+1, "name", s.Name))
		}
		ids[s.ID], nombres[k] = true, true
	}
	return nil
}

// AvisoSinSuma es el aviso de un archivo sin sha256: la suma es opcional al importar (el export siempre la escribe).
const AvisoSinSuma = "archivo sin suma de verificación"

// Parse lee y valida un archivo de import completo: tamaño, formato, versión, tope de scripts, suma, las reglas
// de cada script y que no haya IDs ni nombres repetidos. No toca el store.
func Parse(b []byte) ([]Script, error) {
	s, _, err := ParseAvisos(b)
	return s, err
}

// ParseAvisos es Parse más los avisos. Sin sha256 se valida campo por campo y se avisa; con uno que no coincide, se rechaza.
func ParseAvisos(b []byte) ([]Script, []string, error) {
	if err := leerCabecera(b, Formato, "scripts"); err != nil {
		return nil, nil, err
	}
	var a archivo
	if err := decodifica(b, &a, "scripts"); err != nil {
		return nil, nil, err
	}
	scripts, err := decodificaLista[Script](a.Scripts, "scripts")
	if err != nil {
		return nil, nil, err
	}
	if len(scripts) > MaxImportScripts {
		return nil, nil, i18n.New("scripts.imp.max_scripts", i18n.A("n", len(scripts), "max", MaxImportScripts))
	}
	avisos, err := verificaSuma(a.SHA256, func() (string, error) { _, sum, err := suma(scripts); return sum, err })
	if err != nil {
		return nil, nil, err
	}
	if err := validaScripts(scripts); err != nil {
		return nil, nil, err
	}
	return scripts, avisos, nil
}

// verificaSuma compara la suma dada con la calculada; vacía es opcional y da el aviso.
func verificaSuma(dada string, calcula func() (string, error)) ([]string, error) {
	if dada == "" {
		return []string{AvisoSinSuma}, nil
	}
	if sum, err := calcula(); err != nil || !strings.EqualFold(sum, dada) {
		return nil, errSuma
	}
	return nil, nil
}

var errSuma = i18n.New("scripts.imp.checksum", nil)
