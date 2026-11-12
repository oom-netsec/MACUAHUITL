package core

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// textRefs son las claves de textos de un informe (ToolReport.keys). Este archivo no existe en la base de la fase:
// la regresión se genera allí con un sustituto vacío.
type textRefs = map[string]*v1.TextRef

func keysOf(r *v1.ToolReport) textRefs { return r.GetKeys() }

// aclKeysOf son las claves de los detalles de los hallazgos de ACL, por ruta ("0.detail").
func aclKeysOf(fs []*v1.Finding) textRefs {
	keys := textRefs{}
	for i, f := range fs {
		if f.DetailKey != "" {
			keys[strconv.Itoa(i)+".detail"] = &v1.TextRef{Key: f.DetailKey, Args: f.DetailArgs}
		}
	}
	return keys
}

// jsonAt busca en un JSON decodificado la ruta rows.2.detail (índices numéricos para las listas).
func jsonAt(v any, path string) (string, bool) {
	for _, p := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			v = x[p]
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i >= len(x) {
				return "", false
			}
			v = x[i]
		default:
			return "", false
		}
	}
	s, ok := v.(string)
	return s, ok
}

// checkKeys: cada clave de ToolReport.keys cae sobre un texto del json que es exactamente su plantilla en el idioma pedido.
func checkKeys(t *testing.T, lang string, cases map[string]flotaRec) (total int) {
	t.Helper()
	loc := i18n.Normalize(lang)
	for n, r := range cases {
		var doc any
		if r.Json == "" {
			continue
		}
		if err := json.Unmarshal([]byte(r.Json), &doc); err != nil {
			continue // algunas respuestas llevan otro JSON (hallazgos de ACL)
		}
		for path, ref := range r.Keys {
			got, ok := jsonAt(doc, path)
			if want := i18n.Msg(loc, ref.Key, ref.Args); !ok || got != want {
				t.Errorf("%s %s (%s): json %q, clave da %q", n, path, ref.Key, got, want)
			}
			total++
		}
	}
	return total
}
