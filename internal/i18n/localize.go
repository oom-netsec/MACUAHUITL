package i18n

import (
	"reflect"
	"strconv"
	"strings"
)

// Put guarda un texto de catálogo en un campo string (en es, el texto de siempre) y en su campo hermano de
// tipo Text, para poder darlo en el otro idioma y entregar su clave.
func Put(dst *string, dstTx *Text, key string, kv ...any) {
	*dstTx = Tx(key, kv...)
	*dst = dstTx.In(Es)
}

var textType = reflect.TypeOf(Text{})

// Localize recorre v (un puntero a un informe) y, por cada campo string F (o []string F) con un hermano FTx
// de tipo Text (o []Text) que trae clave, devuelve esa clave bajo su ruta JSON (rows.2.detail, warnings.0) y,
// con en, cambia el texto en su sitio. Con es no toca nada, así el JSON de siempre queda byte por byte igual.
// Solo recorre structs, punteros y slices; los campos sin clave (datos) no se tocan.
func Localize(v any, loc string) map[string]Text {
	keys := map[string]Text{}
	walk(reflect.ValueOf(v), "", loc, keys)
	return keys
}

func walk(v reflect.Value, path string, loc string, keys map[string]Text) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walk(v.Elem(), path, loc, keys)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i), join(path, strconv.Itoa(i)), loc, keys)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() || f.Type == textType {
				continue
			}
			name := jsonName(f)
			if name == "" {
				continue
			}
			fv := v.Field(i)
			p := join(path, name)
			tx, hasTx := t.FieldByName(f.Name + "Tx")
			switch {
			case hasTx && f.Type.Kind() == reflect.String && tx.Type == textType:
				setText(fv, v.FieldByName(tx.Name).Interface().(Text), p, loc, keys)
			case hasTx && f.Type == reflect.TypeOf([]string(nil)) && tx.Type == reflect.TypeOf([]Text(nil)):
				txs := v.FieldByName(tx.Name).Interface().([]Text)
				for j := 0; j < fv.Len() && j < len(txs); j++ {
					setText(fv.Index(j), txs[j], join(p, strconv.Itoa(j)), loc, keys)
				}
			default:
				walk(fv, p, loc, keys)
			}
		}
	}
}

func setText(dst reflect.Value, t Text, path, loc string, keys map[string]Text) {
	if t.Empty() {
		return
	}
	if t.Key != "" && len(t.Nest) == 0 { // un literal, una unión o un texto con textos dentro no tienen clave plana
		keys[path] = t
	}
	if loc == En && dst.CanSet() {
		dst.SetString(t.In(En))
	}
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

func jsonName(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name
	}
	n, _, _ := strings.Cut(tag, ",")
	if n == "-" {
		return ""
	}
	if n == "" {
		return f.Name
	}
	return n
}
