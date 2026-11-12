package i18n

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// Put guarda un texto de catálogo en un campo string (en es, el texto de siempre) y en su campo hermano de
// tipo Text, para poder darlo en el otro idioma y entregar su clave.
func Put(dst *string, dstTx *Text, key string, kv ...any) {
	*dstTx = Tx(key, kv...)
	*dst = dstTx.In(Es)
}

var (
	textType  = reflect.TypeOf(Text{})
	textsType = reflect.TypeOf([]Text(nil))
	strsType  = reflect.TypeOf([]string(nil))
)

// fieldPlan es qué hacer con un campo de un struct: un string con su Text hermano (tx), una lista de strings
// con su lista de Text (list) o bajar a un valor que a su vez tiene textos.
type fieldPlan struct {
	idx, tx int
	seg     string // segmento de la ruta JSON; vacío para un campo anónimo sin tag
	kind    byte   // 't' texto, 'l' lista de textos, 'r' recursivo
}

// typePlan es lo que se sabe de un tipo: si algo dentro lleva Text y, si es struct, qué campos recorrer. Se
// calcula una sola vez por tipo, así recorrer informes sin textos con clave cuesta casi nada.
type typePlan struct {
	hasTx  bool
	fields []fieldPlan
}

var plans sync.Map // reflect.Type → *typePlan

func planOf(t reflect.Type) *typePlan { return planFor(t, map[reflect.Type]bool{}) }

// planFor arma el plan de t; building trae los tipos en curso: uno que se contiene a sí mismo (por puntero)
// cuenta como con textos mientras se arma, así sus campos recursivos no se pierden.
func planFor(t reflect.Type, building map[reflect.Type]bool) *typePlan {
	if p, ok := plans.Load(t); ok {
		return p.(*typePlan)
	}
	if building[t] {
		return &typePlan{hasTx: true}
	}
	building[t] = true
	defer delete(building, t)
	p := &typePlan{}
	defer func() { plans.Store(t, p) }()
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		p.hasTx = planFor(t.Elem(), building).hasTx
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() && !f.Anonymous || f.Type == textType || f.Type == textsType {
				continue
			}
			seg, ok := jsonSeg(f)
			if !ok {
				continue
			}
			fp := fieldPlan{idx: i, seg: seg}
			if sc, has := t.FieldByName(f.Name + "Tx"); has && len(sc.Index) == 1 {
				switch {
				case f.Type.Kind() == reflect.String && sc.Type == textType:
					fp.kind, fp.tx = 't', sc.Index[0]
				case f.Type == strsType && sc.Type == textsType:
					fp.kind, fp.tx = 'l', sc.Index[0]
				}
			}
			if fp.kind == 0 {
				if !planFor(f.Type, building).hasTx {
					continue
				}
				fp.kind = 'r'
			}
			p.fields = append(p.fields, fp)
		}
		p.hasTx = len(p.fields) > 0
	}
	return p
}

// jsonSeg es el segmento de ruta de un campo: su nombre JSON, vacío si es anónimo sin tag (sus campos se
// aplanan en el JSON) y ok=false si el JSON lo omite.
func jsonSeg(f reflect.StructField) (string, bool) {
	tag, has := f.Tag.Lookup("json")
	n, _, _ := strings.Cut(tag, ",")
	switch {
	case n == "-" && tag == "-":
		return "", false
	case n != "":
		return n, true
	case f.Anonymous && f.Type.Kind() == reflect.Struct && !has:
		return "", true
	}
	return f.Name, true
}

// Localize recorre v (un puntero a un informe) y, por cada campo string F (o []string F) con un hermano FTx
// de tipo Text (o []Text) que trae clave, devuelve esa clave bajo su ruta JSON (rows.2.detail, warnings.0) y,
// con en, cambia el texto en su sitio. Con es no toca nada, así el JSON de siempre queda byte por byte igual.
// Solo recorre structs, punteros y slices (CheckLocalizable rechaza los tipos con mapas o interfaces que lleven
// textos); un valor que no se puede asignar no se registra ni se cambia. Los ciclos de punteros se cortan.
func Localize(v any, loc string) map[string]Text {
	keys := map[string]Text{}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || !planOf(rv.Type()).hasTx {
		return keys
	}
	w := &walker{loc: loc, keys: keys}
	w.walk(rv)
	return keys
}

// CheckLocalizable dice si Localize puede traducir v: debe ser un puntero (si no, no puede cambiar nada) y
// ningún mapa ni interfaz que lleve textos, porque Localize no los recorre.
func CheckLocalizable(v any) error {
	t := reflect.TypeOf(v)
	if t == nil {
		return fmt.Errorf("i18n: valor nulo")
	}
	if planOf(t).hasTx && t.Kind() != reflect.Pointer {
		return fmt.Errorf("i18n: %s no es un puntero y no se puede traducir en su sitio", t)
	}
	return checkType(t, map[reflect.Type]bool{})
}

func checkType(t reflect.Type, seen map[reflect.Type]bool) error {
	if seen[t] {
		return nil
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return checkType(t.Elem(), seen)
	case reflect.Map:
		if planOf(t.Elem()).hasTx || planOf(t.Key()).hasTx {
			return fmt.Errorf("i18n: %s es un mapa con textos: Localize no los recorre", t)
		}
	case reflect.Struct:
		hasTx := planOf(t).hasTx
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if hasTx && f.IsExported() && f.Type.Kind() == reflect.Interface {
				return fmt.Errorf("i18n: %s.%s es una interfaz en un tipo con textos: Localize no la recorre", t, f.Name)
			}
			if err := checkType(f.Type, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

type walker struct {
	loc   string
	keys  map[string]Text
	used  map[string]bool // si no es nil, recoge todas las claves de catálogo que aparecen (UsedKeys)
	stack []string
	seen  map[uintptr]bool
}

func (w *walker) push(s string) {
	if s != "" {
		w.stack = append(w.stack, s)
	}
}

func (w *walker) pop(s string) {
	if s != "" {
		w.stack = w.stack[:len(w.stack)-1]
	}
}

func (w *walker) walk(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || !planOf(v.Type()).hasTx {
			return
		}
		if w.seen == nil {
			w.seen = map[uintptr]bool{}
		}
		if p := v.Pointer(); !w.seen[p] {
			w.seen[p] = true
			w.walk(v.Elem())
		}
	case reflect.Slice, reflect.Array:
		if !planOf(v.Type()).hasTx {
			return
		}
		for i := 0; i < v.Len(); i++ {
			s := strconv.Itoa(i)
			w.push(s)
			w.walk(v.Index(i))
			w.pop(s)
		}
	case reflect.Struct:
		for _, fp := range planOf(v.Type()).fields {
			fv := v.Field(fp.idx)
			w.push(fp.seg)
			switch fp.kind {
			case 't':
				w.set(fv, v.Field(fp.tx).Interface().(Text))
			case 'l':
				txs := v.Field(fp.tx).Interface().([]Text)
				for j := 0; j < fv.Len() && j < len(txs); j++ {
					s := strconv.Itoa(j)
					w.push(s)
					w.set(fv.Index(j), txs[j])
					w.pop(s)
				}
			default:
				w.walk(fv)
			}
			w.pop(fp.seg)
		}
	}
}

func (w *walker) set(dst reflect.Value, t Text) {
	if w.used != nil {
		t.collect(w.used)
	}
	if t.Empty() || !dst.CanSet() { // un valor que no se puede cambiar no se registra: la clave diría otra cosa
		return
	}
	if t.Key != "" && len(t.Nest) == 0 { // un literal, una unión o un texto con textos dentro no tienen clave plana
		w.keys[strings.Join(w.stack, ".")] = t
	}
	if w.loc == En {
		dst.SetString(t.In(En))
	}
}

// collect anota todas las claves de catálogo de un texto, también las de sus uniones y argumentos anidados.
func (t Text) collect(into map[string]bool) {
	if t.Key != "" {
		into[t.Key] = true
	}
	for _, p := range t.Parts {
		p.collect(into)
	}
	for _, n := range t.Nest {
		n.collect(into)
	}
	var e *Error
	if t.Err != nil && errors.As(t.Err, &e) {
		into[e.Code] = true
	}
}

// UsedKeys son las claves de catálogo de todos los textos de un informe (v, un puntero), con los anidados y las
// uniones. Es para pruebas: comprobar que los escenarios recorren todo el catálogo de un área.
func UsedKeys(v any) map[string]bool {
	used := map[string]bool{}
	rv := reflect.ValueOf(v)
	if rv.IsValid() && planOf(rv.Type()).hasTx {
		(&walker{loc: Es, keys: map[string]Text{}, used: used}).walk(rv)
	}
	return used
}
