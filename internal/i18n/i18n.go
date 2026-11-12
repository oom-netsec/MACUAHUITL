// Package i18n es el catálogo es/en de códigos estables del núcleo: cada código lleva su texto en los dos
// idiomas, sus argumentos con nombre ({arg}) y los metadatos que viajan al cliente.
//
// El español es el idioma de origen: sin idioma en el contexto, o con uno desconocido, todo sale en es y
// byte por byte igual que antes de existir el catálogo. No hace: auditoría (va fija en inglés, fuera del
// catálogo), ni gRPC (eso es de internal/service).
package i18n

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Idiomas que el núcleo entiende.
const (
	Es = "es"
	En = "en"
)

// Args son los argumentos con nombre de una plantilla.
type Args map[string]string

// A arma Args desde pares clave, valor (el valor se pasa por fmt.Sprint).
func A(kv ...any) Args {
	a := Args{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[fmt.Sprint(kv[i])] = fmt.Sprint(kv[i+1])
	}
	return a
}

// entry es un código del catálogo. En la plantilla {x} inserta el argumento x, {x:q} lo inserta entre comillas
// (como %q de fmt) y {{ o }} escriben una llave literal.
type entry struct {
	Reason string            // motivo estable para el cliente; vacío = el propio código
	Es, En string            //
	Args   []string          // argumentos que usan las plantillas (los mismos en es y en en)
	Extra  []string          // argumentos que solo viajan en la metadata
	Meta   map[string]string // metadata fija del código
}

var catalog = map[string]entry{}

// add registra códigos; cada área tiene su archivo catalog_<área>.go con su init.
func add(m map[string]entry) {
	for k, e := range m {
		if _, dup := catalog[k]; dup {
			panic("i18n: código repetido " + k)
		}
		catalog[k] = e
	}
}

type ctxKey struct{}

// WithLocale deja el idioma en el contexto (lo normaliza: solo es o en).
func WithLocale(ctx context.Context, loc string) context.Context {
	return context.WithValue(ctx, ctxKey{}, Normalize(loc))
}

// Locale devuelve es o en; sin idioma en el contexto, es.
func Locale(ctx context.Context) string {
	if l, ok := ctx.Value(ctxKey{}).(string); ok {
		return l
	}
	return Es
}

// Normalize reduce una etiqueta (es, es-MX, EN-us) a es o en; lo desconocido es es.
func Normalize(tag string) string {
	t := strings.ToLower(strings.TrimSpace(tag))
	if t == En || strings.HasPrefix(t, "en-") || strings.HasPrefix(t, "en_") {
		return En
	}
	return Es
}

// Parse elige el idioma de un valor Accept-Language (lista con q): el de mayor q entre es y en; ausente o
// ninguno conocido, es. A igual q gana el primero de la lista.
func Parse(header string) string {
	best, bestQ := Es, -1.0
	for _, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(part, ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		q := 1.0
		if k, v, ok := strings.Cut(strings.TrimSpace(params), "="); ok && strings.TrimSpace(k) == "q" {
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				q = f
			}
		}
		primary, _, _ := strings.Cut(strings.ReplaceAll(tag, "_", "-"), "-")
		if q <= 0 || (primary != Es && primary != En) || q <= bestQ {
			continue
		}
		best, bestQ = primary, q
	}
	return best
}

// Msg es el texto del código en el idioma dado; un código que no existe se devuelve tal cual.
func Msg(loc, code string, args Args) string {
	e, ok := catalog[code]
	if !ok {
		return code
	}
	if loc == En {
		return render(e.En, args)
	}
	return render(e.Es, args)
}

// T es el texto del código en el idioma del contexto.
func T(ctx context.Context, code string, args Args) string { return Msg(Locale(ctx), code, args) }

// Reason es el motivo estable del código (por omisión, el propio código).
func Reason(code string) string {
	if e := catalog[code]; e.Reason != "" {
		return e.Reason
	}
	return code
}

// Metadata es lo que el cliente recibe: solo los argumentos que el código declara (Args y Extra) más su
// metadata fija. Lo demás que pase quien llama se descarta, así un dato sensible no se cuela por error.
func Metadata(code string, args Args) map[string]string {
	e := catalog[code]
	m := map[string]string{}
	for _, k := range append(append([]string{}, e.Args...), e.Extra...) {
		if v, ok := args[k]; ok {
			m[k] = v
		}
	}
	for k, v := range e.Meta {
		m[k] = v
	}
	return m
}

func render(tpl string, args Args) string {
	var b strings.Builder
	for i := 0; i < len(tpl); i++ {
		c := tpl[i]
		switch {
		case (c == '{' || c == '}') && i+1 < len(tpl) && tpl[i+1] == c:
			b.WriteByte(c)
			i++
		case c == '{':
			end := strings.IndexByte(tpl[i:], '}')
			if end < 0 {
				b.WriteString(tpl[i:])
				return b.String()
			}
			name, verb, _ := strings.Cut(tpl[i+1:i+end], ":")
			v, ok := args[name]
			switch {
			case !ok:
				b.WriteString("{" + name + "}")
			case verb == "q":
				b.WriteString(strconv.Quote(v))
			default:
				b.WriteString(v)
			}
			i += end
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Coded es un error con código del catálogo: el servicio lo vuelve un status con reason y metadata.
type Coded interface {
	error
	Reason() string
	Metadata() map[string]string
	// Localize da el mensaje en el idioma pedido; Error() es siempre el de es.
	Localize(loc string) string
}

// Error es el error de un código del catálogo. Error() es el texto en es, el mismo de antes del catálogo.
type Error struct {
	Code string
	Args Args
}

// New arma el error del código con sus argumentos.
func New(code string, args Args) *Error { return &Error{Code: code, Args: args} }

func (e *Error) Error() string               { return Msg(Es, e.Code, e.Args) }
func (e *Error) Reason() string              { return Reason(e.Code) }
func (e *Error) Metadata() map[string]string { return Metadata(e.Code, e.Args) }
func (e *Error) Localize(loc string) string  { return Msg(loc, e.Code, e.Args) }

// Codes lista los códigos del catálogo en orden (para pruebas y documentación).
func Codes() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
