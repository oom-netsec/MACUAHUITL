package bridge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const pathV1 = "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"

// unmarshalRevisados fija los puntos donde el puente deserializa JSON de la UI directo a un
// request gRPC (todo «Unmarshal»: protojson, proto y json hacia un tipo de v1, y métodos como UnmarshalOptions{}.Unmarshal; la UI puede poner cualquier campo del proto). Revisados el 2026-11-17: ninguno
// tiene campos de actor, ids asignados por el núcleo ni rutas internas; todo campo es una
// elección legítima del usuario y el núcleo valida y es quien decide (guard, modo asistido).
// Una entrada nueva exige revisar los campos de su request antes de agregarla aquí.
var unmarshalRevisados = map[string]string{
	// JobSpec: nombre, objetivos, credenciales, playbooks, salida, horario y opciones (disable_masking,
	// accept_changed_host_keys) que el usuario marca en el formulario; no hay actor ni job_id. El campo kind
	// no es del usuario: CreateJob lo vacía antes de llamar (un patrol no se hace pasar por backup, adhoc o change)
	// y el núcleo pone el suyo en ChangeCreate (change.go) y en backup; lo fija TestCreateJobVaciaElKind.
	"Bridge.CreateJob|JobSpec":    "JobSpec",
	"Bridge.ChangeCreate|JobSpec": "JobSpec",
	// Planes del modo asistido: solo lectura; ejecutar exige assisted=true que viaja aparte en AssistStart.
	// write_memory y las huellas aceptadas las elige el usuario por plan.
	"Bridge.AssistPlanPorts|PlanPortsRequest":           "PlanPortsRequest",
	"Bridge.AssistPlanSnippet|PlanSnippetRequest":       "PlanSnippetRequest",
	"Bridge.AssistPlanCredRotate|PlanCredRotateRequest": "PlanCredRotateRequest",
	"Bridge.AssistPlanRestore|PlanRestoreRequest":       "PlanRestoreRequest",
	// Calculadoras: entradas numéricas y de texto de un cálculo puro, sin efectos.
	// El tipo sale de un parámetro genérico (cualquier Calc*Request): no se resuelve, por eso «?».
	"calcRPC|?": "Calc*Request",
}

// importes devuelve nombre local -> ruta de cada import del archivo (resuelve los alias; «_» y «.» no cuentan).
func importes(af *ast.File) map[string]string {
	m := map[string]string{}
	for _, im := range af.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		n := p[strings.LastIndex(p, "/")+1:]
		if p == "google.golang.org/protobuf/encoding/protojson" {
			n = "protojson"
		}
		if im.Name != nil {
			n = im.Name.Name
		}
		if n != "_" && n != "." {
			m[n] = p
		}
	}
	return m
}

// tipoV1 devuelve el nombre del tipo de v1 que menciona una expresión de tipo o literal («v1.T», «*v1.T», «&v1.T{}», «new(v1.T)»), o "".
func tipoV1(e ast.Expr, v1n map[string]bool) string {
	var out string
	ast.Inspect(e, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && out == "" {
			if x, ok := s.X.(*ast.Ident); ok && v1n[x.Name] {
				out = s.Sel.Name
			}
		}
		return out == ""
	})
	return out
}

// hallazgosUnmarshal devuelve «función|tipo» de cada Unmarshal del archivo que la UI puede alimentar:
// todo protojson y todo método Unmarshal (UnmarshalOptions{}.Unmarshal); proto, json y cualquier otro paquete solo si el destino es de v1.
func hallazgosUnmarshal(fset *token.FileSet, af *ast.File, info *types.Info) []string {
	imps := importes(af)
	v1n := map[string]bool{}
	for n, p := range imps {
		if p == pathV1 {
			v1n[n] = true
		}
	}
	// Variables de tipo v1: declaradas con var, con := de un literal de v1 o como parámetro.
	vt := map[types.Object]string{}
	marca := func(id *ast.Ident, t string) {
		if o := objOf(info, id); o != nil && t != "" {
			vt[o] = t
		}
	}
	ast.Inspect(af, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			if x.Type != nil {
				for _, id := range x.Names {
					marca(id, tipoV1(x.Type, v1n))
				}
			}
			for i, v := range x.Values {
				if i < len(x.Names) {
					marca(x.Names[i], tipoV1(v, v1n))
				}
			}
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); ok && i < len(x.Rhs) {
					marca(id, tipoV1(x.Rhs[i], v1n))
				}
			}
		case *ast.Field:
			for _, id := range x.Names {
				marca(id, tipoV1(x.Type, v1n))
			}
		}
		return true
	})
	// Tipo del destino: la raíz de la expresión (&x, x.campo, x[i]) o el literal mismo.
	destino := func(e ast.Expr) string {
		if t := tipoV1(e, v1n); t != "" {
			return t
		}
		for {
			switch x := e.(type) {
			case *ast.UnaryExpr:
				e = x.X
			case *ast.ParenExpr:
				e = x.X
			case *ast.StarExpr:
				e = x.X
			case *ast.SelectorExpr:
				e = x.X
			case *ast.IndexExpr:
				e = x.X
			case *ast.Ident:
				return vt[objOf(info, x)]
			default:
				return ""
			}
		}
	}
	var out []string
	for _, d := range af.Decls {
		var nombre string
		switch x := d.(type) {
		case *ast.FuncDecl:
			nombre = x.Name.Name
			if x.Recv != nil && len(x.Recv.List) == 1 {
				r := x.Recv.List[0].Type
				if st, ok := r.(*ast.StarExpr); ok {
					r = st.X
				}
				if ix, ok := r.(*ast.IndexExpr); ok {
					r = ix.X
				}
				if id, ok := r.(*ast.Ident); ok {
					nombre = id.Name + "." + nombre
				}
			}
		case *ast.GenDecl: // funciones literales a nivel de paquete: var f = func() {…}
			if x.Tok != token.VAR || len(x.Specs) == 0 {
				continue
			}
			nombre = x.Specs[0].(*ast.ValueSpec).Names[0].Name
		default:
			continue
		}
		ast.Inspect(d, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			s, ok := c.Fun.(*ast.SelectorExpr)
			if !ok || s.Sel.Name != "Unmarshal" {
				return true
			}
			var dest ast.Expr
			if len(c.Args) >= 2 {
				dest = c.Args[1]
			} else if len(c.Args) == 1 {
				dest = c.Args[0]
			}
			t := "?"
			if dest != nil {
				if v := destino(dest); v != "" {
					t = v
				}
			}
			if x, ok := s.X.(*ast.Ident); ok {
				if p, esPkg := imps[x.Name]; esPkg && p != "google.golang.org/protobuf/encoding/protojson" && t == "?" {
					return true // proto.Unmarshal, json.Unmarshal u otro paquete con un destino que no es de v1
				}
			}
			out = append(out, nombre+"|"+t)
			return true
		})
	}
	return out
}

func TestUnmarshalDeLaUIRevisados(t *testing.T) {
	fset := token.NewFileSet()
	archivos, _ := filepath.Glob("*.go")
	var fs []*ast.File
	for _, f := range archivos {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		fs = append(fs, af)
	}
	info := typecheck(fset, fs)
	hallados := map[string]bool{}
	for _, af := range fs {
		for _, h := range hallazgosUnmarshal(fset, af, info) {
			hallados[h] = true
		}
	}
	var sobran, faltan []string
	for n := range hallados {
		if _, ok := unmarshalRevisados[n]; !ok {
			sobran = append(sobran, n)
		}
	}
	for n := range unmarshalRevisados {
		if !hallados[n] {
			faltan = append(faltan, n)
		}
	}
	sort.Strings(sobran)
	sort.Strings(faltan)
	if len(sobran) > 0 {
		t.Errorf("Unmarshal de la UI sin revisar (función|tipo): %v (revisa los campos del request y agrégalo a unmarshalRevisados)", sobran)
	}
	if len(faltan) > 0 {
		t.Errorf("entradas obsoletas en unmarshalRevisados: %v", faltan)
	}
}

// La guardia misma: cada forma de Unmarshal se detecta (si falla, la guardia no sirve).
func TestGuardiaUnmarshalDetectaCadaForma(t *testing.T) {
	const src = `package bridge
import (
	"encoding/json"
	pj "google.golang.org/protobuf/encoding/protojson"
	pb "google.golang.org/protobuf/proto"
	api "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)
func (b *Bridge) A(s string) { var r api.JobSpec; _ = pj.Unmarshal(nil, &r) }
func (b *Bridge) B(s string) { r := &api.JobSpec{}; _ = pj.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(nil, r) }
func (b *Bridge) C(s string) { o := pj.UnmarshalOptions{}; r := api.CreateJobRequest{}; _ = o.Unmarshal(nil, &r) }
func (b *Bridge) D(s string) { var r api.JobSpec; _ = pb.Unmarshal(nil, &r) }
func (b *Bridge) E(s string) { r := new(api.JobSpec); _ = json.Unmarshal(nil, r) }
func (b *Bridge) F(r *api.JobSpec) { _ = json.Unmarshal(nil, &r.Name) }
func (b *Bridge) G(s string) { var x struct{ N string }; _ = json.Unmarshal(nil, &x); var y map[string]any; _ = pb.Unmarshal(nil, nil); _ = json.Unmarshal(nil, &y) }
var H = func(s string) { var r api.PlanPortsRequest; _ = json.Unmarshal(nil, &r) }
var I, J = func() { _ = pj.Unmarshal(nil, nil) }, 0
func (b *Bridge) K() { f := func() { var r api.JobSpec; _ = pj.Unmarshal(nil, &r) }; f() }
`
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := hallazgosUnmarshal(fset, af, typecheck(fset, []*ast.File{af}))
	sort.Strings(got)
	want := []string{"Bridge.A|JobSpec", "Bridge.B|JobSpec", "Bridge.C|CreateJobRequest", "Bridge.D|JobSpec", "Bridge.E|JobSpec", "Bridge.F|JobSpec", "Bridge.K|JobSpec", "H|PlanPortsRequest", "I|?"}
	if strings.Join(got, ",") != strings.Join(want, ",") { // G (destinos locales que no son de v1) no debe salir
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// Un método de *Bridge es la superficie que ve la UI (Wails): ninguno recibe un tipo de gen/macuahuitl/v1 como parámetro
// (la UI podría llenar cualquier campo del proto). Los requests de v1 entran solo como JSON, por el Unmarshal revisado arriba.
func TestMetodosDelPuenteNoRecibenTiposDeV1(t *testing.T) {
	bt := reflect.TypeOf(&Bridge{})
	if bt.NumMethod() < 50 {
		t.Fatalf("solo %d métodos exportados: la reflexión no ve el puente", bt.NumMethod())
	}
	for i := 0; i < bt.NumMethod(); i++ {
		m := bt.Method(i)
		for j := 1; j < m.Type.NumIn(); j++ { // 0 es el receptor
			if p := tipoDeV1(m.Type.In(j), map[reflect.Type]bool{}); p != "" {
				t.Errorf("%s recibe %s (parámetro %d): la UI llenaría campos del proto; recibe JSON y revísalo en unmarshalRevisados", m.Name, p, j)
			}
		}
	}
	// La detección misma: contenedores y estructuras anidadas.
	type anidado struct{ X []map[string]*v1.JobSpec }
	for _, c := range []reflect.Type{reflect.TypeOf(&v1.JobSpec{}), reflect.TypeOf([]v1.JobSpec{}), reflect.TypeOf(map[string]*v1.JobSpec{}), reflect.TypeOf(anidado{}), reflect.TypeOf([2]*v1.JobSpec{})} {
		if tipoDeV1(c, map[reflect.Type]bool{}) == "" {
			t.Errorf("no detecta v1 dentro de %v", c)
		}
	}
	if tipoDeV1(reflect.TypeOf(map[string][]string{}), map[reflect.Type]bool{}) != "" {
		t.Error("falso positivo en tipos simples")
	}
}

// tipoDeV1 devuelve el nombre del primer tipo de gen/macuahuitl/v1 dentro de t (punteros, listas, mapas y campos), o "".
func tipoDeV1(t reflect.Type, visto map[reflect.Type]bool) string {
	if visto[t] {
		return ""
	}
	visto[t] = true
	if t.PkgPath() == pathV1 {
		return t.Name()
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
		return tipoDeV1(t.Elem(), visto)
	case reflect.Map:
		if k := tipoDeV1(t.Key(), visto); k != "" {
			return k
		}
		return tipoDeV1(t.Elem(), visto)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if n := tipoDeV1(t.Field(i).Type, visto); n != "" {
				return n
			}
		}
	}
	return ""
}
