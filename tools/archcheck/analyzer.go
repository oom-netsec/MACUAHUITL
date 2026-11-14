// Package archcheck verifica por máquina las reglas de dependencia del ADR 0008 §4:
//   - un dominio no importa core, service, gen, grpc ni red;
//   - un dominio no importa otro dominio (salvo lo compartido, ver Shared);
//   - core no importa un dominio directamente (solo vía service);
//   - la raíz de un dominio tampoco importa internal/ipc ni internal/transport;
//   - un servicio (internal/service/<área>) no importa core ni el servicio de otra área.
//
// Solo los subpaquetes de internal/diag (internal/diag/dnsq) son una capa de red:
// pueden usar net, gen, ipc y transport, pero nunca core, service ni otro dominio.
// Los subpaquetes de cualquier otro dominio se tratan como su raíz.
package archcheck

import (
	"go/ast"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ModulePath es la ruta del módulo; los paquetes fuera de él no se revisan.
const ModulePath = "github.com/oom-netsec/MACUAHUITL"

var Analyzer = &analysis.Analyzer{
	Name: "archcheck",
	Doc:  "reglas de dependencia entre dominio, servicio y núcleo (ADR 0008 §4)",
	Run:  run,
}

// under dice si rel es dir o está dentro de él.
func under(rel, dir string) bool { return rel == dir || strings.HasPrefix(rel, dir+"/") }

func underAny(rel string, dirs []string) bool {
	for _, d := range dirs {
		if under(rel, d) {
			return true
		}
	}
	return false
}

// domainOf devuelve el dominio al que pertenece rel ("" si no es de dominio).
func domainOf(rel string) string {
	for _, d := range Domains {
		if under(rel, d) {
			return d
		}
	}
	return ""
}

// isNetwork cubre net y x/net salvo los paquetes sin sockets (igual que noegress).
func isNetwork(path string) bool {
	switch path {
	case "net/netip", "net/url", "net/mail":
		return false
	}
	return under(path, "net") || under(path, "golang.org/x/net")
}

func isGRPC(path string) bool {
	// grpc/codes y grpc/status son inofensivos, como en noegress.
	return path == "google.golang.org/grpc" || strings.HasPrefix(path, "google.golang.org/grpc/") &&
		path != "google.golang.org/grpc/codes" && path != "google.golang.org/grpc/status"
}

// serviceArea devuelve internal/service/<área> si rel es un servicio de área
// (servicetest es apoyo de pruebas, no un área).
func serviceArea(rel string) string {
	rest, ok := strings.CutPrefix(rel, "internal/service/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	if name == "servicetest" {
		return ""
	}
	return "internal/service/" + name
}

// netLayer: los subpaquetes de internal/diag son la capa de red del dominio diag.
func netLayer(rel string) bool { return under(rel, "internal/diag") && rel != "internal/diag" }

func run(pass *analysis.Pass) (any, error) {
	// Los paquetes de test externos (foo_test) y el main generado (foo.test) llevan sufijos; se recortan.
	pkg := strings.TrimSuffix(strings.TrimSuffix(pass.Pkg.Path(), ".test"), "_test")
	rel, ok := strings.CutPrefix(pkg, ModulePath+"/")
	if !ok {
		return nil, nil
	}
	checkTestOnlyLang(pass, rel)
	dom := domainOf(rel)
	isCore := under(rel, "internal/core")
	area := serviceArea(rel)
	if dom == "" && !isCore && area == "" {
		return nil, nil
	}
	root := !netLayer(rel)
	for _, f := range pass.Files {
		isTest := strings.HasSuffix(pass.Fset.File(f.Pos()).Name(), "_test.go")
		// Las pruebas de core son de integración: arman dobles de dominio a propósito.
		if isCore && isTest {
			continue
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if msg := check(rel, dom, area, isCore, root, isTest, path); msg != "" {
				pass.Reportf(imp.Pos(), "archcheck: %s importa %q: %s (ADR 0008 §4)", rel, path, msg)
			}
		}
	}
	return nil, nil
}

// check devuelve el motivo de la violación, o "" si el import es válido.
func check(rel, dom, area string, isCore, root, isTest bool, path string) string {
	target, internal := strings.CutPrefix(path, ModulePath+"/")
	if isCore {
		if d := domainOf(target); internal && d != "" && !underAny(target, Shared) {
			return "core no importa dominios (" + d + "); solo vía internal/service"
		}
		return ""
	}
	if area != "" {
		switch {
		case under(target, "internal/core"):
			return "un servicio no depende de core; recibe lo que necesita por service.Deps"
		case under(target, "internal/service/servicetest"):
			if !isTest {
				return "servicetest es solo para pruebas"
			}
		case internal && under(target, "internal/service") && target != "internal/service" && !under(target, area):
			return "un servicio no importa el de otra área (" + target + ")"
		}
		return ""
	}
	if internal {
		switch {
		case under(target, "internal/core"), under(target, "internal/service"):
			return "un dominio no depende de core ni de service"
		case under(target, "gen") && root:
			return "un dominio no importa gen; eso es de service"
		case (under(target, "internal/ipc") || under(target, "internal/transport")) && root:
			return "un dominio no importa ipc ni transport; eso es de service o de su capa de red"
		}
		if d := domainOf(target); d != "" && d != dom && !underAny(target, Shared) {
			return "otro dominio (" + d + "); lo compartido va en internal/parse o en Shared"
		}
		return ""
	}
	if root && (isNetwork(path) || isGRPC(path)) {
		return "un dominio no importa red ni grpc; eso va en su capa de red o en service"
	}
	return ""
}

// checkTestOnlyLang: i18n.SetDefault e i18ntest cambian el idioma por omisión del proceso: solo valen en archivos
// *_test.go (y en el propio apoyo de pruebas).
func checkTestOnlyLang(pass *analysis.Pass, rel string) {
	if under(rel, "internal/i18n") { // el paquete que lo define y su apoyo de pruebas
		return
	}
	const i18nPath, testPath = ModulePath + "/internal/i18n", ModulePath + "/internal/i18n/i18ntest"
	for _, f := range pass.Files {
		if strings.HasSuffix(pass.Fset.File(f.Pos()).Name(), "_test.go") {
			continue
		}
		for _, imp := range f.Imports {
			if path, err := strconv.Unquote(imp.Path.Value); err == nil && path == testPath {
				pass.Reportf(imp.Pos(), "archcheck: i18ntest es solo para pruebas (*_test.go)")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if fn, ok := typeutilCallee(pass, call); ok && fn.Name() == "SetDefault" && fn.Pkg() != nil && fn.Pkg().Path() == i18nPath {
				pass.Reportf(call.Pos(), "archcheck: SetDefault es solo para pruebas (*_test.go)")
			}
			return true
		})
	}
}

func typeutilCallee(pass *analysis.Pass, call *ast.CallExpr) (*types.Func, bool) {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.Ident:
		id = f
	default:
		return nil, false
	}
	fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
	return fn, ok
}
