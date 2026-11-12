// Package noegress prohíbe imports de red fuera de los paquetes permitidos (spec §10.5).
//
// Es la prueba estática de la promesa "la aplicación solo conecta a destinos
// que escribió el ingeniero": todo el código de red vive en pocos paquetes
// que un auditor puede leer completos.
package noegress

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ModulePath es la ruta del módulo; los paquetes fuera de él no se revisan.
const ModulePath = "github.com/oom-netsec/MACUAHUITL"

// forbidden son los imports que pueden abrir sockets o lanzar procesos.
var forbidden = map[string]bool{
	"C":                       true, // cgo: socket() desde C sin pasar por Go
	"crypto/tls":              true,
	"log/syslog":              true,
	"os/exec":                 true,
	"syscall":                 true,
	"golang.org/x/sys/unix":   true,
	"golang.org/x/crypto/ssh": true,
	"google.golang.org/grpc":  true, // solo la raíz: grpc/codes y grpc/status son inofensivos
}

// forbiddenPrefixes cubren familias completas; harmless son las excepciones sin red.
var (
	forbiddenPrefixes = []string{"net", "golang.org/x/net"}
	harmless          = map[string]bool{"net/netip": true, "net/url": true, "net/mail": true}
)

func isForbidden(path string) bool {
	if forbidden[path] {
		return true
	}
	if harmless[path] {
		return false
	}
	for _, p := range forbiddenPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

var allowed = []string{
	"internal/transport",
	"internal/diag",
	"internal/ipc",
	"internal/sys", // endurecimiento: prctl, setrlimit, mlockall
	"gen",
	"test/simulator",
	"tools",
}

var Analyzer = &analysis.Analyzer{
	Name: "noegress",
	Doc:  "prohíbe imports de red fuera de internal/transport, internal/diag e internal/ipc",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	// Los paquetes de test externos (foo_test) y sus variantes llevan sufijos; se recortan.
	pkg := strings.TrimSuffix(pass.Pkg.Path(), "_test")
	rel, ok := strings.CutPrefix(pkg, ModulePath+"/")
	if pkg == ModulePath {
		rel, ok = "", true
	}
	if !ok || isAllowed(rel) {
		return nil, nil
	}
	for _, f := range pass.Files {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !isForbidden(path) {
				continue
			}
			pass.Reportf(imp.Pos(), "noegress: %s importa %q; la red solo se permite en internal/transport, internal/diag e internal/ipc (spec §10.5)", pkg, path)
		}
	}
	return nil, nil
}

func isAllowed(rel string) bool {
	for _, a := range allowed {
		if rel == a || strings.HasPrefix(rel, a+"/") {
			return true
		}
	}
	return false
}
