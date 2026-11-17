package bridge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// unmarshalRevisados fija los puntos donde el puente deserializa JSON de la UI directo a un
// request gRPC (la UI puede poner cualquier campo del proto). Revisados el 2026-11-17: ninguno
// tiene campos de actor, ids asignados por el núcleo ni rutas internas; todo campo es una
// elección legítima del usuario y el núcleo valida y es quien decide (guard, modo asistido).
// Una entrada nueva exige revisar los campos de su request antes de agregarla aquí.
var unmarshalRevisados = map[string]string{
	// JobSpec: nombre, objetivos, credenciales, playbooks, salida, horario y opciones (disable_masking,
	// accept_changed_host_keys) que el usuario marca en el formulario; no hay actor ni job_id.
	"Bridge.CreateJob":    "JobSpec",
	"Bridge.ChangeCreate": "JobSpec",
	// Planes del modo asistido: solo lectura; ejecutar exige assisted=true que viaja aparte en AssistStart.
	// write_memory y las huellas aceptadas las elige el usuario por plan.
	"Bridge.AssistPlanPorts":      "PlanPortsRequest",
	"Bridge.AssistPlanSnippet":    "PlanSnippetRequest",
	"Bridge.AssistPlanCredRotate": "PlanCredRotateRequest",
	"Bridge.AssistPlanRestore":    "PlanRestoreRequest",
	// Calculadoras: entradas numéricas y de texto de un cálculo puro, sin efectos.
	"calcRPC": "Calc*Request",
}

func TestUnmarshalDeLaUIRevisados(t *testing.T) {
	fset := token.NewFileSet()
	archivos, _ := filepath.Glob("*.go")
	hallados := map[string]bool{}
	for _, f := range archivos {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			nombre := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				if st, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
					nombre = st.X.(*ast.Ident).Name + "." + nombre
				}
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Unmarshal" {
						if x, ok := s.X.(*ast.Ident); ok && x.Name == "protojson" {
							hallados[nombre] = true
						}
					}
				}
				return true
			})
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
		t.Errorf("protojson.Unmarshal de la UI sin revisar: %v (revisa los campos del request y agrégalo a unmarshalRevisados)", sobran)
	}
	if len(faltan) > 0 {
		t.Errorf("entradas obsoletas en unmarshalRevisados: %v", faltan)
	}
}
