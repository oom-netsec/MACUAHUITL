package bridge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

func calleeName(e ast.Expr) (recv, name string) {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return "", ""
	}
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return "", f.Name
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name, f.Sel.Name
		}
	case *ast.IndexExpr: // call[T](...)
		if id, ok := f.X.(*ast.Ident); ok {
			return "", id.Name
		}
	}
	return "", ""
}

// internos son los ayudantes de Bridge que ya envuelven sus errores; también se revisan, y los métodos exportados
// pueden devolver su resultado tal cual.
var internos = map[string]bool{"stream": true, "console": true, "terminal": true, "open": true}

// Garantía general: todo método exportado de *Bridge que devuelve error solo lo devuelve como nil, envuelto con
// wrapErr, salido de call(...) o de otro método exportado de Bridge (que se revisa aparte). Un `return err` vale solo
// si toda asignación a esa variable, en el método, viene de call(...) o wrapErr(...). Lo demás llegaría a TS sin la
// forma {message, code, reason, metadata}.
func TestMetodosDelPuenteDevuelvenErrorEnvuelto(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || !(fn.Name.IsExported() || internos[fn.Name.Name]) || fn.Body == nil || fn.Type.Results == nil {
					continue
				}
				if st, ok := fn.Recv.List[0].Type.(*ast.StarExpr); !ok || st.X.(*ast.Ident).Name != "Bridge" {
					continue
				}
				errAt, n := -1, 0
				for _, r := range fn.Type.Results.List {
					k := max(len(r.Names), 1)
					if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
						errAt = n + k - 1
					}
					n += k
				}
				if errAt < 0 {
					continue
				}
				checked++
				safe := safeVars(fn.Body)
				where := func(p token.Pos) string { return fset.Position(p).String() }
				ast.Inspect(fn.Body, func(nd ast.Node) bool {
					if _, lit := nd.(*ast.FuncLit); lit {
						return false // las gorutinas y los cierres no devuelven al llamador
					}
					rs, ok := nd.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					var e ast.Expr
					switch {
					case len(rs.Results) == 0:
						t.Errorf("%s: return desnudo en %s", where(rs.Pos()), fn.Name.Name)
						return true
					case len(rs.Results) == 1 && n > 1:
						e = rs.Results[0] // return f() con varios valores
					default:
						e = rs.Results[errAt]
					}
					if !okExpr(e, safe, len(rs.Results) == 1 && n > 1) {
						t.Errorf("%s: %s devuelve un error sin wrapErr", where(rs.Pos()), fn.Name.Name)
					}
					return true
				})
			}
		}
	}
	if checked < 100 {
		t.Fatalf("solo se revisaron %d métodos: ¿cambió el recorrido?", checked)
	}
}

func okExpr(e ast.Expr, safe map[string]bool, multi bool) bool {
	if id, ok := e.(*ast.Ident); ok && !multi {
		return id.Name == "nil" || safe[id.Name]
	}
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND { // &Error{...}
		if cl, ok := u.X.(*ast.CompositeLit); ok {
			if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "Error" {
				return true
			}
		}
	}
	recv, name := calleeName(e)
	return name == "wrapErr" || name == "call" || (recv == "b" && name != "" && (name[0] >= 'A' && name[0] <= 'Z' || internos[name]))
}

// safeVars son las variables de error cuyas asignaciones, todas, vienen de call(...) o wrapErr(...).
func safeVars(body *ast.BlockStmt) map[string]bool {
	ok, bad := map[string]bool{}, map[string]bool{}
	ast.Inspect(body, func(nd ast.Node) bool {
		if _, lit := nd.(*ast.FuncLit); lit {
			return false
		}
		as, isAs := nd.(*ast.AssignStmt)
		if !isAs {
			return true
		}
		for i, l := range as.Lhs {
			id, isID := l.(*ast.Ident)
			if !isID || id.Name == "_" {
				continue
			}
			var rhs ast.Expr
			if len(as.Rhs) == len(as.Lhs) {
				rhs = as.Rhs[i]
			} else if len(as.Rhs) == 1 && i == len(as.Lhs)-1 {
				rhs = as.Rhs[0] // x, err := f()
			}
			if _, n := calleeName(rhs); rhs != nil && (n == "call" || n == "wrapErr") {
				ok[id.Name] = true
			} else {
				bad[id.Name] = true
			}
		}
		return true
	})
	for k := range bad {
		delete(ok, k)
	}
	return ok
}
