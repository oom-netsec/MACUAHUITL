package bridge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
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
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	checked := 0
	{
		for _, f := range files {
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
	mark := func(lhs []ast.Expr, rhs []ast.Expr) {
		for i, l := range lhs {
			id, isID := l.(*ast.Ident)
			if !isID || id.Name == "_" {
				continue
			}
			var r ast.Expr
			if len(rhs) == len(lhs) {
				r = rhs[i]
			} else if len(rhs) == 1 && i == len(lhs)-1 {
				r = rhs[0] // x, err := f()
			}
			if _, n := calleeName(r); r != nil && (n == "call" || n == "wrapErr") {
				ok[id.Name] = true
			} else {
				bad[id.Name] = true
			}
		}
	}
	// En un cierre solo cuenta `x = …` sobre un nombre que el cierre no declara: ese pisa la variable del método;
	// un `err :=` del cierre es otra variable.
	ast.Inspect(body, func(nd ast.Node) bool {
		switch x := nd.(type) {
		case *ast.FuncLit:
			own := map[string]bool{}
			ast.Inspect(x.Body, func(n ast.Node) bool {
				switch y := n.(type) {
				case *ast.AssignStmt:
					if y.Tok == token.DEFINE {
						for _, l := range y.Lhs {
							if id, ok := l.(*ast.Ident); ok {
								own[id.Name] = true
							}
						}
					}
				case *ast.ValueSpec:
					for _, id := range y.Names {
						own[id.Name] = true
					}
				}
				return true
			})
			ast.Inspect(x.Body, func(n ast.Node) bool {
				if y, ok := n.(*ast.AssignStmt); ok && y.Tok != token.DEFINE {
					for _, l := range y.Lhs {
						if id, ok := l.(*ast.Ident); ok && !own[id.Name] && id.Name != "_" {
							bad[id.Name] = true
						}
					}
				}
				return true
			})
			return false
		case *ast.AssignStmt:
			mark(x.Lhs, x.Rhs)
		case *ast.ValueSpec: // var err = f(); sin valor arranca en nil y no cuenta
			if len(x.Values) > 0 {
				lhs := make([]ast.Expr, len(x.Names))
				for i, n := range x.Names {
					lhs[i] = n
				}
				mark(lhs, x.Values)
			}
		}
		return true
	})
	for k := range bad {
		delete(ok, k)
	}
	return ok
}

// safeVars no se deja engañar: una asignación dentro de un cierre o una declaración var con otro origen hacen que la
// variable deje de ser segura.
func TestSafeVarsVeCierresYDeclaracionesVar(t *testing.T) {
	for _, c := range []struct {
		name, body string
		safe       bool
	}{
		{"solo call", `err := call(); return err`, true},
		{"cierre que la pisa", `err := call(); func() { err = errors.New("x") }(); return err`, false},
		{"cierre con su propio err", `err := call(); func() { err := call(); err = errors.New("x"); _ = err }(); return err`, true},
		{"var con otro origen", `var err = errors.New("x"); err = call(); return err`, false},
		{"var con call", `var err = call(); return err`, true},
		{"var sin valor y luego call", `var err error; err = call(); return err`, true},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\nfunc f() error {\n"+c.body+"\n}\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		body := f.Decls[0].(*ast.FuncDecl).Body
		if got := safeVars(body)["err"]; got != c.safe {
			t.Errorf("%s: seguro = %v, se esperaba %v", c.name, got, c.safe)
		}
	}
}
