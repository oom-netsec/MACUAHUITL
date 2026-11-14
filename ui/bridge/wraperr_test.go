package bridge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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

// typecheck resuelve cada identificador a su objeto (go/types, sin importador: los errores de imports no importan,
// solo hace falta saber qué variable es cuál, también con sombras y cierres).
func typecheck(fset *token.FileSet, files []*ast.File) *types.Info {
	info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	_, _ = (&types.Config{Error: func(error) {}}).Check("bridge", fset, files, info)
	return info
}

func objOf(info *types.Info, id *ast.Ident) types.Object {
	if o := info.Defs[id]; o != nil {
		return o
	}
	return info.Uses[id]
}

// checkMethod reporta cada return de un método de *Bridge que puede llegar a TS con un error sin envolver. Devuelve
// false si el método no devuelve error.
func checkMethod(info *types.Info, fn *ast.FuncDecl, report func(token.Pos, string)) bool {
	errAt, n := -1, 0
	var named types.Object // el resultado de error, si tiene nombre
	for _, r := range fn.Type.Results.List {
		k := max(len(r.Names), 1)
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
			errAt = n + k - 1
			if len(r.Names) > 0 {
				named = objOf(info, r.Names[len(r.Names)-1])
			}
		}
		n += k
	}
	if errAt < 0 {
		return false
	}
	safe := safeVars(info, fn.Body)
	// Un resultado con nombre lo puede cambiar un defer después del return: toda asignación suya tiene que ser segura.
	if named != nil && !safe[named] && assigned(info, fn.Body, named) {
		report(fn.Pos(), fn.Name.Name+": el resultado de error con nombre recibe un error sin wrapErr")
	}
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
			report(rs.Pos(), "return desnudo en "+fn.Name.Name)
			return true
		case len(rs.Results) == 1 && n > 1:
			e = rs.Results[0] // return f() con varios valores
		default:
			e = rs.Results[errAt]
		}
		if !okExpr(info, e, safe, len(rs.Results) == 1 && n > 1) {
			report(rs.Pos(), fn.Name.Name+" devuelve un error sin wrapErr")
		}
		return true
	})
	return true
}

// Garantía general: todo método exportado de *Bridge que devuelve error solo lo devuelve como nil, envuelto con
// wrapErr, salido de call(...) o de otro método exportado de Bridge (que se revisa aparte). Un `return err` vale solo
// si toda asignación a esa variable, en el método y en sus cierres, viene de call(...) o wrapErr(...). Lo demás
// llegaría a TS sin la forma {message, code, reason, metadata}.
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
	info := typecheck(fset, files)
	checked := 0
	for _, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || !bridgeMethod(fn) {
				continue
			}
			if checkMethod(info, fn, func(p token.Pos, msg string) { t.Errorf("%s: %s", fset.Position(p), msg) }) {
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("solo se revisaron %d métodos: ¿cambió el recorrido?", checked)
	}
}

func bridgeMethod(fn *ast.FuncDecl) bool {
	if fn.Recv == nil || !(fn.Name.IsExported() || internos[fn.Name.Name]) || fn.Body == nil || fn.Type.Results == nil {
		return false
	}
	st, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	return ok && st.X.(*ast.Ident).Name == "Bridge"
}

func okExpr(info *types.Info, e ast.Expr, safe map[types.Object]bool, multi bool) bool {
	if id, ok := e.(*ast.Ident); ok && !multi {
		return id.Name == "nil" || safe[objOf(info, id)]
	}
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND { // &Error{...}
		if cl, ok := u.X.(*ast.CompositeLit); ok {
			if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "Error" {
				return true
			}
		}
	}
	recv, name := calleeName(e)
	return recv == "" && (name == "wrapErr" || name == "call") || (recv == "b" && name == "bridgeErr") || (recv == "b" && name != "" && (name[0] >= 'A' && name[0] <= 'Z' || internos[name]))
}

func wraps(e ast.Expr) bool {
	recv, n := calleeName(e)
	return e != nil && (recv == "" && (n == "call" || n == "wrapErr") || recv == "b" && n == "bridgeErr")
}

// safeVars son las variables cuyas asignaciones, todas (también en cierres), vienen de call(...) o wrapErr(...). La
// variable de un range y toda variable de la que se toma la dirección (&v) quedan inseguras.
func safeVars(info *types.Info, body *ast.BlockStmt) map[types.Object]bool {
	ok, bad := map[types.Object]bool{}, map[types.Object]bool{}
	set := func(e ast.Expr, good bool) {
		id, isID := e.(*ast.Ident)
		if !isID || id.Name == "_" {
			return
		}
		o := objOf(info, id)
		if o == nil {
			return
		}
		if good {
			ok[o] = true
		} else {
			bad[o] = true
		}
	}
	mark := func(lhs, rhs []ast.Expr) {
		for i, l := range lhs {
			var r ast.Expr
			if len(rhs) == len(lhs) {
				r = rhs[i]
			} else if len(rhs) == 1 && i == len(lhs)-1 {
				r = rhs[0] // x, err := f()
			}
			set(l, wraps(r))
		}
	}
	ast.Inspect(body, func(nd ast.Node) bool {
		switch x := nd.(type) {
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
		case *ast.RangeStmt:
			set(x.Key, false)
			set(x.Value, false)
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				set(x.X, false)
			}
		}
		return true
	})
	for k := range bad {
		delete(ok, k)
	}
	return ok
}

// assigned dice si la variable recibe alguna asignación en el cuerpo (también en cierres).
func assigned(info *types.Info, body *ast.BlockStmt, o types.Object) bool {
	found := false
	ast.Inspect(body, func(nd ast.Node) bool {
		if as, ok := nd.(*ast.AssignStmt); ok {
			for _, l := range as.Lhs {
				if id, ok := l.(*ast.Ident); ok && objOf(info, id) == o {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// La prueba no se deja engañar: cierres, declaraciones var, range, punteros, sombras en bloques y un resultado con
// nombre que cambia un defer.
func TestCheckMethodVeLosCasosDificiles(t *testing.T) {
	for _, c := range []struct {
		name, src string
		ok        bool
	}{
		{"solo call", `func (b *Bridge) X() error { err := call(); return err }`, true},
		{"cierre que la pisa", `func (b *Bridge) X() error { err := call(); func() { err = errors.New("x") }(); return err }`, false},
		{"cierre con su propio err", `func (b *Bridge) X() error { err := call(); func() { err := call(); err = errors.New("x"); _ = err }(); return err }`, true},
		{"sombra en un bloque del cierre", `func (b *Bridge) X() error { err := call(); func() { if err := g(); err != nil {}; err = errors.New("x") }(); return err }`, false},
		{"var con otro origen", `func (b *Bridge) X() error { var err = errors.New("x"); err = call(); return err }`, false},
		{"var con call", `func (b *Bridge) X() error { var err = call(); return err }`, true},
		{"var sin valor y luego call", `func (b *Bridge) X() error { var err error; err = call(); return err }`, true},
		{"range que la pisa", `func (b *Bridge) X(es []error) error { err := call(); for _, err = range es {}; return err }`, false},
		{"range que la declara", `func (b *Bridge) X(es []error) error { for _, err := range es { return err }; return nil }`, false},
		{"por puntero", `func (b *Bridge) X() error { err := call(); p := &err; *p = errors.New("x"); return err }`, false},
		{"sombra en if no contamina", `func (b *Bridge) X() error { if err := g(); err != nil {}; err := call(); return err }`, true},
		{"resultado con nombre y defer", `func (b *Bridge) X() (err error) { defer func() { err = errors.New("x") }(); return nil }`, false},
		{"resultado con nombre envuelto en defer", `func (b *Bridge) X() (err error) { defer func() { err = wrapErr(err) }(); err = call(); return err }`, true},
		{"call de otro receptor", `func (b *Bridge) X() error { return x.call() }`, false},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x.go", "package bridge\ntype Bridge struct{}\n"+c.src+"\n", 0)
		if err != nil {
			t.Fatal(c.name, err)
		}
		info := typecheck(fset, []*ast.File{f})
		var msgs []string
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && bridgeMethod(fn) {
				checkMethod(info, fn, func(_ token.Pos, m string) { msgs = append(msgs, m) })
			}
		}
		if (len(msgs) == 0) != c.ok {
			t.Errorf("%s: aceptado = %v, se esperaba %v (%v)", c.name, len(msgs) == 0, c.ok, msgs)
		}
	}
}
