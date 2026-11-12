// Package iosconf lee una configuración IOS/IOS-XE (show running-config) como
// árbol jerárquico por indentación: "interface Gi1/0/1" es padre de sus líneas
// con sangría. Los cuerpos de banner y macro son texto opaco, no secciones.
//
// No hace: validar la sintaxis de IOS ni interpretar comandos.
package iosconf

import (
	"regexp"
	"strings"
	"sync"
)

type Node struct {
	Line     string // texto sin sangría, con espacios repetidos colapsados
	Num      int    // línea en el texto original, desde 1
	Body     string // cuerpo de banner o macro
	Parent   *Node
	Children []*Node
}

// bannerRe: textos con delimitador (banner, refuse/vacant-message de line, menu title/prompt/text).
var bannerRe = regexp.MustCompile(`^(?:banner \S+|(?:vacant|refuse)-message|menu \S+ (?:title|prompt|text \S+)) (.+)$`)

// skip: ruido que no es configuración.
func skip(line string) bool {
	return line == "" || strings.HasPrefix(line, "!") || line == "end" ||
		strings.HasPrefix(line, "Building configuration") || strings.HasPrefix(line, "Current configuration")
}

// Parse arma el árbol. Nunca falla: una línea que no encaja queda donde la deja su sangría.
func Parse(text string) *Node {
	root := &Node{}
	type level struct {
		indent int
		n      *Node
	}
	var stack []level
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimRight(strings.TrimSuffix(lines[i], "\r"), " \t")
		trimmed := strings.TrimLeft(raw, " \t")
		if skip(trimmed) {
			continue
		}
		indent := len(raw) - len(trimmed)
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		parent := root
		if len(stack) > 0 {
			parent = stack[len(stack)-1].n
		}
		n := &Node{Line: strings.Join(strings.Fields(trimmed), " "), Num: i + 1, Parent: parent}
		parent.Children = append(parent.Children, n)
		// Texto libre: hasta el delimitador (banner) o "@" (macro). Sin cierre, llega al final.
		end := ""
		if m := bannerRe.FindStringSubmatch(trimmed); m != nil {
			end = delimiter(m[1])
			if rest := strings.TrimPrefix(m[1], end); strings.Contains(rest, end) {
				n.Body = rest[:strings.Index(rest, end)]
				end = ""
			}
		} else if strings.HasPrefix(n.Line, "macro name ") {
			end = "@"
		}
		if end != "" {
			var body []string
			for i++; i < len(lines); i++ {
				l := strings.TrimSuffix(lines[i], "\r")
				if end == "@" && strings.TrimSpace(l) == "@" || end != "@" && strings.Contains(l, end) {
					if end != "@" {
						body = append(body, l[:strings.Index(l, end)])
					}
					break
				}
				body = append(body, l)
			}
			n.Body = strings.Join(body, "\n")
			continue
		}
		stack = append(stack, level{indent, n})
	}
	return root
}

// delimiter: IOS muestra Ctrl-C como los dos caracteres "^C"; si no, es el primer carácter.
func delimiter(s string) string {
	if strings.HasPrefix(s, "^C") {
		return "^C"
	}
	r := []rune(s)
	return string(r[0])
}

var cache sync.Map

// Compile ancla el patrón a la línea completa: "ip http server" no coincide con "no ip http server".
func Compile(pattern string) (*regexp.Regexp, error) {
	if re, ok := cache.Load(pattern); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(`^(?:` + pattern + `)$`)
	if err != nil {
		return nil, err
	}
	cache.Store(pattern, re)
	return re, nil
}

// Find devuelve los hijos directos que coinciden con pattern (completo). Para patrones
// fijos del código; un patrón inválido es un error de programación y entra en pánico.
func (n *Node) Find(pattern string) []*Node {
	re, err := Compile(pattern)
	if err != nil {
		panic(err)
	}
	return n.FindRe(re)
}

func (n *Node) FindRe(re *regexp.Regexp) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if re.MatchString(c.Line) {
			out = append(out, c)
		}
	}
	return out
}

func (n *Node) Has(pattern string) bool { return len(n.Find(pattern)) > 0 }

// Walk visita todos los descendientes en orden.
func (n *Node) Walk(f func(*Node)) {
	for _, c := range n.Children {
		f(c)
		c.Walk(f)
	}
}

// Path es la línea con sus secciones: "router ospf 1 > address-family ipv4 > network ...".
func (n *Node) Path() string {
	var parts []string
	for p := n; p != nil && p.Parent != nil; p = p.Parent {
		parts = append([]string{p.Line}, parts...)
	}
	return strings.Join(parts, " > ")
}

// String reconstruye el árbol con un espacio de sangría por nivel.
func (n *Node) String() string {
	var b strings.Builder
	var rec func(*Node, int)
	rec = func(x *Node, d int) {
		for _, c := range x.Children {
			b.WriteString(strings.Repeat(" ", d) + c.Line + "\n")
			rec(c, d+1)
		}
	}
	rec(n, 0)
	return b.String()
}
