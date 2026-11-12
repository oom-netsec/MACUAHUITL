package simulator

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

// Running (fase 16c): el equipo guarda un running-config completo y jerárquico (Config.Running). `show running-config` lo muestra tal como
// quedó tras las líneas recibidas en modo configuración: encabezados de sección (que cambian el contexto), `no X`, líneas de un solo valor
// que sustituyen a la anterior, ACL con números de secuencia y comandos globales. Es un modelo de lo que hace IOS, no de todo IOS.

type cnode struct {
	line string
	kids []*cnode
}

type runCfg struct {
	mu   sync.Mutex
	root *cnode
}

func newRunCfg(text string) *runCfg {
	var conv func(n *iosconf.Node) *cnode
	conv = func(n *iosconf.Node) *cnode {
		c := &cnode{line: n.Line}
		for _, k := range n.Children {
			c.kids = append(c.kids, conv(k))
		}
		return c
	}
	return &runCfg{root: conv(iosconf.Parse(text))}
}

var simSections = []string{"interface ", "router ", "line ", "vlan ", "ip access-list ", "ipv6 access-list ", "route-map ", "class-map ", "policy-map ", "address-family "}

func sectionLine(l string) bool {
	for _, p := range simSections {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

func (n *cnode) child(line string) *cnode {
	for _, k := range n.kids {
		if k.line == line {
			return k
		}
	}
	return nil
}

func (n *cnode) at(path []string) *cnode {
	for _, p := range path {
		if n = n.child(p); n == nil {
			return nil
		}
	}
	return n
}

// section devuelve las secciones de primer nivel cuyo encabezado cumple re, con sus líneas hijas (`show running-config | section RE`).
func (c *runCfg) section(re *regexp.Regexp) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	var rec func(n *cnode, d int)
	rec = func(n *cnode, d int) {
		b.WriteString(strings.Repeat(" ", d) + n.line + "\n")
		for _, k := range n.kids {
			rec(k, d+1)
		}
	}
	for _, k := range c.root.kids {
		if re.MatchString(k.line) {
			rec(k, 0)
		}
	}
	return b.String()
}

func (c *runCfg) render() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	var rec func(n *cnode, d int)
	rec = func(n *cnode, d int) {
		for _, k := range n.kids {
			b.WriteString(strings.Repeat(" ", d) + k.line + "\n")
			rec(k, d+1)
			if d == 0 && len(k.kids) > 0 {
				b.WriteString("!\n")
			}
		}
	}
	rec(c.root, 0)
	return fmt.Sprintf("Building configuration...\n\nCurrent configuration : %d bytes\n!\n%send\n\n", b.Len(), b.String())
}

// simKey agrupa las líneas que se sustituyen entre sí en este modelo.
func simKey(path []string, line string) string {
	body := strings.TrimPrefix(line, "no ")
	var list []string
	if len(path) > 0 && strings.HasPrefix(path[0], "interface ") {
		list = []string{"description", "switchport access vlan", "switchport voice vlan", "switchport trunk allowed vlan", "switchport trunk native vlan", "switchport mode", "speed", "duplex",
			"spanning-tree portfast", "spanning-tree bpduguard", "storm-control broadcast", "storm-control multicast", "storm-control unicast",
			"switchport port-security maximum", "switchport port-security violation", "switchport port-security aging time", "switchport port-security"}
		if f := strings.Fields(body); len(f) >= 4 && f[0] == "ip" && f[1] == "access-group" {
			return "ip access-group " + f[len(f)-1]
		}
	} else if len(path) == 0 {
		// Claves que dependen de un nombre o una dirección: la community, el servidor NTP y la ruta estática (R M salto) se sustituyen o se
		// quitan por ellas, sin importar las opciones que sigan (modelo de la documentación de Cisco, sin validar en laboratorio).
		if f := strings.Fields(body); len(f) >= 3 && (f[0] == "snmp-server" && f[1] == "community" || f[0] == "ntp" && f[1] == "server") {
			return strings.Join(f[:3], " ")
		} else if len(f) >= 5 && f[0] == "ip" && f[1] == "route" {
			return strings.Join(f[:5], " ")
		}
		list = []string{"banner motd", "hostname", "snmp-server location", "snmp-server contact", "clock timezone", "logging buffered", "logging trap", "logging facility",
			"logging source-interface", "ip domain-name", "ip domain name", "spanning-tree mode", "errdisable recovery interval"}
	}
	for _, p := range list {
		if body == p || strings.HasPrefix(body, p+" ") {
			return p
		}
	}
	return ""
}

func firstWord(l string) string { f := strings.Fields(l); return f[0] }

func isSeq(l string) bool { _, err := strconv.Atoi(firstWord(l)); return err == nil }

// apply aplica una línea en el contexto ctx y devuelve el contexto nuevo.
func (c *runCfg) apply(ctx []string, line string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(ctx); i >= 0; i-- {
		if p := append(slices.Clone(ctx[:i]), line); true {
			if n := c.root.at(p); n != nil && (len(n.kids) > 0 || sectionLine(line)) {
				return p
			}
		}
	}
	if sectionLine(line) { // IOS crea la interfaz o la ACL que se nombra
		c.root.kids = append(c.root.kids, &cnode{line: line})
		return []string{line}
	}
	parent := c.root.at(ctx)
	if parent == nil {
		return ctx
	}
	neg := strings.HasPrefix(line, "no ")
	body := strings.TrimPrefix(line, "no ")
	if len(ctx) == 0 && !neg && body == "logging trap informational" { // el nivel de fábrica no se muestra: ponerlo quita la línea
		neg = true
	}
	acl := len(ctx) > 0 && strings.Contains(ctx[len(ctx)-1], "access-list")
	del := func(f func(*cnode) bool) {
		parent.kids = slices.DeleteFunc(parent.kids, f)
	}
	switch {
	case acl && !neg && isSeq(line):
		del(func(k *cnode) bool { return isSeq(k.line) && firstWord(k.line) == firstWord(line) })
		parent.kids = append(parent.kids, &cnode{line: line})
		slices.SortStableFunc(parent.kids, func(a, b *cnode) int {
			x, _ := strconv.Atoi(firstWord(a.line))
			y, _ := strconv.Atoi(firstWord(b.line))
			return x - y
		})
	case acl && neg && isSeq(body) && !strings.Contains(body, " "):
		del(func(k *cnode) bool { return isSeq(k.line) && firstWord(k.line) == body })
	default:
		if k := simKey(ctx, body); k != "" {
			del(func(n *cnode) bool { return simKey(ctx, n.line) == k })
			if !neg {
				parent.kids = append(parent.kids, &cnode{line: line})
			}
		} else if neg && parent.child(body) != nil {
			del(func(n *cnode) bool { return n.line == body })
		} else if !neg && parent.child("no "+line) != nil {
			del(func(n *cnode) bool { return n.line == "no "+line })
		} else if parent.child(line) == nil {
			parent.kids = append(parent.kids, &cnode{line: line})
		}
	}
	return ctx
}

func promptMode(ctx []string) string {
	switch {
	case len(ctx) == 0:
		return "config"
	case strings.HasPrefix(ctx[0], "interface "):
		return "config-if"
	case strings.Contains(ctx[0], "access-list"):
		return "config-ext-nacl"
	}
	return "config-sub"
}
