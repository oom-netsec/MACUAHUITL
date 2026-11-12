package compliance

import (
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

type rule struct {
	id, title, ref string
	check          func(cfg *iosconf.Node) (Status, i18n.Text, []*iosconf.Node)
}

// titleTx es el título de la regla como texto de catálogo; los que son un comando de IOS no se traducen.
func (r rule) titleTx() i18n.Text {
	if _, ok := noTitleKey[r.id]; ok {
		return i18n.Text{}
	}
	return i18n.Tx("compliance.title." + r.id)
}

var noTitleKey = map[string]bool{"password-encryption": true, "source-route": true, "tcp-keepalives": true}

const guide = "Cisco Guide to Harden Cisco IOS XE Devices"

// Sin validar en laboratorio: escritas sobre la guía pública y la referencia de comandos.
var rules = []rule{
	{"aaa-new-model", "AAA habilitado (aaa new-model)", guide + " — Management Plane: AAA", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		return need(c, `aaa new-model`, "compliance.detail.no_aaa")
	}},
	{"ssh-v2", "Solo SSH versión 2", guide + " — Management Plane: SSH", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		return need(c, `ip ssh version 2`, "compliance.detail.no_ssh2")
	}},
	{"vty-transport", "VTY solo por SSH (sin telnet)", guide + " — Management Plane: Restricting Interactive Access", vtyTransport},
	{"http-server", "Sin HTTP en claro; HTTPS solo con autenticación", guide + " — Management Plane: HTTP", httpServer},
	{"ntp-auth", "NTP autenticado", guide + " — Management Plane: Network Time Protocol", ntpAuth},
	{"logging-host", "Logging a un servidor remoto", guide + " — Management Plane: Logging", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		return need(c, `logging (host \S+.*|\d+\.\d+\.\d+\.\d+.*)`, "compliance.detail.no_logging")
	}},
	{"password-encryption", "service password-encryption", guide + " — Password Management", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		return need(c, `service password-encryption`, "compliance.detail.no_pwenc")
	}},
	{"secret-types", "Secretos tipo 8/9 en vez de contraseñas reversibles", guide + " — Password Management: enable secret / username secret", secretTypes},
	{"banner", "Banner de acceso legal", guide + " — Management Plane: Warning Banners", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		return need(c, `banner (login|motd) .*`, "compliance.detail.no_banner")
	}},
	{"exec-timeout", "exec-timeout en consola y VTY", guide + " — Management Plane: Session Timeouts", execTimeout},
	{"copp", "Control Plane Policing presente", guide + " — Control Plane: CoPP", copp},
	{"snmp-community", "SNMP sin comunidades por defecto ni v1/v2c sin ACL", guide + " — Management Plane: SNMP", snmpCommunity},
	{"source-route", "no ip source-route", guide + " — Data Plane: IP Source Routing", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		return need(c, `no ip source-route`, "compliance.detail.no_srcroute")
	}},
	{"tcp-keepalives", "service tcp-keepalives-in", guide + " — Management Plane: TCP Keepalives", func(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
		if c.Has(`service tcp-keepalives-in`) {
			return Pass, i18n.Text{}, nil
		}
		return Warn, i18n.Tx("compliance.detail.no_keepalives"), nil
	}},
}

// Hardening evalúa todas las reglas incluidas, en orden.
func Hardening(cfg *iosconf.Node) []Finding {
	out := make([]Finding, 0, len(rules))
	for _, r := range rules {
		st, detail, ns := r.check(cfg)
		out = append(out, Finding{Rule: r.id, Title: r.title, Status: st, Detail: detail.In(i18n.Es), Lines: lineNums(ns), Reference: r.ref, TitleTx: r.titleTx(), DetailTx: detail})
	}
	return out
}

func need(c *iosconf.Node, pattern, why string) (Status, i18n.Text, []*iosconf.Node) {
	if c.Has(pattern) {
		return Pass, i18n.Text{}, nil
	}
	return Fail, i18n.Tx(why), nil
}

func vtyTransport(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	vtys := c.Find(`line vty .*`)
	if len(vtys) == 0 {
		return Warn, i18n.Tx("compliance.detail.no_vty"), nil
	}
	var bad []i18n.Text
	var ns []*iosconf.Node
	for _, v := range vtys {
		ti := v.Find(`transport input .*`)
		switch {
		case len(ti) == 0:
			bad = append(bad, i18n.Tx("compliance.detail.vty_no_transport", "line", v.Line))
			ns = append(ns, v)
		case ti[0].Line != "transport input ssh" && ti[0].Line != "transport input none":
			bad = append(bad, i18n.Tx("compliance.detail.vty_transport", "line", v.Line, "transport", ti[0].Line))
			ns = append(ns, ti[0])
		}
	}
	if len(bad) > 0 {
		return Fail, i18n.Join("; ", bad...), ns
	}
	return Pass, i18n.Text{}, nil
}

func httpServer(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	if ns := c.Find(`ip http server`); len(ns) > 0 {
		return Fail, i18n.Tx("compliance.detail.http_server"), ns
	}
	if ns := c.Find(`ip http secure-server`); len(ns) > 0 && !c.Has(`ip http authentication (local|aaa)( .*)?`) {
		return Fail, i18n.Tx("compliance.detail.http_secure"), ns
	}
	return Pass, i18n.Text{}, nil
}

func ntpAuth(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	servers := c.Find(`ntp server .*`)
	if len(servers) == 0 {
		return Fail, i18n.Tx("compliance.detail.no_ntp"), nil
	}
	var miss []i18n.Text
	for _, p := range []string{`ntp authenticate`, `ntp authentication-key \d+ .*`, `ntp trusted-key \d+.*`} {
		if !c.Has(p) {
			w := strings.Fields(p)[0] + " " + strings.Fields(p)[1]
			miss = append(miss, i18n.Lit(w, w))
		}
	}
	var nokey []*iosconf.Node
	for _, s := range servers {
		if !strings.Contains(" "+s.Line+" ", " key ") {
			nokey = append(nokey, s)
		}
	}
	if len(nokey) > 0 {
		miss = append(miss, i18n.Tx("compliance.detail.ntp_nokey").With("lines", lineListTx(nokey)))
	}
	if len(miss) > 0 {
		return Fail, i18n.Tx("compliance.detail.ntp_missing").With("items", i18n.Join(", ", miss...)), nokey
	}
	return Pass, i18n.Text{}, nil
}

var (
	reversible = regexp.MustCompile(`^(enable password .*|username \S+ .*\bpassword .*)$`)
	md5Secret  = regexp.MustCompile(`^(enable|username \S+ .*) secret [45] .*$`)
	linePass   = regexp.MustCompile(`^password( [07])? .*$`)
)

func secretTypes(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	var fails, warns []*iosconf.Node
	c.Walk(func(n *iosconf.Node) {
		switch {
		case n.Parent.Parent == nil && reversible.MatchString(n.Line):
			fails = append(fails, n)
		case n.Parent.Parent == nil && md5Secret.MatchString(n.Line):
			warns = append(warns, n)
		case n.Parent.Parent != nil && strings.HasPrefix(n.Parent.Line, "line ") && linePass.MatchString(n.Line):
			warns = append(warns, n)
		}
	})
	all := append(append([]*iosconf.Node{}, fails...), warns...)
	switch {
	case len(fails) > 0:
		d := i18n.Tx("compliance.detail.secret_reversible").With("lines", lineListTx(fails))
		if len(warns) > 0 {
			d = i18n.Join("; ", d, i18n.Tx("compliance.detail.secret_also").With("lines", lineListTx(warns)))
		}
		return Fail, d, all
	case len(warns) > 0:
		return Warn, i18n.Tx("compliance.detail.secret_weak").With("lines", lineListTx(warns)), all
	}
	return Pass, i18n.Text{}, nil
}

func execTimeout(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	var fails, warns []i18n.Text
	var ns []*iosconf.Node
	for _, l := range c.Find(`line (con 0|vty .*)`) {
		et := l.Find(`exec-timeout .*`)
		switch {
		case len(et) == 0:
			warns = append(warns, i18n.Tx("compliance.detail.exec_none", "line", l.Line))
		case et[0].Line == "exec-timeout 0" || et[0].Line == "exec-timeout 0 0":
			fails = append(fails, i18n.Tx("compliance.detail.exec_zero", "line", l.Line, "timeout", et[0].Line))
			ns = append(ns, et[0])
		}
	}
	switch {
	case len(fails) > 0:
		return Fail, i18n.Join("; ", append(fails, warns...)...), ns
	case len(warns) > 0:
		return Warn, i18n.Join("; ", warns...), nil
	}
	return Pass, i18n.Text{}, nil
}

func copp(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	for _, cp := range c.Find(`control-plane( host)?`) {
		if cp.Has(`service-policy input .*`) {
			return Pass, i18n.Text{}, nil
		}
	}
	return Fail, i18n.Tx("compliance.detail.no_copp"), nil
}

// snmpCommunity: snmp-server community NOMBRE [view V] [RO|RW] [ipv6 ACL6] [ACL].
func snmpCommunity(c *iosconf.Node) (Status, i18n.Text, []*iosconf.Node) {
	var fails, warns []i18n.Text
	var ns []*iosconf.Node
	for _, n := range c.Find(`snmp-server community .*`) {
		f := strings.Fields(n.Line)
		name, acl := f[2], ""
		for i := 3; i < len(f); i++ {
			switch strings.ToLower(f[i]) {
			case "view", "ipv6":
				i++
			case "ro", "rw":
			default:
				acl = f[i]
			}
		}
		switch {
		case strings.EqualFold(name, "public") || strings.EqualFold(name, "private"):
			fails = append(fails, i18n.Tx("compliance.detail.snmp_default", "n", n.Num, "name", name))
			ns = append(ns, n)
		case acl == "":
			fails = append(fails, i18n.Tx("compliance.detail.snmp_noacl", "n", n.Num))
			ns = append(ns, n)
		default:
			warns = append(warns, i18n.Tx("compliance.detail.snmp_acl", "n", n.Num, "acl", acl))
		}
	}
	switch {
	case len(fails) > 0:
		return Fail, i18n.Join("; ", append(fails, warns...)...), ns
	case len(warns) > 0:
		return Warn, i18n.Join("; ", warns...), nil
	}
	return Pass, i18n.Text{}, nil
}
