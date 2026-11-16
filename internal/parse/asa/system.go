package asa

import (
	"regexp"
	"strings"
)

// ParseChecksum lee `show checksum` y devuelve el Cryptochecksum en minúsculas y sin espacios.
func ParseChecksum(s string) (string, bool) {
	for _, l := range lines(s) {
		k, v, ok := kv(l)
		if ok && strings.HasPrefix(strings.ToLower(k), "cryptochecksum") {
			v = strings.ToLower(strings.Join(strings.Fields(v), ""))
			return v, v != "" && strings.Trim(v, "0123456789abcdef") == ""
		}
	}
	return "", false
}

// ParseMode lee `show mode` y devuelve "single" o "multiple".
func ParseMode(s string) (string, bool) {
	for _, l := range lines(s) {
		if k, v, ok := kv(l); ok && strings.EqualFold(k, "Security context mode") && (v == "single" || v == "multiple") {
			return v, true
		}
	}
	return "", false
}

// Context es una fila de `show context`.
type Context struct {
	Name       string
	Admin      bool
	Class      string
	Interfaces []string
	Mode       string // Routed o Transparent
	URL        string
}

var reCtxTotal = regexp.MustCompile(`^Total active Security Contexts:\s*(\d+)`)

// ParseContexts lee `show context` y el total declarado. ok=false sin el encabezado "Context Name".
func ParseContexts(s string) (list []Context, total int, ok bool) {
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		if strings.HasPrefix(l, "Context Name") {
			ok = true
			continue
		}
		if m := reCtxTotal.FindStringSubmatch(l); m != nil {
			total = int(atoi(m[1]))
			continue
		}
		if !ok || l == "" {
			continue
		}
		f := strings.Fields(l)
		if indent(raw) > 1 { // continuación de la lista de interfaces
			if n := len(list); n > 0 {
				list[n-1].Interfaces = append(list[n-1].Interfaces, splitIfaces(f)...)
			}
			continue
		}
		if len(f) < 3 {
			continue
		}
		c := Context{Name: strings.TrimPrefix(f[0], "*"), Admin: strings.HasPrefix(f[0], "*"), Class: f[1], URL: f[len(f)-1]}
		mid := f[2 : len(f)-1]
		if n := len(mid); n > 0 && (mid[n-1] == "Routed" || mid[n-1] == "Transparent") {
			c.Mode, mid = mid[n-1], mid[:n-1]
		}
		c.Interfaces = splitIfaces(mid)
		list = append(list, c)
	}
	return list, total, ok
}

func splitIfaces(f []string) (out []string) {
	for _, w := range f {
		if w = strings.Trim(w, ","); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// indent cuenta el sangrado de la línea original (la tabulación vale 8).
func indent(l string) int {
	n := 0
	for _, r := range l {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 8
		default:
			return n
		}
	}
	return n
}

// Resource es una fila de `show resource usage`.
type Resource struct {
	Name                  string // sin el " [rate]"
	Rate                  bool   // recurso de tasa (conns/s...)
	Current, Peak, Denied int64
	Limit                 int64 // -1 si N/A o unlimited
	Unlimited             bool
	Flag                  string // U o S de "12000(U)"
	Context               string // contexto, System o Summary
}

var reLimit = regexp.MustCompile(`^(\d+)(?:\((\w)\))?$`)

// ParseResourceUsage lee `show resource usage` (system, summary, un contexto o all). ok=false sin encabezado.
func ParseResourceUsage(s string) ([]Resource, bool) {
	var out []Resource
	ok := false
	for _, l := range lines(s) {
		f := strings.Fields(l)
		if len(f) >= 6 && f[0] == "Resource" && f[1] == "Current" {
			ok = true
			continue
		}
		if !ok || len(f) < 6 {
			continue
		}
		n := len(f)
		r := Resource{Context: f[n-1], Current: -1, Peak: -1, Denied: -1, Limit: -1}
		if !isNum(f[n-5]) || !isNum(f[n-4]) || !isNum(f[n-2]) {
			continue
		}
		r.Current, r.Peak, r.Denied = atoi(f[n-5]), atoi(f[n-4]), atoi(f[n-2])
		switch lim := f[n-3]; {
		case lim == "unlimited":
			r.Unlimited = true
		case lim == "N/A":
		default:
			m := reLimit.FindStringSubmatch(lim)
			if m == nil {
				continue
			}
			r.Limit, r.Flag = atoi(m[1]), m[2]
		}
		r.Name = strings.Join(f[:n-5], " ")
		if strings.HasSuffix(r.Name, " [rate]") {
			r.Name, r.Rate = strings.TrimSuffix(r.Name, " [rate]"), true
		}
		out = append(out, r)
	}
	return out, ok
}

func isNum(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

// AspRow es un motivo de `show asp drop`.
type AspRow struct {
	Section string // frame o flow
	Desc    string
	Keyword string // acl-drop, rpf-violated...
	Count   int64
}

// AspDrop es `show asp drop`; Cleared guarda la línea "Last clearing:" de cada sección.
type AspDrop struct {
	Rows    []AspRow
	Cleared map[string]string
}

var reAsp = regexp.MustCompile(`^(.+?)\s+\(([\w-]+)\)\s+(\d+)$`)

// ParseAspDrop lee `show asp drop`. Sin encabezado (`show asp drop frame|flow`) la sección queda "".
// ok=false sin encabezado, filas ni línea "Last clearing:".
func ParseAspDrop(s string) (AspDrop, bool) {
	d := AspDrop{Cleared: map[string]string{}}
	// `show asp drop frame|flow` no trae encabezado: la sección queda "" (quien llama sabe qué comando corrió)
	sec, ok := "", false
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		switch {
		case l == "Frame drop:":
			sec, ok = "frame", true
		case l == "Flow drop:":
			sec, ok = "flow", true
		case strings.HasPrefix(l, "Last clearing:"):
			d.Cleared[sec] = strings.TrimSpace(strings.TrimPrefix(l, "Last clearing:"))
			ok = true
		default:
			if m := reAsp.FindStringSubmatch(l); m != nil {
				d.Rows = append(d.Rows, AspRow{sec, m[1], m[2], atoi(m[3])})
				ok = true
			}
		}
	}
	return d, ok
}

// CountRow es una línea "N in use, M most used" con su etiqueta ("" para la general).
type CountRow struct {
	Name            string
	InUse, MostUsed int64
}

var reCount = regexp.MustCompile(`^(?:(.+?):\s*)?(\d+) in use, (\d+) most used`)

// ParseCount lee `show conn count` y `show xlate count`: la primera línea es el total; las demás
// (fwd/dir/centralized de cluster) quedan con su etiqueta. ok=false sin ninguna línea "N in use".
func ParseCount(s string) ([]CountRow, bool) {
	var out []CountRow
	for _, l := range lines(s) {
		if m := reCount.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			out = append(out, CountRow{m[1], atoi(m[2]), atoi(m[3])})
		}
	}
	return out, len(out) > 0
}

// ClusterMember es una unidad de `show cluster info`.
type ClusterMember struct {
	Name, State         string
	Local               bool
	ID                  int64
	Version, Serial     string
	CCLIP, CCLMAC       string
	LastJoin, LastLeave string
	Extra               map[string]string // campos de otras versiones (Site ID, Member Limit...)
}

// IsControl es true para el nodo de control (MASTER antes de 9.19(1), CONTROL_NODE después).
func (m ClusterMember) IsControl() bool { return m.State == "MASTER" || m.State == "CONTROL_NODE" }

// ClusterInfo es `show cluster info`.
type ClusterInfo struct {
	Name, Mode string
	On         bool
	Members    []ClusterMember
}

var (
	reClHead = regexp.MustCompile(`^Cluster (\S+): (On|Off)`)
	reClThis = regexp.MustCompile(`^This is "([^"]+)" in state (\S+)`)
	reClUnit = regexp.MustCompile(`^Unit "([^"]+)" in state (\S+)`)
)

// ParseClusterInfo lee `show cluster info`. ok=false sin la línea "Cluster <nombre>: On/Off".
func ParseClusterInfo(s string) (ClusterInfo, bool) {
	var c ClusterInfo
	ok := false
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		if m := reClHead.FindStringSubmatch(l); m != nil {
			c.Name, c.On, ok = m[1], m[2] == "On", true
			continue
		}
		if !ok {
			continue
		}
		if m := reClThis.FindStringSubmatch(l); m != nil {
			c.Members = append(c.Members, ClusterMember{Name: m[1], State: m[2], Local: true})
			continue
		}
		if m := reClUnit.FindStringSubmatch(l); m != nil {
			c.Members = append(c.Members, ClusterMember{Name: m[1], State: m[2]})
			continue
		}
		k, v, isKV := kv(l)
		if !isKV {
			continue
		}
		if len(c.Members) == 0 {
			if k == "Interface mode" {
				c.Mode = v
			}
			continue
		}
		m := &c.Members[len(c.Members)-1]
		switch k {
		case "ID":
			m.ID = atoi(v)
		case "Version":
			m.Version = v
		case "Serial No.":
			m.Serial = v
		case "CCL IP":
			m.CCLIP = v
		case "CCL MAC":
			m.CCLMAC = v
		case "Last join":
			m.LastJoin = v
		case "Last leave":
			m.LastLeave = v
		default:
			if m.Extra == nil {
				m.Extra = map[string]string{}
			}
			m.Extra[k] = v
		}
	}
	return c, ok
}

// HealthMember es una columna de `show cluster info health`.
type HealthMember struct {
	ID    int64
	Name  string
	Local bool
}

// HealthRow es una fila de la tabla: etiqueta y un valor por miembro, en el orden de Members.
type HealthRow struct {
	Label  string
	Values []string
}

// ClusterHealth es `show cluster info health` (formato reconstruido; no hay salida publicada).
type ClusterHealth struct {
	Members []HealthMember
	Rows    []HealthRow
}

var (
	reHlMap = regexp.MustCompile(`(\d+) - ([^\s(]+)(\(LOCAL\))?`)
	reHlCol = regexp.MustCompile(`^(\d+)(\(LOCAL\))?$`)
)

// ParseClusterHealth lee la tabla de salud: primero el mapeo "ID - nombre", luego el encabezado de
// IDs y las filas (los últimos N campos son los valores, el resto la etiqueta). ok=false sin mapeo.
func ParseClusterHealth(s string) (ClusterHealth, bool) {
	var h ClusterHealth
	phase := 0 // 1 mapeo, 2 encabezado visto
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "Member ID to name mapping") {
			phase = 1
			continue
		}
		f := strings.Fields(l)
		switch {
		case phase == 1 && reHlMap.MatchString(l):
			for _, m := range reHlMap.FindAllStringSubmatch(l, -1) {
				h.Members = append(h.Members, HealthMember{atoi(m[1]), m[2], m[3] != ""})
			}
		case phase >= 1 && allCols(f):
			phase = 2
		case phase == 2 && len(f) > len(h.Members) && len(h.Members) > 0:
			n := len(h.Members)
			// la fila no repite columnas: los valores con espacios no se admiten (shortcut: un valor = una palabra)
			h.Rows = append(h.Rows, HealthRow{strings.Join(f[:len(f)-n], " "), f[len(f)-n:]})
		}
	}
	return h, len(h.Members) > 0
}

func allCols(f []string) bool {
	for _, w := range f {
		if !reHlCol.MatchString(w) {
			return false
		}
	}
	return len(f) > 0
}

// Version es `show version`: lo que sirve para comparar un par.
type Version struct {
	Software, SSP, DeviceManager string
	Hostname, Uptime             string
	Model                        string
	RAMMB                        int64
	Serial                       string
	LicenseMode                  string            // Smart Licensing u otro; "" si no aparece
	Features                     map[string]string // "Licensed features for this platform"
	Contexts                     int64             // Security Contexts del feature
	FailoverFeature              string            // Active/Active, Active/Standby, Disabled
	ConfigRegister               string
}

var (
	reVerSW = regexp.MustCompile(`^Cisco Adaptive Security Appliance Software Version (\S+)`)
	reVerHW = regexp.MustCompile(`^Hardware:\s+([^,]+),\s*(\d+) MB RAM`)
	reVerUp = regexp.MustCompile(`^(\S+) up (.+)$`)
)

// ParseVersion lee `show version`. ok=false sin la línea "Software Version".
func ParseVersion(s string) (Version, bool) {
	v := Version{Features: map[string]string{}}
	ok, inFeat := false, false
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		if m := reVerSW.FindStringSubmatch(l); m != nil {
			v.Software, ok = m[1], true
			continue
		}
		if l == "" {
			inFeat = false
			continue
		}
		switch {
		case inFeat:
			if k, val, isKV := kv(l); isKV && !strings.HasPrefix(k, "Serial Number") {
				v.Features[k] = val
				continue
			}
			inFeat = false
		case strings.HasPrefix(l, "Licensed features"):
			inFeat = true
			continue
		}
		switch {
		case strings.HasPrefix(l, "SSP Operating System Version"):
			v.SSP = strings.TrimSpace(strings.TrimPrefix(l, "SSP Operating System Version"))
		case strings.HasPrefix(l, "Device Manager Version"):
			v.DeviceManager = strings.TrimSpace(strings.TrimPrefix(l, "Device Manager Version"))
		case reVerHW.MatchString(l):
			m := reVerHW.FindStringSubmatch(l)
			v.Model, v.RAMMB = strings.TrimSpace(m[1]), atoi(m[2])
		case strings.HasPrefix(l, "License mode:"):
			v.LicenseMode = strings.TrimSpace(strings.TrimPrefix(l, "License mode:"))
		case strings.HasPrefix(l, "Serial Number:"):
			v.Serial = strings.TrimSpace(strings.TrimPrefix(l, "Serial Number:"))
		case strings.HasPrefix(l, "Configuration register is "):
			v.ConfigRegister = strings.TrimPrefix(l, "Configuration register is ")
		default:
			if m := reVerUp.FindStringSubmatch(l); m != nil && v.Hostname == "" && !strings.HasPrefix(l, "failover") && !strings.HasPrefix(l, "Start-up") {
				v.Hostname, v.Uptime = m[1], m[2]
			}
		}
	}
	// con licencias PAK el valor lleva una columna de duración ("5 perpetual")
	v.FailoverFeature = firstWord(v.Features["Failover"])
	v.Contexts = atoi(firstWord(v.Features["Security Contexts"]))
	return v, ok
}

var reVolatile = regexp.MustCompile(`(?i)^(?:Cryptochecksum:.*|ntp clock-period .*|Building configuration.*|\S+# (?:show|more) .*)$`)

// NormalizeRunningConfig quita lo que cambia sin que cambie la configuración: ": Saved", ": Written by",
// fechas de último cambio, Cryptochecksum, ntp clock-period, el eco del comando y el prompt. Conserva
// el resto tal cual; dos configuraciones iguales dan la misma cadena. ok=false si no queda "ASA Version".
func NormalizeRunningConfig(s string) (string, bool) {
	var out []string
	ok := false
	for _, l := range lines(s) {
		// la cabecera de comentarios (": Saved", ": Serial Number", ": Hardware"...) cambia de una unidad a otra
		if !ok && strings.HasPrefix(l, ":") {
			continue
		}
		if reVolatile.MatchString(strings.TrimSpace(l)) {
			continue
		}
		if strings.HasPrefix(l, "ASA Version ") {
			ok = true
		}
		out = append(out, l)
	}
	if n := len(out); n > 0 && regexp.MustCompile(`^\S+#$`).MatchString(out[n-1]) { // prompt final
		out = out[:n-1]
	}
	return strings.Join(out, "\n") + "\n", ok
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}
