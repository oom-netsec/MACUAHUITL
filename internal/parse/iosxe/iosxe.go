// Package iosxe convierte salidas `show` de IOS-XE (17.x, formato de la
// documentación pública de Cisco; sin validar en laboratorio) en tipos de Go.
// No depende de otros paquetes internos ni toca la red.
//
// Convención: cada parser devuelve (filas, ok). ok=false significa "no reconozco
// este formato": quien llama debe avisar, nunca tomarlo como "sin filas".
package iosxe

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func lines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

func atoi(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

// NormMAC acepta cualquier notación (aabb.cc00.0a01, aa:bb:..., aa-bb-..., aabbcc000a01)
// y devuelve la forma de Cisco en minúsculas.
func NormMAC(s string) (string, bool) {
	var sb strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			sb.WriteRune(r)
		case r == '.' || r == ':' || r == '-':
		default:
			return "", false
		}
	}
	h := sb.String()
	if len(h) != 12 {
		return "", false
	}
	return h[0:4] + "." + h[4:8] + "." + h[8:12], true
}

var ifPrefixes = []struct{ long, short string }{
	{"twentyfivegige", "Twe"}, {"hundredgige", "Hu"}, {"fortygigabitethernet", "Fo"}, {"tengigabitethernet", "Te"},
	{"gigabitethernet", "Gi"}, {"fastethernet", "Fa"}, {"ethernet", "Eth"}, {"port-channel", "Po"},
	{"twe", "Twe"}, {"hu", "Hu"}, {"fo", "Fo"}, {"te", "Te"}, {"gi", "Gi"}, {"fa", "Fa"}, {"eth", "Eth"}, {"po", "Po"},
}

// ShortIf lleva el nombre de interfaz a la abreviatura de IOS (GigabitEthernet1/0/1 → Gi1/0/1).
func ShortIf(s string) string {
	l := strings.ToLower(s)
	for _, p := range ifPrefixes {
		if strings.HasPrefix(l, p.long) && len(l) > len(p.long) && l[len(p.long)] >= '0' && l[len(p.long)] <= '9' {
			return p.short + s[len(p.long):]
		}
	}
	return s
}

// ---- show ip arp ----

type ARP struct{ IP, MAC, Iface string }

var arpRe = regexp.MustCompile(`^Internet\s+(\S+)\s+\S+\s+([0-9a-fA-F.]{14})\s+ARPA\s+(\S+)`)

func ParseARP(text string) ([]ARP, bool) {
	var out []ARP
	head := false
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "Protocol") && strings.Contains(ln, "Hardware Addr") {
			head = true
		}
		if m := arpRe.FindStringSubmatch(ln); m != nil {
			if mac, ok := NormMAC(m[2]); ok {
				out = append(out, ARP{IP: m[1], MAC: mac, Iface: ShortIf(m[3])})
			}
		}
	}
	return out, head || len(out) > 0
}

// ---- show mac address-table ----

type MACEntry struct{ VLAN, MAC, Type, Port string }

var macRe = regexp.MustCompile(`^\s*(\d+|All)\s+([0-9a-fA-F.]{14})\s+(\S+)\s+(\S+)`)

func ParseMACTable(text string) ([]MACEntry, bool) {
	var out []MACEntry
	head := false
	for _, ln := range lines(text) {
		if strings.Contains(ln, "Mac Address") && strings.Contains(ln, "Ports") {
			head = true
		}
		if m := macRe.FindStringSubmatch(ln); m != nil {
			if mac, ok := NormMAC(m[2]); ok {
				out = append(out, MACEntry{VLAN: m[1], MAC: mac, Type: strings.ToUpper(m[3]), Port: ShortIf(m[4])})
			}
		}
	}
	return out, head || len(out) > 0
}

// ---- show ip dhcp snooping binding ----

type DHCPBinding struct{ MAC, IP, VLAN, Iface string }

var dhcpRe = regexp.MustCompile(`^\s*([0-9a-fA-F:.-]{12,17})\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\d+)\s+(\S+)`)

func ParseDHCPSnooping(text string) ([]DHCPBinding, bool) {
	var out []DHCPBinding
	head := false
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "MacAddress") {
			head = true
		}
		if m := dhcpRe.FindStringSubmatch(ln); m != nil {
			if mac, ok := NormMAC(m[1]); ok {
				out = append(out, DHCPBinding{MAC: mac, IP: m[2], VLAN: m[3], Iface: ShortIf(m[4])})
			}
		}
	}
	return out, head || len(out) > 0
}

// ---- show interfaces status ----

type IfStatus struct{ Port, Name, Status, VLAN, Duplex, Speed, Type string }

// ifStatusRe ancla en lo que sí es de vocabulario cerrado (duplex y velocidad) y toma el resto por
// posición: así un Name con espacios, o columnas de datos desplazadas respecto a la cabecera, no
// corren los campos. Type va al final y puede traer espacios («Not Present», «1000BaseSX SFP»).
// Name es codicioso: el par dúplex/velocidad real es el último antes de Type, así una descripción
// como «PC sala 3 half 10» no se lleva el Status (err-disabled) que revisa el modo asistido.
var ifStatusRe = regexp.MustCompile(`^(\S+)\s+(?:(.*\S)\s+)?(\S+)\s+(\S+)\s+(a-full|a-half|full|half|auto)\s+(a-[\d.]+[GM]?|[\d.]+[GM]?|auto)(?:\s+(.*?))?\s*$`)

// ParseIfStatus lee cada fila por ifStatusRe; si una fila no encaja (duplex o velocidad fuera del
// vocabulario), corta esa fila por las columnas de la cabecera.
func ParseIfStatus(text string) ([]IfStatus, bool) {
	var out []IfStatus
	var cols []int
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "Port") && strings.Contains(ln, "Status") && strings.Contains(ln, "Vlan") {
			cols = nil
			for _, h := range []string{"Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"} {
				cols = append(cols, strings.Index(ln, h))
			}
			continue
		}
		if cols == nil || strings.TrimSpace(ln) == "" || len(ln) <= cols[2] {
			continue
		}
		if m := ifStatusRe.FindStringSubmatch(ln); m != nil {
			out = append(out, IfStatus{Port: ShortIf(m[1]), Name: m[2], Status: m[3], VLAN: m[4], Duplex: m[5], Speed: m[6], Type: m[7]})
			continue
		}
		cut := func(i int) string {
			if cols[i] < 0 || cols[i] >= len(ln) {
				return ""
			}
			end := len(ln)
			if i+1 < len(cols) && cols[i+1] >= 0 && cols[i+1] < end {
				end = cols[i+1]
			}
			return strings.TrimSpace(ln[cols[i]:end])
		}
		if p := cut(0); p != "" {
			out = append(out, IfStatus{Port: ShortIf(p), Name: cut(1), Status: cut(2), VLAN: cut(3), Duplex: cut(4), Speed: cut(5), Type: cut(6)})
		}
	}
	return out, cols != nil
}

// ---- show ip route / show ip cef ----

type NextHop struct{ IP, Iface string }

type Route struct {
	Code      string
	Prefix    netip.Prefix
	Connected bool // C o L: sale por Hops[0].Iface sin siguiente salto
	Metric    string
	Hops      []NextHop
}

var (
	// El código puede ir en minúscula (i L1, i ia, o, l); la máscara es opcional
	// porque bajo "is subnetted" las hijas no la traen.
	routeRe = regexp.MustCompile(`^([A-Za-z*+%][A-Za-z0-9*+% ]{0,5}?)\s+(\d+\.\d+\.\d+\.\d+)(/\d+)?(.*)$`)
	// "172.16.0.0/24 is subnetted" (hijas sin máscara) o "10.0.0.0/8 is variably subnetted" (cada hija trae la suya).
	subnRe = regexp.MustCompile(`^\s+\d+\.\d+\.\d+\.\d+/(\d+) is (variably )?subnetted`)
	viaRe  = regexp.MustCompile(`(?:\[(\d+/\d+)\] )?via (\d+\.\d+\.\d+\.\d+)(.*)$`)
	connRe = regexp.MustCompile(`is directly connected, (\S+)`)
	sumRe  = regexp.MustCompile(`is a summary, \S+, (\S+)`)
)

func hopFrom(tail string) NextHop {
	var h NextHop
	for _, p := range strings.Split(tail, ",") {
		if p = strings.TrimSpace(p); p != "" && p[0] >= 'A' && p[0] <= 'z' {
			h.Iface = ShortIf(p)
		}
	}
	return h
}

func ParseRoute(text string) ([]Route, bool) {
	out, _, ok := parseRoute(text)
	return out, ok
}

// RouteUnread devuelve las líneas con forma de ruta que ParseRoute no pudo leer
// (p. ej. una hija sin máscara y sin encabezado "is subnetted"): quien las usa
// debe avisar que la tabla puede estar incompleta.
func RouteUnread(text string) []string {
	_, un, _ := parseRoute(text)
	return un
}

func parseRoute(text string) (out []Route, unread []string, ok bool) {
	codes := false
	maskless := -1 // bits de las hijas sin máscara; -1 si no hay encabezado "is subnetted"
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "Codes:") || strings.HasPrefix(ln, "Gateway of last resort") {
			codes = true
		}
		if m := subnRe.FindStringSubmatch(ln); m != nil {
			maskless = -1
			if m[2] == "" {
				maskless = int(atoi(m[1]))
			}
			continue
		}
		if m := routeRe.FindStringSubmatch(ln); m != nil {
			addr := m[2] + m[3]
			if m[3] == "" {
				if maskless < 0 {
					unread = append(unread, ln)
					continue
				}
				addr += "/" + strconv.Itoa(maskless)
			}
			p, err := netip.ParsePrefix(addr)
			if err != nil {
				unread = append(unread, ln)
				continue
			}
			r := Route{Code: strings.TrimSpace(m[1]), Prefix: p.Masked()}
			if c := connRe.FindStringSubmatch(m[4]); c != nil {
				r.Connected, r.Hops = true, []NextHop{{Iface: ShortIf(c[1])}}
			} else if c := sumRe.FindStringSubmatch(m[4]); c != nil { // resumen hacia Null0
				r.Hops = []NextHop{{Iface: ShortIf(c[1])}}
			} else if v := viaRe.FindStringSubmatch(m[4]); v != nil {
				r.Metric = v[1]
				h := hopFrom(v[3])
				h.IP = v[2]
				r.Hops = []NextHop{h}
			}
			out = append(out, r)
			continue
		}
		if v := viaRe.FindStringSubmatch(ln); v != nil && len(out) > 0 && strings.HasPrefix(ln, " ") && !out[len(out)-1].Connected {
			h := hopFrom(v[3])
			h.IP = v[2]
			last := &out[len(out)-1]
			last.Hops = append(last.Hops, h)
			if last.Metric == "" {
				last.Metric = v[1]
			}
		}
	}
	return out, unread, codes || len(out) > 0
}

// LongestMatch devuelve la ruta más específica que contiene a ip.
func LongestMatch(routes []Route, ip netip.Addr) (Route, bool) {
	best, found := Route{}, false
	for _, r := range routes {
		if r.Prefix.Contains(ip) && (!found || r.Prefix.Bits() > best.Prefix.Bits()) {
			best, found = r, true
		}
	}
	return best, found
}

var cefRe = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+(\S+)\s+(\S+)\s*$`)
var cefContRe = regexp.MustCompile(`^\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s*$`)

// ParseCEF lee show ip cef y lo entrega con la forma de una tabla de rutas.
func ParseCEF(text string) ([]Route, bool) {
	var out []Route
	head := false
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "Prefix") && strings.Contains(ln, "Next Hop") {
			head = true
			continue
		}
		if m := cefRe.FindStringSubmatch(ln); m != nil {
			s := m[1]
			if !strings.Contains(s, "/") {
				s += "/32"
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				continue
			}
			r := Route{Code: "CEF", Prefix: p.Masked()}
			switch m[2] {
			case "attached":
				r.Connected, r.Hops = true, []NextHop{{Iface: ShortIf(m[3])}}
			case "drop": // descarte explícito: si se omite, el LPM cae a una ruta menos específica
				r.Hops = []NextHop{{Iface: "Null0"}}
			case "receive", "no", "punt":
				continue
			default:
				if _, err := netip.ParseAddr(m[2]); err != nil {
					continue
				}
				r.Hops = []NextHop{{IP: m[2], Iface: ShortIf(m[3])}}
			}
			out = append(out, r)
		} else if m := cefContRe.FindStringSubmatch(ln); m != nil && len(out) > 0 && !out[len(out)-1].Connected {
			out[len(out)-1].Hops = append(out[len(out)-1].Hops, NextHop{IP: m[1], Iface: ShortIf(m[2])})
		}
	}
	return out, head || len(out) > 0
}

// ---- show ntp status ----

type NTP struct {
	Synced  bool
	Stratum int
	Line    string
}

func ParseNTP(text string) (NTP, bool) {
	for _, ln := range lines(text) {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "Clock is synchronized"):
			return NTP{Synced: true, Stratum: stratum(t), Line: t}, true
		case strings.HasPrefix(t, "Clock is unsynchronized"):
			return NTP{Stratum: stratum(t), Line: t}, true
		}
	}
	return NTP{}, false
}

var stratumRe = regexp.MustCompile(`stratum (\d+)`)

func stratum(s string) int {
	if m := stratumRe.FindStringSubmatch(s); m != nil {
		return int(atoi(m[1]))
	}
	return 0
}

// ---- show inventory ----

type InvItem struct{ Name, Descr, PID, VID, SN string }

var (
	invNameRe = regexp.MustCompile(`^NAME: "([^"]*)",\s*DESCR: "([^"]*)"`)
	invPIDRe  = regexp.MustCompile(`^PID:\s*([^,]*?)\s*,\s*VID:\s*([^,]*?)\s*,\s*SN:\s*(\S*)`)
)

func ParseInventory(text string) ([]InvItem, bool) {
	var out []InvItem
	var cur *InvItem
	for _, ln := range lines(text) {
		if m := invNameRe.FindStringSubmatch(ln); m != nil {
			out = append(out, InvItem{Name: m[1], Descr: m[2]})
			cur = &out[len(out)-1]
		} else if m := invPIDRe.FindStringSubmatch(ln); m != nil && cur != nil {
			cur.PID, cur.VID, cur.SN = m[1], m[2], m[3]
			cur = nil
		}
	}
	return out, len(out) > 0
}

// ---- show version ----

// Version reúne lo que dicen show version de IOS-XE y de NX-OS; ok solo si hay nombre de equipo.
type Version struct {
	Host, Model, Version, Serial string
	Uptime                       time.Duration
	UptimeLine                   string   // línea "<host> uptime is ..." tal cual
	UptimeKnown                  bool     // la línea traía al menos una unidad de tiempo
	Reasons                      []string // "Last reload reason" / "System returned to ROM by"
	DRAMKB                       int64
	Image                        string // "System image file is" (flash:packages.conf)
	Register                     string // "Configuration register is" (0x2102)
	InstallMode                  string // install o bundle si show version lo dice ("Installation mode is" o la tabla de módulos); si no, vacío
}

var (
	verXERe    = regexp.MustCompile(`(?m)Cisco IOS XE Software, Version (\S+)`)
	verNXRe    = regexp.MustCompile(`(?m)NXOS: version (\S+)`)
	verRe      = regexp.MustCompile(`Version ([^\s,]+)`)
	hostRe     = regexp.MustCompile(`(?m)^(\S+) uptime is (.+)$`)
	hostNXRe   = regexp.MustCompile(`(?m)^\s*Device name:\s*(\S+)`)
	modelRe    = regexp.MustCompile(`(?m)^cisco (\S+) .*processor with (\d+)K/(\d+)K bytes of memory`)
	modelNXRe  = regexp.MustCompile(`(?m)^\s*cisco Nexus\S* (\S+) [Cc]hassis`)
	modelLoose = regexp.MustCompile(`(?m)^cisco (\S+) .*processor`)
	serialRe   = regexp.MustCompile(`(?m)^Processor board ID (\S+)`)
	imageRe    = regexp.MustCompile(`System image file is "([^"]+)"`)
	registerRe = regexp.MustCompile(`(?m)^Configuration register is (0x[0-9A-Fa-f]+)`)
	instModeRe = regexp.MustCompile(`(?mi)^Installation mode is (\w+)`)
	tableMode  = regexp.MustCompile(`(?m)^\*?\s*\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(INSTALL|BUNDLE)\s*$`)
	unitRe     = regexp.MustCompile(`(\d+) (year|week|day|hour|minute|second)s?`)
	units      = map[string]time.Duration{"year": 365 * 24 * time.Hour, "week": 7 * 24 * time.Hour, "day": 24 * time.Hour, "hour": time.Hour, "minute": time.Minute, "second": time.Second}
)

func ParseVersion(text string) (Version, bool) {
	var v Version
	if m := hostNXRe.FindStringSubmatch(text); m != nil {
		v.Host = m[1]
	}
	if m := hostRe.FindStringSubmatch(text); m != nil {
		if v.Host == "" {
			v.Host = m[1]
		}
		v.UptimeLine = m[0]
		for _, p := range unitRe.FindAllStringSubmatch(m[2], -1) {
			v.Uptime += time.Duration(atoi(p[1])) * units[p[2]]
			v.UptimeKnown = true
		}
	}
	for _, re := range []*regexp.Regexp{verXERe, verNXRe, verRe} {
		if x := re.FindStringSubmatch(text); x != nil {
			v.Version = x[1]
			break
		}
	}
	if x := modelRe.FindStringSubmatch(text); x != nil {
		v.Model, v.DRAMKB = x[1], atoi(x[2])+atoi(x[3])
	}
	if x := modelNXRe.FindStringSubmatch(text); x != nil {
		v.Model = x[1]
	} else if x := modelLoose.FindStringSubmatch(text); x != nil && v.Model == "" {
		v.Model = x[1]
	}
	if x := serialRe.FindStringSubmatch(text); x != nil {
		v.Serial = x[1]
	}
	if x := imageRe.FindStringSubmatch(text); x != nil {
		v.Image = x[1]
	}
	if x := registerRe.FindStringSubmatch(text); x != nil {
		v.Register = x[1]
	}
	if x := instModeRe.FindStringSubmatch(text); x != nil {
		v.InstallMode = strings.ToLower(x[1])
	} else if x := tableMode.FindStringSubmatch(text); x != nil {
		v.InstallMode = strings.ToLower(x[1])
	}
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "Last reload reason") || strings.HasPrefix(ln, "System returned to ROM by") {
			v.Reasons = append(v.Reasons, ln)
		}
	}
	return v, v.Host != ""
}

// ---- dir flash: / dir bootflash: ----

type Dir struct {
	FS          string
	Total, Free int64 // 0 y 0 si la salida no trae la línea "bytes total"
	Files       []DirFile
}

type DirFile struct {
	Name string
	Size int64
}

var (
	dirOfRe    = regexp.MustCompile(`^Directory of (\S+?)(?:/.*)?$`)
	dirTotalRe = regexp.MustCompile(`(\d+) bytes total \((\d+) bytes free\)`)
	dirFileRe  = regexp.MustCompile(`^\s*\d+\s+[-d][-rwx]+\s+(\d+)\s+.*\s(\S+)\s*$`)
)

func ParseDir(text string) (Dir, bool) {
	var d Dir
	for _, ln := range lines(text) {
		if m := dirOfRe.FindStringSubmatch(ln); m != nil && d.FS == "" {
			d.FS = m[1]
		}
		if m := dirFileRe.FindStringSubmatch(ln); m != nil {
			d.Files = append(d.Files, DirFile{Name: m[2], Size: atoi(m[1])})
		}
		if m := dirTotalRe.FindStringSubmatch(ln); m != nil {
			d.Total, d.Free = atoi(m[1]), atoi(m[2])
			return d, d.Total > 0 && d.Free <= d.Total
		}
	}
	return d, false
}

// ---- show processes cpu / memory ----

type CPU struct {
	FiveSec, OneMin, FiveMin float64
	Line                     string
}

var cpuRe = regexp.MustCompile(`CPU utilization for five seconds: (\d+)%(?:/\d+%)?; one minute: (\d+)%; five minutes: (\d+)%`)

func ParseCPU(text string) (CPU, bool) {
	for _, ln := range lines(text) {
		if m := cpuRe.FindStringSubmatch(ln); m != nil {
			return CPU{float64(atoi(m[1])), float64(atoi(m[2])), float64(atoi(m[3])), ln}, true
		}
	}
	return CPU{}, false
}

type Mem struct {
	Total, Free int64
	Line        string
}

var (
	memPoolRe  = regexp.MustCompile(`^\s*Processor Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)`)
	memStatsRe = regexp.MustCompile(`^\s*Processor\s+[0-9A-Fa-f]+\s+(\d+)\s+(\d+)\s+(\d+)`)
)

// ParseMem lee show processes memory ("Processor Pool Total") o show memory statistics (fila "Processor").
func ParseMem(text string) (Mem, bool) {
	for _, ln := range lines(text) {
		m := memPoolRe.FindStringSubmatch(ln)
		if m == nil {
			m = memStatsRe.FindStringSubmatch(ln)
		}
		if m != nil {
			if t, f := atoi(m[1]), atoi(m[3]); t > 0 && f <= t {
				return Mem{t, f, ln}, true
			}
		}
	}
	return Mem{}, false
}

// ProcMem es una fila de show processes memory [sorted]: lo que cada proceso tiene reservado.
type ProcMem struct {
	PID, TTY                  int
	Allocated, Freed, Holding int64
	Getbufs, Retbufs          int64
	Name                      string
}

var (
	procMemHeadRe = regexp.MustCompile(`^\s*PID\s+TTY\s+Allocated\s+Freed\s+Holding\s+Getbufs\s+Retbufs\s+Process`)
	procMemRowRe  = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)\s+(\d+)\s+(\d+)\s+(\S.*?)\s*$`)
)

// ParseProcessMemory lee show processes memory [sorted]. ok=false si no está la cabecera de columnas
// (p. ej. show processes memory platform, que tiene otras).
func ParseProcessMemory(text string) ([]ProcMem, bool) {
	var out []ProcMem
	head := false
	for _, ln := range lines(text) {
		if procMemHeadRe.MatchString(ln) {
			head = true
			continue
		}
		if !head {
			continue
		}
		if m := procMemRowRe.FindStringSubmatch(ln); m != nil {
			out = append(out, ProcMem{PID: int(atoi(m[1])), TTY: int(atoi(m[2])), Allocated: atoi(m[3]), Freed: atoi(m[4]), Holding: atoi(m[5]), Getbufs: atoi(m[6]), Retbufs: atoi(m[7]), Name: m[8]})
		}
	}
	return out, len(out) > 0 // las filas solo cuentan tras la cabecera
}

// ---- show interfaces ----

type Iface struct {
	Name               string // abreviado (Gi1/0/1)
	Raw                string // tal como lo imprime el equipo (GigabitEthernet1/0/1)
	AdminDown          bool
	MAC                string
	IPs                []string // con máscara
	Duplex             string   // Full, Half, Auto
	Runts, Giants      int64
	CRC, InErrors      int64
	OutErrors          int64
	OutDrops, Resets   int64
	InDrops            int64 // tercer campo de "Input queue: tam/máx/drops/flushes"
	LostCarrier        int64 // "N lost carrier, M no carrier"
	NoCarrier          int64
	CarrierTransitions int64             // "N carrier transitions" (routers); Evidence["carrier_transitions"] existe solo si el equipo lo imprime
	Evidence           map[string]string // contador → línea original, sin recortar
	// Series de métricas (fase 19). HasBytes: el equipo imprimió los contadores de octetos; sin ellos
	// los campos en bytes y las tasas valen 0 y no deben graficarse.
	Description       string
	BWKbit            int64 // "BW 1000000 Kbit/sec"; 0 si no lo imprime
	InBytes, OutBytes int64
	InPkts, OutPkts   int64
	InRateBps         int64 // "5 minute input rate N bits/sec" (promedio de 5 min del equipo)
	OutRateBps        int64
	HasBytes, HasRate bool
	// «Last clearing of "show interface" counters hh:mm:ss»: hace cuánto se limpiaron los contadores
	// (clear counters). HasClear es false con «never», con una forma más larga (2d03h) o sin la línea.
	ClearAgo time.Duration
	HasClear bool
}

var (
	ifHeadRe   = regexp.MustCompile(`^(\S+) is (administratively )?(?:up|down|deleted)\b.*, line protocol is `)
	ifMACRe    = regexp.MustCompile(`address is ([0-9a-fA-F.]{14})`)
	ifIPRe     = regexp.MustCompile(`^\s*Internet address is (\S+)`)
	ifDuplexRe = regexp.MustCompile(`^\s*(Full|Half|Auto)-duplex`)
	ifRuntRe   = regexp.MustCompile(`(\d+) runts, (\d+) giants`)
	ifErrRe    = regexp.MustCompile(`^\s*(\d+) input errors, (\d+) CRC`)
	ifOutRe    = regexp.MustCompile(`^\s*(\d+) output errors`)
	ifDropRe   = regexp.MustCompile(`Total output drops: (\d+)`)
	ifInDropRe = regexp.MustCompile(`^\s*Input queue: \d+/\d+/(\d+)/\d+`)
	ifResetRe  = regexp.MustCompile(`(\d+) interface resets`)
	ifLostRe   = regexp.MustCompile(`(\d+) lost carrier, (\d+) no carrier`)
	ifCarrRe   = regexp.MustCompile(`(\d+) carrier transitions`)
	ifDescRe   = regexp.MustCompile(`^\s*Description: (.*?)\s*$`)
	ifBWRe     = regexp.MustCompile(`\bBW (\d+) Kbit`)
	ifInBytes  = regexp.MustCompile(`^\s*(\d+) packets input, (\d+) bytes`)
	ifOutBytes = regexp.MustCompile(`^\s*(\d+) packets output, (\d+) bytes`)
	ifClearRe  = regexp.MustCompile(`Last clearing of "show interface" counters (\d+):(\d\d):(\d\d)\s*$`)
	ifRateRe   = regexp.MustCompile(`^\s*5 minute (input|output) rate (\d+) bits/sec`)
)

func ParseInterfaces(text string) ([]Iface, bool) {
	var out []Iface
	var c *Iface
	for _, ln := range lines(text) {
		if m := ifHeadRe.FindStringSubmatch(ln); m != nil {
			out = append(out, Iface{Name: ShortIf(m[1]), Raw: m[1], AdminDown: m[2] != "", Evidence: map[string]string{}})
			c = &out[len(out)-1]
			continue
		}
		if c == nil {
			continue
		}
		if m := ifDescRe.FindStringSubmatch(ln); m != nil && c.Description == "" {
			c.Description = m[1]
		}
		if m := ifBWRe.FindStringSubmatch(ln); m != nil && c.BWKbit == 0 {
			c.BWKbit = atoi(m[1])
		}
		if m := ifClearRe.FindStringSubmatch(ln); m != nil {
			c.ClearAgo = time.Duration(atoi(m[1]))*time.Hour + time.Duration(atoi(m[2]))*time.Minute + time.Duration(atoi(m[3]))*time.Second
			c.HasClear = true
		}
		if m := ifInBytes.FindStringSubmatch(ln); m != nil {
			c.InPkts, c.InBytes, c.HasBytes = atoi(m[1]), atoi(m[2]), true
		}
		if m := ifOutBytes.FindStringSubmatch(ln); m != nil {
			c.OutPkts, c.OutBytes = atoi(m[1]), atoi(m[2])
		}
		if m := ifRateRe.FindStringSubmatch(ln); m != nil {
			if m[1] == "input" {
				c.InRateBps = atoi(m[2])
			} else {
				c.OutRateBps = atoi(m[2])
			}
			c.HasRate = true
		}
		if m := ifMACRe.FindStringSubmatch(ln); m != nil && c.MAC == "" {
			c.MAC, _ = NormMAC(m[1])
		}
		if m := ifIPRe.FindStringSubmatch(ln); m != nil {
			c.IPs = append(c.IPs, m[1])
		}
		if m := ifDuplexRe.FindStringSubmatch(ln); m != nil {
			c.Duplex = m[1]
			c.Evidence["duplex"] = ln
		}
		if m := ifRuntRe.FindStringSubmatch(ln); m != nil {
			c.Runts, c.Giants = atoi(m[1]), atoi(m[2])
			c.Evidence["runts"], c.Evidence["giants"] = ln, ln
		}
		if m := ifErrRe.FindStringSubmatch(ln); m != nil {
			c.InErrors, c.CRC = atoi(m[1]), atoi(m[2])
			c.Evidence["input_errors"], c.Evidence["crc"] = ln, ln
		}
		if m := ifOutRe.FindStringSubmatch(ln); m != nil {
			c.OutErrors = atoi(m[1])
			c.Evidence["output_errors"] = ln
		}
		if m := ifDropRe.FindStringSubmatch(ln); m != nil {
			c.OutDrops = atoi(m[1])
			c.Evidence["drops"] = ln
		}
		if m := ifInDropRe.FindStringSubmatch(ln); m != nil {
			c.InDrops = atoi(m[1])
			c.Evidence["input_drops"] = ln
		}
		if m := ifResetRe.FindStringSubmatch(ln); m != nil {
			c.Resets = atoi(m[1])
			c.Evidence["resets"] = ln
		}
		if m := ifLostRe.FindStringSubmatch(ln); m != nil {
			c.LostCarrier, c.NoCarrier = atoi(m[1]), atoi(m[2])
			c.Evidence["lost_carrier"] = ln
		}
		if m := ifCarrRe.FindStringSubmatch(ln); m != nil {
			c.CarrierTransitions = atoi(m[1])
			c.Evidence["carrier_transitions"] = ln
		}
	}
	return out, len(out) > 0
}

// ---- show ip interface brief ----

// IPBrief es una fila; IP es "unassigned" en las interfaces sin dirección.
type IPBrief struct {
	Iface, IP, Status string
	Raw               string // nombre de la interfaz tal como lo imprime el equipo
	Protocol          string // up o down
}

var briefRe = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(?:YES|NO)\s+\S+\s+(.+?)\s+(\S+)\s*$`)

func ParseIPBrief(text string) ([]IPBrief, bool) {
	var out []IPBrief
	head := false
	for _, ln := range lines(text) {
		if strings.HasPrefix(ln, "Interface") && strings.Contains(ln, "IP-Address") {
			head = true
		}
		if m := briefRe.FindStringSubmatch(ln); m != nil {
			out = append(out, IPBrief{Iface: ShortIf(m[1]), IP: m[2], Status: m[3], Raw: m[1], Protocol: m[4]})
		}
	}
	return out, head || len(out) > 0
}

// ---- CDP / LLDP ----

// Neighbor es una entrada CDP o LLDP vista desde el equipo que la reporta.
// LocalIf y RemoteIf van abreviados (Gi1/0/1); LocalRaw y RemoteRaw, como los imprime el equipo.
type Neighbor struct {
	Protocol, Device, LocalIf, RemoteIf, MgmtIP string
	LocalRaw, RemoteRaw                         string
	Platform, Version                           string
	NativeVLAN, Duplex                          string   // del puerto remoto, tal como lo anuncia el vecino
	Capabilities                                []string // CDP: Router, Switch, Host, Phone, Trans-Bridge...; LLDP: Bridge, Router, Phone, WLAN...
}

// Infra dice si el vecino es un equipo de red (Router/Switch/Bridge) y no un
// teléfono, AP o host. Sin capacidades publicadas se asume que sí: ante la duda,
// el rastreo debe exigir evidencia del vecino en vez de declarar un acceso.
func (n Neighbor) Infra() bool {
	if len(n.Capabilities) == 0 {
		return true
	}
	has := map[string]bool{}
	for _, c := range n.Capabilities {
		has[c] = true
	}
	return (has["Router"] || has["Switch"] || has["Bridge"]) && !has["Phone"] && !has["WLAN"] && !has["Host"]
}

var (
	cdpCapRe  = regexp.MustCompile(`Capabilities:\s*(.*)$`)
	lldpCaps  = map[string]string{"B": "Bridge", "R": "Router", "T": "Phone", "W": "WLAN", "S": "Host", "C": "Docsis", "P": "Repeater", "O": "Other"}
	reSoftVer = regexp.MustCompile(`Software (\d\S*)`)
)

// kv parte "Clave: valor" (NX-OS a veces no deja espacio tras los dos puntos).
func kv(line string) (string, string, bool) {
	k, v, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v), true
}

// first devuelve el primer grupo de la primera expresión que coincida.
func first(s string, res ...*regexp.Regexp) string {
	for _, re := range res {
		if m := re.FindStringSubmatch(s); m != nil {
			return m[1]
		}
	}
	return ""
}

// ParseCDP entiende show cdp neighbors detail de IOS/IOS-XE y NX-OS.
func ParseCDP(text string) ([]Neighbor, bool) {
	var out []Neighbor
	var cur *Neighbor
	entryIP := ""
	wantVersion, inMgmt := false, false
	flush := func() {
		if cur != nil && cur.Device != "" {
			if cur.MgmtIP == "" {
				cur.MgmtIP = entryIP
			}
			out = append(out, *cur)
		}
	}
	for _, raw := range lines(text) {
		line := strings.TrimSpace(raw)
		if wantVersion && line != "" {
			cur.Version, wantVersion = first(line, verRe), false
			continue
		}
		k, v, ok := kv(line)
		if !ok {
			continue
		}
		if k == "device id" {
			flush()
			cur, entryIP, inMgmt = &Neighbor{Protocol: "cdp", Device: v}, "", false
			continue
		}
		if cur == nil {
			continue
		}
		if m := cdpCapRe.FindStringSubmatch(raw); m != nil {
			cur.Capabilities = strings.Fields(m[1])
		}
		switch {
		case k == "system name" && v != "":
			cur.Device = v
		case k == "platform":
			cur.Platform = strings.TrimPrefix(strings.TrimSpace(strings.Split(v, ",")[0]), "cisco ")
		case k == "interface":
			// "Interface: Gi1/0/1,  Port ID (outgoing port): Gi1/0/2"
			l, r, _ := strings.Cut(v, ",")
			cur.LocalRaw = strings.TrimSpace(l)
			cur.LocalIf = ShortIf(cur.LocalRaw)
			if _, rv, ok := kv(r); ok {
				cur.RemoteRaw, cur.RemoteIf = rv, ShortIf(rv)
			}
		case k == "version":
			wantVersion = true
		case k == "native vlan":
			cur.NativeVLAN = v
		case k == "duplex":
			cur.Duplex = v
		case strings.HasPrefix(k, "management address") || strings.HasPrefix(k, "mgmt address"):
			inMgmt = true
		case k == "ip address" || k == "ipv4 address":
			if inMgmt && cur.MgmtIP == "" {
				cur.MgmtIP = v
			} else if entryIP == "" {
				entryIP = v
			}
		}
	}
	flush()
	return out, len(out) > 0 || !strings.Contains(text, "Device ID")
}

// ParseLLDP entiende show lldp neighbors detail de IOS/IOS-XE y NX-OS.
func ParseLLDP(text string) ([]Neighbor, bool) {
	var out []Neighbor
	cur := map[string]string{}
	var desc string
	wantDesc := false
	done := func() {
		if cur["port id"] == "" && cur["chassis id"] == "" {
			return
		}
		n := Neighbor{Protocol: "lldp", Device: cur["system name"], RemoteRaw: cur["port id"], MgmtIP: cur["ip"], NativeVLAN: cur["vlan id"]}
		n.LocalRaw = cur["local intf"]
		if n.LocalRaw == "" {
			n.LocalRaw = cur["local port id"]
		}
		n.LocalIf, n.RemoteIf = ShortIf(n.LocalRaw), ShortIf(n.RemoteRaw)
		if n.MgmtIP == "" {
			n.MgmtIP = cur["management address"]
		}
		if n.Device == "" {
			n.Device = cur["chassis id"]
		}
		n.Version = first(desc, verRe, reSoftVer)
		if n.NativeVLAN == "-" {
			n.NativeVLAN = ""
		}
		caps := cur["enabled capabilities"]
		if caps == "" {
			caps = cur["system capabilities"]
		}
		for _, c := range strings.Split(caps, ",") {
			if name := lldpCaps[strings.TrimSpace(c)]; name != "" {
				n.Capabilities = append(n.Capabilities, name)
			}
		}
		out = append(out, n)
		cur, desc = map[string]string{}, ""
	}
	for _, raw := range lines(text) {
		line := strings.TrimSpace(raw)
		if wantDesc && line != "" {
			desc, wantDesc = line, false
			continue
		}
		k, v, ok := kv(line)
		if !ok {
			continue
		}
		switch k {
		case "local intf", "local port id", "chassis id":
			// Cada plataforma abre la entrada con una clave distinta; una clave repetida es la siguiente entrada.
			if cur[k] != "" || (k != "chassis id" && (cur["local intf"] != "" || cur["local port id"] != "")) {
				done()
			}
			cur[k] = v
		case "system description":
			if v == "" {
				wantDesc = true
			} else {
				desc = v
			}
		case "port id", "system name", "ip", "management address", "vlan id", "enabled capabilities", "system capabilities":
			if cur[k] == "" && !strings.EqualFold(v, "not advertised") {
				cur[k] = v
			}
		}
	}
	done()
	return out, len(out) > 0 || !strings.Contains(text, "Local Intf") && !strings.Contains(text, "Local Port id") && !strings.Contains(text, "Chassis id")
}

var reSTPHead = regexp.MustCompile(`^(?:VLAN|MST)0*(\d+)\s*$`)

// ParseSTPRoots (show spanning-tree) devuelve las VLAN o instancias MST donde este equipo es el root.
func ParseSTPRoots(text string) []int {
	var out []int
	cur := -1
	for _, raw := range lines(text) {
		line := strings.TrimSpace(raw)
		if m := reSTPHead.FindStringSubmatch(line); m != nil {
			cur = int(atoi(m[1]))
			continue
		}
		if cur >= 0 && strings.Contains(line, "This bridge is the root") {
			out = append(out, cur)
			cur = -1
		}
	}
	return out
}

// ---- show etherchannel summary ----

var (
	rePo     = regexp.MustCompile(`\b(Po\d+)\([A-Za-z]+\)`)
	reMember = regexp.MustCompile(`\b([A-Za-z][A-Za-z-]*\d[\d/.:]*)\([A-Za-z]+\)`)
)

// ParsePortChannels: port-channel → miembros (con líneas de continuación).
func ParsePortChannels(text string) map[string][]string {
	out := map[string][]string{}
	cur := ""
	for _, line := range lines(text) {
		if m := rePo.FindStringSubmatch(line); m != nil {
			cur = m[1]
		} else if strings.TrimSpace(line) == "" || !strings.HasPrefix(line, " ") {
			cur = ""
		}
		if cur == "" {
			continue
		}
		for _, m := range reMember.FindAllStringSubmatch(line, -1) {
			if !strings.HasPrefix(m[1], "Po") {
				out[cur] = append(out[cur], ShortIf(m[1]))
			}
		}
	}
	return out
}
