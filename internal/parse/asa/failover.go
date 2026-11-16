package asa

import (
	"regexp"
	"strings"
)

// FailoverIface es una línea "Interface nombre (ip): Normal (Monitored)"; en A/A lleva el contexto delante.
type FailoverIface struct {
	Context, Name, IP, State, Monitoring string
}

// FailoverGroup es un grupo A/A: "Group 1 State: Active" y su "Active time".
type FailoverGroup struct {
	ID         int
	State      string
	ActiveTime int64
}

// FailoverHost es el bloque "This host" u "Other host".
type FailoverHost struct {
	This       bool
	Role       string // Primary o Secondary
	State      string // solo A/S: Active, Standby Ready...
	ActiveTime int64  // solo A/S
	Groups     []FailoverGroup
	Slots      []string
	Ifaces     []FailoverIface
}

// StatRow es una fila de Stateful Failover Logical Update Statistics; las filas que este parser no
// conoce se guardan igual (Name es lo que trae el equipo).
type StatRow struct {
	Name                  string
	Xmit, Xerr, Rcv, Rerr int64
}

// Queue son las columnas Cur/Max/Total de Logical Update Queue Information.
type Queue struct{ Cur, Max, Total int64 }

// Failover es la salida de `show failover`.
type Failover struct {
	On                             bool
	Unit                           string // Primary o Secondary
	LANName, LANIface, LANState    string
	ReconnectTimeout               string
	UnitPoll, UnitHold             int64
	IfPoll, IfHold                 int64
	Policy                         string
	Monitored, MonitoredMax        int64
	VersionOurs, VersionMate       string
	SerialOurs, SerialMate         string
	LastFailover                   map[int]string // por grupo; en A/S, clave 0
	Hosts                          []FailoverHost
	LinkName, LinkIface, LinkState string // línea "Link :" de la tabla
	Stats                          []StatRow
	RecvQ, XmitQ                   Queue
}

// Host devuelve el bloque propio (this=true) o el del par.
func (f Failover) Host(this bool) (FailoverHost, bool) {
	for _, h := range f.Hosts {
		if h.This == this {
			return h, true
		}
	}
	return FailoverHost{}, false
}

// Stat busca una fila de la tabla por nombre.
func (f Failover) Stat(name string) (StatRow, bool) {
	for _, r := range f.Stats {
		if r.Name == name {
			return r, true
		}
	}
	return StatRow{}, false
}

var (
	reFoOn     = regexp.MustCompile(`^Failover (On|Off)\b`)
	reFoLAN    = regexp.MustCompile(`^Failover LAN Interface: (\S+) (\S+) \((\w+)\)`)
	reFoPoll   = regexp.MustCompile(`^(Unit|Interface) Poll frequency (\d+) seconds?, holdtime (\d+) seconds?`)
	reFoMon    = regexp.MustCompile(`^Monitored Interfaces (\d+) of (\d+) maximum`)
	reFoVer    = regexp.MustCompile(`^Version: Ours (\S+), Mate (\S+)`)
	reFoSer    = regexp.MustCompile(`^Serial Number: Ours (\S+), Mate (\S+)`)
	reFoLast   = regexp.MustCompile(`(?i)^(?:Group (\d+) )?last failover at: (.+)$`)
	reFoHost   = regexp.MustCompile(`^(This host|Other host):\s*(\w+)(?:\s+-\s+(.+))?$`)
	reFoGroup  = regexp.MustCompile(`^Group (\d+)\s+State:\s*(.+)$`)
	reFoActive = regexp.MustCompile(`^Active time:\s*(\d+)`)
	reFoSlot   = regexp.MustCompile(`^slot \d+:.*`)
	reFoIface  = regexp.MustCompile(`^(?:(\S+) )?Interface (\S+) \(([^)]*)\):\s*(.+?)(?:\s+\(([^)]*)\))?$`)
	reFoLink   = regexp.MustCompile(`^Link\s*:\s*(\S+) (\S+) \((\w+)\)`)
	reFoStat   = regexp.MustCompile(`^(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$`)
	reFoQueue  = regexp.MustCompile(`^(Recv|Xmit) Q:\s+(\d+)\s+(\d+)\s+(\d+)$`)
)

// ParseFailover lee `show failover` (A/S o A/A). ok=false si no aparece "Failover On/Off" o si es la
// salida de un contexto ("This context:"), que no trae bloques de host.
func ParseFailover(s string) (Failover, bool) {
	f := Failover{LastFailover: map[int]string{}}
	seen := false
	if strings.Contains(s, "This context:") {
		return f, false // dentro de un contexto no hay bloques de host
	}
	var host *FailoverHost
	inStats := false
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		if l == "" {
			continue
		}
		if m := reFoOn.FindStringSubmatch(l); m != nil {
			f.On, seen = m[1] == "On", true
			continue
		}
		if !seen {
			continue
		}
		if strings.HasPrefix(l, "Stateful Failover Logical Update Statistics") {
			inStats, host = true, nil
			continue
		}
		if inStats {
			switch {
			case reFoLink.MatchString(l):
				m := reFoLink.FindStringSubmatch(l)
				f.LinkName, f.LinkIface, f.LinkState = m[1], m[2], m[3]
			case reFoQueue.MatchString(l):
				m := reFoQueue.FindStringSubmatch(l)
				q := Queue{atoi(m[2]), atoi(m[3]), atoi(m[4])}
				if m[1] == "Recv" {
					f.RecvQ = q
				} else {
					f.XmitQ = q
				}
			default:
				// fila genérica: nombre (con espacios) y cuatro contadores; el encabezado y lo desconocido no encajan
				if m := reFoStat.FindStringSubmatch(l); m != nil {
					f.Stats = append(f.Stats, StatRow{m[1], atoi(m[2]), atoi(m[3]), atoi(m[4]), atoi(m[5])})
				}
			}
			continue
		}
		if m := reFoHost.FindStringSubmatch(l); m != nil {
			f.Hosts = append(f.Hosts, FailoverHost{This: m[1] == "This host", Role: m[2], State: strings.TrimSpace(m[3])})
			host = &f.Hosts[len(f.Hosts)-1]
			continue
		}
		if host != nil {
			if m := reFoGroup.FindStringSubmatch(l); m != nil {
				host.Groups = append(host.Groups, FailoverGroup{ID: int(atoi(m[1])), State: m[2]})
				continue
			}
			if m := reFoActive.FindStringSubmatch(l); m != nil {
				if n := len(host.Groups); n > 0 {
					host.Groups[n-1].ActiveTime = atoi(m[1])
				} else {
					host.ActiveTime = atoi(m[1])
				}
				continue
			}
			if reFoSlot.MatchString(l) {
				host.Slots = append(host.Slots, l)
				continue
			}
			if m := reFoIface.FindStringSubmatch(l); m != nil {
				host.Ifaces = append(host.Ifaces, FailoverIface{m[1], m[2], m[3], m[4], m[5]})
				continue
			}
			continue
		}
		switch {
		case strings.HasPrefix(l, "Failover unit "):
			f.Unit = strings.TrimPrefix(l, "Failover unit ")
		case reFoLAN.MatchString(l):
			m := reFoLAN.FindStringSubmatch(l)
			f.LANName, f.LANIface, f.LANState = m[1], m[2], m[3]
		case strings.HasPrefix(l, "Reconnect timeout "):
			f.ReconnectTimeout = strings.TrimPrefix(l, "Reconnect timeout ")
		case reFoPoll.MatchString(l):
			m := reFoPoll.FindStringSubmatch(l)
			if m[1] == "Unit" {
				f.UnitPoll, f.UnitHold = atoi(m[2]), atoi(m[3])
			} else {
				f.IfPoll, f.IfHold = atoi(m[2]), atoi(m[3])
			}
		case strings.HasPrefix(l, "Interface Policy "):
			f.Policy = strings.TrimPrefix(l, "Interface Policy ")
		case reFoMon.MatchString(l):
			m := reFoMon.FindStringSubmatch(l)
			f.Monitored, f.MonitoredMax = atoi(m[1]), atoi(m[2])
		case reFoVer.MatchString(l):
			m := reFoVer.FindStringSubmatch(l)
			f.VersionOurs, f.VersionMate = m[1], m[2]
		case reFoSer.MatchString(l):
			m := reFoSer.FindStringSubmatch(l)
			f.SerialOurs, f.SerialMate = m[1], m[2]
		case reFoLast.MatchString(l):
			m := reFoLast.FindStringSubmatch(l)
			f.LastFailover[int(atoi(m[1]))] = strings.TrimSpace(m[2])
		}
	}
	return f, seen
}

// FailoverStateRow es una fila de `show failover state`; Group es 0 en A/S.
type FailoverStateRow struct {
	This   bool
	Role   string
	Group  int
	State  string
	Reason string
	Time   string
}

// FailoverState es `show failover state`.
type FailoverState struct {
	Rows                   []FailoverStateRow
	ConfigState, CommState string
}

var (
	reStHost = regexp.MustCompile(`^(This host|Other host)\s+-\s+(\w+)`)
	reStTime = regexp.MustCompile(`\s*(\d\d:\d\d:\d\d \S+ \w{3} +\d+ \d{4})$`)
	reStGrp  = regexp.MustCompile(`^Group (\d+)\s+`)
)

// ParseFailoverState lee `show failover state`. ok=false sin ningún "This host -" / "Other host -".
func ParseFailoverState(s string) (FailoverState, bool) {
	var st FailoverState
	host := -1 // índice de la fila del host (un puntero se invalidaría al crecer el slice)
	section := ""
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		switch {
		case l == "":
		case strings.HasPrefix(l, "===") && !strings.HasPrefix(l, "====Configuration State") && !strings.HasPrefix(l, "====Communication State"):
			section, host = "", -1 // encabezado desconocido: cierra la sección
		case strings.HasPrefix(l, "====Configuration State"):
			section, host = "cfg", -1
		case strings.HasPrefix(l, "====Communication State"):
			section, host = "comm", -1
		case reStHost.MatchString(l):
			m := reStHost.FindStringSubmatch(l)
			st.Rows = append(st.Rows, FailoverStateRow{This: m[1] == "This host", Role: m[2]})
			host, section = len(st.Rows)-1, ""
		case section == "cfg" && st.ConfigState == "":
			st.ConfigState = l
		case section == "comm" && st.CommState == "":
			st.CommState = l
		case host >= 0 && !strings.HasPrefix(l, "State "):
			r := st.Rows[host]
			if m := reStGrp.FindStringSubmatch(l); m != nil {
				r.Group, l = int(atoi(m[1])), strings.TrimPrefix(l, m[0])
			}
			if m := reStTime.FindStringSubmatch(l); m != nil {
				r.Time, l = m[1], strings.TrimSuffix(l, m[0])
			}
			c := cols(l)
			r.State = c[0]
			r.Reason = strings.Join(c[1:], " ")
			// la primera fila (A/S) completa el bloque del host; las siguientes (A/A) lo duplican por grupo
			if st.Rows[host].State == "" && r.Group == 0 {
				st.Rows[host] = r
			} else {
				st.Rows = append(st.Rows, r)
			}
		}
	}
	return st, len(st.Rows) > 0
}

// FailoverHistoryEntry es una transición de `show failover history`.
type FailoverHistoryEntry struct {
	Time, From, To, Reason string
	Peer                   bool // del bloque PEER History (details)
	ThisHost, OtherHost    int  // conteo de "Interface check"
	Details                []string
}

var (
	reHiTime = regexp.MustCompile(`^\d\d:\d\d:\d\d \S+ \w{3} +\d+ \d{4}$`)
	reHiHost = regexp.MustCompile(`^(This|Other) Host:(\d+)$`)
)

// ParseFailoverHistory lee `show failover history [details]`. ok=false si no hay encabezado "From State".
func ParseFailoverHistory(s string) ([]FailoverHistoryEntry, bool) {
	var out []FailoverHistoryEntry
	header, peer := false, false
	var cur *FailoverHistoryEntry
	expect := false // la línea siguiente a la hora trae From/To/Reason
	for _, raw := range lines(s) {
		l := strings.TrimSpace(raw)
		switch {
		case l == "" || strings.HasPrefix(l, "===") && !strings.Contains(l, "PEER"):
		case strings.HasPrefix(l, "From State"):
			header = true
		case strings.HasPrefix(l, "PEER History") || strings.Contains(l, "PEER-HISTORY"):
			peer = true
		case reHiTime.MatchString(l):
			out = append(out, FailoverHistoryEntry{Time: l, Peer: peer})
			cur, expect = &out[len(out)-1], true
		case expect:
			expect = false
			c := colSep.Split(l, 3) // el motivo puede traer dobles espacios
			if len(c) == 3 {
				cur.From = strings.TrimSpace(c[0])
				cur.To = strings.TrimSpace(c[1])
				cur.Reason = strings.Join(strings.Fields(c[2]), " ")
			}
		case cur != nil && reHiHost.MatchString(l):
			m := reHiHost.FindStringSubmatch(l)
			if m[1] == "This" {
				cur.ThisHost = int(atoi(m[2]))
			} else {
				cur.OtherHost = int(atoi(m[2]))
			}
		case cur != nil:
			cur.Details = append(cur.Details, l)
		}
	}
	return out, header
}
