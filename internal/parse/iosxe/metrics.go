package iosxe

import (
	"regexp"
	"strconv"
	"strings"
)

// Lecturas para las gráficas y la vista de frente del switch (fase 19). Fixtures en
// testdata; sin validar en laboratorio.

// ---- show processes memory / show memory statistics: pools ----

// MemPool es un pool de memoria: "Processor", "I/O", "lsmpi_io", "reserve P"… tal como lo imprime el equipo.
type MemPool struct {
	Name              string
	Total, Used, Free int64
}

var (
	poolRe     = regexp.MustCompile(`^\s*(\S.*?) Pool Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)`)
	poolStatRe = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9/ _.-]*?)\s+[0-9A-Fa-f]{6,}\s+(\d+)\s+(\d+)\s+(\d+)(?:\s+\d+){0,2}\s*$`)
)

// ParseMemPools lee el encabezado de show processes memory ("<pool> Pool Total: … Used: … Free: …")
// o la tabla de show memory statistics. Descarta pools con total 0 o libre mayor que el total.
func ParseMemPools(text string) ([]MemPool, bool) {
	var pools, stats []MemPool
	add := func(dst *[]MemPool, name string, total, used, free int64) {
		if total > 0 && free <= total && used <= total {
			*dst = append(*dst, MemPool{name, total, used, free})
		}
	}
	for _, ln := range lines(text) {
		if m := poolRe.FindStringSubmatch(ln); m != nil {
			add(&pools, m[1], atoi(m[2]), atoi(m[3]), atoi(m[4]))
		} else if m := poolStatRe.FindStringSubmatch(ln); m != nil {
			add(&stats, m[1], atoi(m[2]), atoi(m[3]), atoi(m[4]))
		}
	}
	if len(pools) > 0 {
		return pools, true
	}
	return stats, len(stats) > 0
}

// ---- show interfaces trunk ----

type Trunk struct{ Port, Mode, Encap, Status, Native string }

// ParseTrunks lee la primera tabla de show interfaces trunk (puerto, modo, encapsulación, estado, VLAN nativa).
// ok=false si no está su cabecera; sin trunks devuelve ok=true y la lista vacía.
func ParseTrunks(text string) ([]Trunk, bool) {
	var out []Trunk
	head := false
	for _, ln := range lines(text) {
		f := strings.Fields(ln)
		if !head {
			head = len(f) >= 5 && f[0] == "Port" && f[1] == "Mode" && f[2] == "Encapsulation"
			continue
		}
		if len(f) == 0 {
			break // fin de la primera tabla
		}
		if len(f) >= 5 {
			out = append(out, Trunk{ShortIf(f[0]), f[1], f[2], f[3], f[4]})
		}
	}
	return out, head
}

// ---- show etherchannel summary ----

type ChannelMember struct{ Port, Flags string } // Flags: P (en el canal), D (caído), s, I, w…

type EtherChannel struct {
	Name     string // Po1
	State    string // SU, SD, RU…
	Protocol string // LACP, PAgP o "-"
	Members  []ChannelMember
}

var (
	ecRowRe    = regexp.MustCompile(`^\s*\d+\s+(Po\d+)\(([A-Za-z]+)\)\s+(\S+)\s*(.*)$`)
	ecMemberRe = regexp.MustCompile(`([A-Za-z][A-Za-z-]*\d[\d/.:]*)\(([A-Za-z]+)\)`)
)

// ParseEtherChannels lee show etherchannel summary con las banderas de cada miembro y sus líneas de continuación.
func ParseEtherChannels(text string) ([]EtherChannel, bool) {
	var out []EtherChannel
	for _, ln := range lines(text) {
		if m := ecRowRe.FindStringSubmatch(ln); m != nil {
			out = append(out, EtherChannel{Name: m[1], State: m[2], Protocol: m[3]})
			ln = m[4]
		} else if len(out) == 0 || strings.TrimSpace(ln) == "" || !strings.HasPrefix(ln, " ") {
			continue
		}
		c := &out[len(out)-1]
		for _, mm := range ecMemberRe.FindAllStringSubmatch(ln, -1) {
			c.Members = append(c.Members, ChannelMember{ShortIf(mm[1]), mm[2]})
		}
	}
	return out, len(out) > 0
}

// ---- posición de un puerto físico ----

// PortPos es la posición de un puerto físico a partir de su nombre. Module es el primer número y
// Stack el segundo (0 si el nombre solo trae dos números): Gi1/0/12 → Module 1, Stack 0, Port 12.
// (En un switch apilable el primero es el miembro del stack y el segundo la ranura; los nombres son los que pidió la vista.)
type PortPos struct {
	Kind          string // Gi, Fa, Te, Twe, Fo, Hu, Eth
	Module, Stack int
	Port          int
}

var portPosRe = regexp.MustCompile(`^([A-Za-z]+)(\d+)/(\d+)(?:/(\d+))?$`)

// ParsePortPos lee Gi1/0/12, GigabitEthernet1/0/12, Fa0/24 o Eth1/5. Subinterfaces (Gi1/0/1.100), Po, Vlan y
// nombres que no son puertos de hardware devuelven ok=false.
func ParsePortPos(name string) (PortPos, bool) {
	m := portPosRe.FindStringSubmatch(ShortIf(strings.TrimSpace(name)))
	if m == nil {
		return PortPos{}, false
	}
	switch m[1] {
	case "Gi", "Fa", "Te", "Twe", "Fo", "Hu", "Eth":
	default:
		return PortPos{}, false
	}
	n := func(x string) int { v, _ := strconv.Atoi(x); return v }
	if m[4] == "" {
		return PortPos{m[1], n(m[2]), 0, n(m[3])}, true
	}
	return PortPos{m[1], n(m[2]), n(m[3]), n(m[4])}, true
}
