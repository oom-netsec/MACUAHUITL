package metrics

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Comandos del estado de puertos.
const (
	CmdPortStatus = "show interfaces status"
	CmdTrunk      = "show interfaces trunk"
	CmdChannels   = "show etherchannel summary"
)

// PortCommands son los comandos de solo lectura que se corren en vivo o que el trabajo debió recolectar.
var PortCommands = []string{CmdPortStatus, CmdTrunk, CmdChannels}

// Port es un puerto físico para dibujar el frente del switch. Los textos de estado, VLAN, dúplex,
// velocidad y tipo son los que imprime el equipo.
type Port struct {
	Name, Kind            string // Gi1/0/12, Gi
	Module, Stack, Number int    // Gi1/0/12 → 1, 0, 12 (ver iosxe.PortPos)
	Description           string
	Status                string // connected, notconnect, disabled, err-disabled, inactive…
	VLAN                  string // «10», «trunk», «routed»
	Duplex, Speed, Type   string
	DuplexMode            string // full, half o auto, sin el prefijo «a-»
	SpeedMbps             int    // 0 si está en auto o no se sabe
	AutoNeg               bool   // velocidad o dúplex negociados («a-1000», «auto»)
	Trunk                 bool
	TrunkNative           string // VLAN nativa si show interfaces trunk la dio
	Channel               string // Po1 si es miembro de un port-channel
	ChannelFlags          string // P (en el canal), D (caído), s, I, w…
}

type ChannelMember struct{ Port, Flags string }

type Channel struct {
	Name, State, Protocol string
	Members               []ChannelMember
}

type PortStatus struct {
	Ports    []Port
	Channels []Channel
	Warnings []string
}

// PortDevice es el estado de puertos de un equipo, con su origen.
type PortDevice struct {
	PortStatus
	Address, Hostname string
	At                time.Time // hora de show interfaces status
}

// PortTexts son las salidas de los comandos; HaveX dice si el comando se recolectó (aunque venga vacío).
type PortTexts struct {
	Status, Trunk, Channels string
	HaveTrunk, HaveChannels bool
}

func speedMbps(s string) (mbps int, auto bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if rest, ok := strings.CutPrefix(s, "a-"); ok {
		s, auto = rest, true
	}
	if s == "auto" {
		return 0, true
	}
	mult := 1
	if rest, ok := strings.CutSuffix(s, "g"); ok {
		s, mult = rest, 1000
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, auto
	}
	return n * mult, auto
}

func duplexMode(s string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "a-")
}

// BuildPorts arma el estado de los puertos físicos con lo que dicen show interfaces status, show interfaces
// trunk y show etherchannel summary. Lo que falta o no se entiende queda en Warnings; sin el estado no hay puertos.
func BuildPorts(in PortTexts) PortStatus {
	var ps PortStatus
	warnMissing := func(cmd, why string) {
		ps.Warnings = append(ps.Warnings, fmt.Sprintf("falta el comando %s: %s", cmd, why))
	}
	rows, ok := iosxe.ParseIfStatus(in.Status)
	switch {
	case strings.TrimSpace(in.Status) == "":
		warnMissing(CmdPortStatus, "sin él no hay puertos que mostrar")
		return ps
	case !ok:
		ps.Warnings = append(ps.Warnings, "no se pudo leer "+CmdPortStatus+": no trae la tabla de puertos")
		return ps
	}
	trunks := map[string]iosxe.Trunk{}
	if !in.HaveTrunk {
		warnMissing(CmdTrunk, "«trunk» se deduce de la columna VLAN y no se conoce la VLAN nativa")
	} else if ts, ok := iosxe.ParseTrunks(in.Trunk); !ok {
		ps.Warnings = append(ps.Warnings, "no se pudo leer "+CmdTrunk)
	} else {
		for _, t := range ts {
			trunks[strings.ToLower(t.Port)] = t
		}
	}
	chOf := map[string]ChannelMember{}
	chName := map[string]string{}
	if !in.HaveChannels {
		warnMissing(CmdChannels, "no se sabe qué puertos son miembros de un canal")
	} else if ecs, ok := iosxe.ParseEtherChannels(in.Channels); !ok {
		if !strings.Contains(in.Channels, "channel-groups in use: 0") { // un switch sin canales lo dice así
			ps.Warnings = append(ps.Warnings, "no se pudo leer "+CmdChannels)
		}
	} else {
		for _, ec := range ecs {
			ch := Channel{Name: ec.Name, State: ec.State, Protocol: ec.Protocol}
			for _, m := range ec.Members {
				ch.Members = append(ch.Members, ChannelMember{m.Port, m.Flags})
				chOf[strings.ToLower(m.Port)], chName[strings.ToLower(m.Port)] = ChannelMember{m.Port, m.Flags}, ec.Name
			}
			ps.Channels = append(ps.Channels, ch)
		}
	}
	for _, r := range rows {
		pos, isPort := iosxe.ParsePortPos(r.Port)
		if !isPort { // Po, Vlan, Lo…: no son puertos del frente
			continue
		}
		key := strings.ToLower(r.Port)
		mbps, aSpeed := speedMbps(r.Speed)
		dm := duplexMode(r.Duplex)
		p := Port{Name: r.Port, Kind: pos.Kind, Module: pos.Module, Stack: pos.Stack, Number: pos.Port, Description: r.Name, Status: strings.ToLower(r.Status),
			VLAN: r.VLAN, Duplex: r.Duplex, Speed: r.Speed, Type: r.Type, DuplexMode: dm, SpeedMbps: mbps,
			AutoNeg: aSpeed || strings.HasPrefix(strings.ToLower(r.Duplex), "a-") || dm == "auto"}
		p.Trunk = strings.EqualFold(r.VLAN, "trunk")
		if t, ok := trunks[key]; ok {
			p.Trunk, p.TrunkNative = p.Trunk || t.Status == "trunking", t.Native
		}
		if m, ok := chOf[key]; ok {
			p.Channel, p.ChannelFlags = chName[key], m.Flags
		}
		ps.Ports = append(ps.Ports, p)
	}
	return ps
}

var portWant = map[string]bool{CmdPortStatus: true, CmdTrunk: true, CmdChannels: true}

// PortsFromJob lee el estado de puertos de la evidencia de un trabajo de Patrol (la ronda más reciente de
// cada comando). device elige el equipo (dirección o nombre); puede ir vacío si el trabajo tiene uno solo.
func PortsFromJob(dir, device string) (PortDevice, error) {
	devs, err := listDevices(dir)
	if err != nil {
		return PortDevice{}, fmt.Errorf("metrics: %w", err)
	}
	var pick []devDir
	for _, dd := range devs {
		if dd.matches(device) {
			pick = append(pick, dd)
		}
	}
	switch {
	case len(pick) == 0 && device != "":
		return PortDevice{}, fmt.Errorf("metrics: el trabajo no tiene datos del equipo %q", device)
	case len(pick) == 0:
		return PortDevice{}, fmt.Errorf("metrics: el trabajo no tiene salidas de equipos")
	case len(pick) > 1:
		var names []string
		for _, r := range pick {
			names = append(names, r.Host+" ("+r.IP+")")
		}
		return PortDevice{}, fmt.Errorf("metrics: el trabajo tiene %d equipos (%s): indica uno", len(pick), strings.Join(names, ", "))
	}
	d, ok := loadDevice(dir, pick[0], portWant, parseText, true)
	if !ok {
		return PortDevice{}, fmt.Errorf("metrics: el trabajo no tiene salidas del equipo %s", pick[0].Host)
	}
	last := map[string]section{}
	for _, s := range d.Secs { // ordenadas: gana la ronda más reciente
		last[s.Cmd] = s
	}
	text := func(c string) string { s, _ := last[c].Val.(string); return s }
	in := PortTexts{Status: text(CmdPortStatus), Trunk: text(CmdTrunk), Channels: text(CmdChannels)}
	_, in.HaveTrunk = last[CmdTrunk]
	_, in.HaveChannels = last[CmdChannels]
	ps := BuildPorts(in)
	ps.Warnings = append(d.Warnings, ps.Warnings...)
	return PortDevice{PortStatus: ps, Address: d.IP, Hostname: d.Host, At: last[CmdPortStatus].At}, nil
}
