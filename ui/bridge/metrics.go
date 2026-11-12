package bridge

import (
	"context"
	"path/filepath"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Métricas (Fase 19): series de CPU, memoria e interfaces de un trabajo de Patrol ----
// Las listas siempre son arreglos (nunca null) para que las gráficas no tengan que revisarlo.

type MetricsQueryDTO struct {
	Job           string   `json:"job"` // ID del trabajo o carpeta de salida absoluta
	Device        string   `json:"device"`
	MaxPoints     int      `json:"maxPoints"`
	MaxInterfaces int      `json:"maxInterfaces"`
	Interfaces    []string `json:"interfaces"`
}

type CpuPointDTO struct {
	Round   int     `json:"round"`
	AtMs    int64   `json:"atMs"`
	FiveSec float64 `json:"fiveSec"`
	OneMin  float64 `json:"oneMin"`
	FiveMin float64 `json:"fiveMin"`
}

type MemoryPointDTO struct {
	Round int   `json:"round"`
	AtMs  int64 `json:"atMs"`
	Used  int64 `json:"used"`
	Free  int64 `json:"free"`
	Total int64 `json:"total"`
}

type MemorySeriesDTO struct {
	Pool   string           `json:"pool"`
	Points []MemoryPointDTO `json:"points"`
}

type InterfacePointDTO struct {
	Round      int     `json:"round"`
	AtMs       int64   `json:"atMs"`
	InBps      float64 `json:"inBps"`
	OutBps     float64 `json:"outBps"`
	Source     string  `json:"source"`
	InUtilPct  float64 `json:"inUtilPct"`
	OutUtilPct float64 `json:"outUtilPct"`
	DeltaOK    bool    `json:"deltaOk"`
	InErrors   int64   `json:"inErrors"`
	OutErrors  int64   `json:"outErrors"`
	CRC        int64   `json:"crc"`
	Resets     int64   `json:"resets"`
	InDrops    int64   `json:"inDrops"`
	OutDrops   int64   `json:"outDrops"`
	Reboot     bool    `json:"reboot"`
}

type InterfaceSeriesDTO struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	BwKbit      int64               `json:"bwKbit"`
	PeakUtilPct float64             `json:"peakUtilPct"`
	Points      []InterfacePointDTO `json:"points"`
}

type RebootDTO struct {
	Round  int   `json:"round"`
	BootMs int64 `json:"bootMs"`
}

type DeviceMetricsDTO struct {
	Address        string               `json:"address"`
	Hostname       string               `json:"hostname"`
	Rounds         int                  `json:"rounds"`
	CPU            []CpuPointDTO        `json:"cpu"`
	Memory         []MemorySeriesDTO    `json:"memory"`
	Interfaces     []InterfaceSeriesDTO `json:"interfaces"`
	InterfaceTotal int                  `json:"interfaceTotal"`
	Reboots        []RebootDTO          `json:"reboots"`
	Truncated      bool                 `json:"truncated"`
	Warnings       []string             `json:"warnings"`
}

type JobMetricsDTO struct {
	Devices  []DeviceMetricsDTO `json:"devices"`
	Warnings []string           `json:"warnings"`
}

func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// JobMetrics devuelve las series de un trabajo de Patrol (ID o carpeta absoluta).
func (b *Bridge) JobMetrics(q MetricsQueryDTO) (JobMetricsDTO, error) {
	req := &v1.GetJobMetricsRequest{Device: q.Device, MaxPoints: int32(q.MaxPoints), MaxInterfaces: int32(q.MaxInterfaces), Interfaces: q.Interfaces}
	if filepath.IsAbs(q.Job) {
		req.Dir = q.Job
	} else {
		req.JobId = q.Job
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (JobMetricsDTO, error) {
		r, err := v1.NewMetricsServiceClient(c).GetJobMetrics(ctx, req)
		out := JobMetricsDTO{Devices: []DeviceMetricsDTO{}, Warnings: strs(r.GetWarnings())}
		for _, d := range r.GetDevices() {
			m := DeviceMetricsDTO{Address: d.Address, Hostname: d.Hostname, Rounds: int(d.Rounds), CPU: []CpuPointDTO{}, Memory: []MemorySeriesDTO{}, Interfaces: []InterfaceSeriesDTO{},
				InterfaceTotal: int(d.InterfaceTotal), Reboots: []RebootDTO{}, Truncated: d.Truncated, Warnings: strs(d.Warnings)}
			for _, p := range d.Cpu {
				m.CPU = append(m.CPU, CpuPointDTO{int(p.Round), p.AtMs, p.FiveSec, p.OneMin, p.FiveMin})
			}
			for _, s := range d.Memory {
				ms := MemorySeriesDTO{Pool: s.Pool, Points: []MemoryPointDTO{}}
				for _, p := range s.Points {
					ms.Points = append(ms.Points, MemoryPointDTO{int(p.Round), p.AtMs, p.Used, p.Free, p.Total})
				}
				m.Memory = append(m.Memory, ms)
			}
			for _, s := range d.Interfaces {
				is := InterfaceSeriesDTO{Name: s.Name, Description: s.Description, BwKbit: s.BwKbit, PeakUtilPct: s.PeakUtilPct, Points: []InterfacePointDTO{}}
				for _, p := range s.Points {
					is.Points = append(is.Points, InterfacePointDTO{int(p.Round), p.AtMs, p.InBps, p.OutBps, p.Source, p.InUtilPct, p.OutUtilPct, p.DeltaOk,
						p.InErrors, p.OutErrors, p.Crc, p.Resets, p.InDrops, p.OutDrops, p.Reboot})
				}
				m.Interfaces = append(m.Interfaces, is)
			}
			for _, e := range d.Reboots {
				m.Reboots = append(m.Reboots, RebootDTO{int(e.Round), e.BootMs})
			}
			out.Devices = append(out.Devices, m)
		}
		return out, err
	})
}

// ---- Estado de puertos para la vista de frente del switch ----

// PortStatusQueryDTO: con Job (ID o carpeta absoluta) lee la evidencia; sin Job consulta en vivo a Device por SSH.
type PortStatusQueryDTO struct {
	Job          string   `json:"job"`
	Device       string   `json:"device"`
	Port         int      `json:"port"`
	CredentialID string   `json:"credentialId"`
	HostKeys     []string `json:"acceptedHostKeys"`
	LegacySSH    bool     `json:"legacySsh"`
}

type PortInfoDTO struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Module         int    `json:"module"`
	Stack          int    `json:"stack"`
	Number         int    `json:"number"`
	Description    string `json:"description"`
	Status         string `json:"status"`
	VLAN           string `json:"vlan"`
	Duplex         string `json:"duplex"`
	Speed          string `json:"speed"`
	DuplexMode     string `json:"duplexMode"`
	SpeedMbps      int    `json:"speedMbps"`
	AutoNegotiated bool   `json:"autoNegotiated"`
	Type           string `json:"type"`
	Trunk          bool   `json:"trunk"`
	TrunkNative    string `json:"trunkNative"`
	Channel        string `json:"channel"`
	ChannelFlags   string `json:"channelFlags"`
}

type ChannelMemberDTO struct {
	Port  string `json:"port"`
	Flags string `json:"flags"`
}

type PortChannelDTO struct {
	Name     string             `json:"name"`
	State    string             `json:"state"`
	Protocol string             `json:"protocol"`
	Members  []ChannelMemberDTO `json:"members"`
}

type PortStatusDTO struct {
	Source   string           `json:"source"` // job o live
	Address  string           `json:"address"`
	Hostname string           `json:"hostname"`
	AtMs     int64            `json:"atMs"`
	Ports    []PortInfoDTO    `json:"ports"`
	Channels []PortChannelDTO `json:"channels"`
	Warnings []string         `json:"warnings"`
}

// PortStatus devuelve los puertos físicos de un switch para dibujar su frente.
func (b *Bridge) PortStatus(q PortStatusQueryDTO) (PortStatusDTO, error) {
	req := &v1.GetPortStatusRequest{Device: q.Device, Port: uint32(q.Port), CredentialId: q.CredentialID, AcceptedHostKeyFingerprints: q.HostKeys, LegacySsh: q.LegacySSH}
	if filepath.IsAbs(q.Job) {
		req.Dir = q.Job
	} else {
		req.JobId = q.Job
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (PortStatusDTO, error) {
		r, err := v1.NewMetricsServiceClient(c).GetPortStatus(ctx, req)
		out := PortStatusDTO{Source: r.GetSource(), Address: r.GetAddress(), Hostname: r.GetHostname(), AtMs: r.GetAtMs(), Ports: []PortInfoDTO{}, Channels: []PortChannelDTO{}, Warnings: strs(r.GetWarnings())}
		for _, p := range r.GetPorts() {
			out.Ports = append(out.Ports, PortInfoDTO{p.Name, p.Kind, int(p.Module), int(p.Stack), int(p.Number), p.Description, p.Status, p.Vlan, p.Duplex, p.Speed, p.DuplexMode,
				int(p.SpeedMbps), p.AutoNegotiated, p.Type, p.Trunk, p.TrunkNative, p.Channel, p.ChannelFlags})
		}
		for _, ch := range r.GetChannels() {
			dto := PortChannelDTO{Name: ch.Name, State: ch.State, Protocol: ch.Protocol, Members: []ChannelMemberDTO{}}
			for _, m := range ch.Members {
				dto.Members = append(dto.Members, ChannelMemberDTO{m.Port, m.Flags})
			}
			out.Channels = append(out.Channels, dto)
		}
		return out, err
	})
}
