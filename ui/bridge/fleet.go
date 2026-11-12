package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Flota (Fase 15): solo lee outputs/ en el núcleo ----

type FleetDTO struct {
	Json     string `json:"json"`
	Text     string `json:"text"`
	Svg      string `json:"svg,omitempty"`
	Csv      string `json:"csv,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

func fleetDTO(r *v1.ToolReport, err error) (FleetDTO, error) {
	return FleetDTO{Json: r.GetJson(), Text: r.GetText()}, err
}

func (b *Bridge) FleetFind(q string) (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Find(ctx, &v1.FindRequest{Query: q})
		return fleetDTO(r.GetReport(), err)
	})
}

func (b *Bridge) FleetTrace(q string) (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Trace(ctx, &v1.TraceRequest{Query: q})
		return fleetDTO(r.GetReport(), err)
	})
}

func (b *Bridge) FleetPath(src, dst string) (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Path(ctx, &v1.PathRequest{Query: src, Dst: dst})
		d, err := fleetDTO(r.GetReport(), err)
		d.Svg = r.GetSvg()
		return d, err
	})
}

func (b *Bridge) FleetHealth() (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Health(ctx, &v1.HealthRequest{})
		return fleetDTO(r.GetReport(), err)
	})
}

func (b *Bridge) FleetSummary() (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Summary(ctx, &v1.SummaryRequest{})
		return fleetDTO(r.GetReport(), err)
	})
}

// FleetCapacity: need vacío = solo mostrar; "1.2G" marca a quién le cabe.
func (b *Bridge) FleetCapacity(need string) (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Capacity(ctx, &v1.CapacityRequest{Need: need})
		return fleetDTO(r.GetReport(), err)
	})
}

func (b *Bridge) FleetInventory() (FleetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (FleetDTO, error) {
		r, err := v1.NewFleetServiceClient(c).Inventory(ctx, &v1.InventoryRequest{})
		d, err := fleetDTO(r.GetReport(), err)
		d.Csv, d.Markdown = r.GetCsv(), r.GetMarkdown()
		return d, err
	})
}
