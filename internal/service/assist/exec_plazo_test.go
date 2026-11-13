package assist

import (
	"context"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// plazoDrv anota el plazo total del contexto con que Run fue llamado.
type plazoDrv struct {
	platform.Driver
	left []time.Duration
}

func (p *plazoDrv) Err() error { return nil }
func (p *plazoDrv) Run(ctx context.Context, cmd string, _ time.Duration) (platform.Output, error) {
	dl, ok := ctx.Deadline()
	if !ok {
		p.left = append(p.left, -1)
	} else {
		p.left = append(p.left, time.Until(dl))
	}
	return platform.Output{Text: "[OK]\n"}, nil
}

// Como el timeout del driver es de inactividad, el modo asistido pone un plazo total de 2 min a cada comando.
func TestReadYSaveTienenPlazoTotal(t *testing.T) {
	drv := &plazoDrv{}
	e := newExec(nil, "plan-x", nil, transport.HostKeyPolicy{})
	e.conns["sw"] = &conn{drv: drv}
	if _, err := e.Read(context.Background(), "sw", []string{"show version"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Save(context.Background(), "sw"); err != nil {
		t.Fatal(err)
	}
	if len(drv.left) != 2 {
		t.Fatalf("Run se llamó %d veces", len(drv.left))
	}
	for i, l := range drv.left {
		if l <= time.Minute || l > 2*time.Minute {
			t.Errorf("llamada %d: plazo total %s, quiero ~2 min", i, l)
		}
	}
}
