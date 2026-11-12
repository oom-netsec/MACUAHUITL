package core

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/acl"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/change"
	"github.com/oom-netsec/MACUAHUITL/internal/cleaner"
	"github.com/oom-netsec/MACUAHUITL/internal/compliance"
	"github.com/oom-netsec/MACUAHUITL/internal/drift"
	"github.com/oom-netsec/MACUAHUITL/internal/fleet"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/upgrade"
)

// Todo informe que pasa por service.ReportL debe poder traducirse en su sitio: puntero, y sin mapas ni
// interfaces que lleven textos (Localize no los recorre).
func TestInformesDeReportLSonLocalizables(t *testing.T) {
	for name, v := range map[string]any{
		"fleet.Find": &fleet.FindResult{}, "fleet.Trace": &fleet.TraceResult{}, "fleet.Path": &fleet.PathResult{},
		"fleet.Health": &fleet.HealthResult{}, "fleet.Summary": &fleet.SummaryResult{}, "fleet.Capacity": &fleet.CapacityResult{},
		"fleet.Inventory": &fleet.InventoryResult{}, "analyze.Report": &analyze.Report{}, "analyze.Diff": &analyze.DiffReport{},
		"analyze.Timeline": &analyze.TimelineReport{}, "change": &change.Report{}, "upgrade": &upgrade.Report{},
		"compliance": &compliance.Report{}, "drift": &drift.Report{}, "cleaner": &cleaner.Result{}, "acl.Finding": &[]acl.Finding{},
	} {
		if err := i18n.CheckLocalizable(v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
