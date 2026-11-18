package diag

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/diag"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const (
	cero  = "# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (0 hosts up) scanned in 0.50 seconds"
	uno   = "# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (1 host up) scanned in 0.50 seconds"
	cero0 = "# Nmap done at Tue Nov 17 10:00:00 2026 -- 0 IP addresses (0 hosts up) scanned in 0.01 seconds"
)

func TestAvisoCeroHostsUp(t *testing.T) {
	for loc, want := range map[string]string{i18n.Es: "0 hosts arriba", i18n.En: "0 hosts up"} {
		w := avisoNmap(loc, diag.Nmap, nil, cero)
		if !strings.Contains(w, want) || !strings.Contains(w, "skip_discovery") {
			t.Errorf("%s: %q", loc, w)
		}
	}
	for name, c := range map[string]struct {
		tool diag.Tool
		opts map[string]string
		line string
	}{
		"con hosts up":     {diag.Nmap, nil, uno},
		"otra herramienta": {diag.Ping, nil, cero},
		"scan=ping":        {diag.Nmap, map[string]string{"scan": "ping"}, cero},
		"0 IP addresses":   {diag.Nmap, nil, cero0},
		"ya con -Pn":       {diag.Nmap, map[string]string{"skip_discovery": "true"}, cero},
	} {
		if w := avisoNmap(i18n.En, c.tool, c.opts, c.line); w != "" {
			t.Errorf("%s: avisó %q", name, w)
		}
	}
}
