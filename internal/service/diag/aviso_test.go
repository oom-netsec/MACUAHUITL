package diag

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/diag"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestAvisoCeroHostsUp(t *testing.T) {
	cero := "# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (0 hosts up) scanned in 0.50 seconds"
	uno := "# Nmap done at Tue Nov 17 10:00:00 2026 -- 1 IP address (1 host up) scanned in 0.50 seconds"
	for loc, want := range map[string]string{i18n.Es: "0 hosts respondieron", i18n.En: "0 hosts responded"} {
		w := avisoNmap(loc, diag.Nmap, cero)
		if !strings.Contains(w, want) || !strings.Contains(w, "skip_discovery") {
			t.Errorf("%s: %q", loc, w)
		}
	}
	if avisoNmap(i18n.En, diag.Nmap, uno) != "" || avisoNmap(i18n.En, diag.Ping, cero) != "" {
		t.Error("aviso donde no toca")
	}
}
