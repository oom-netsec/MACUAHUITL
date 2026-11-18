package analyze

import (
	"encoding/json"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"strings"
	"testing"
	"time"
)

func TestTimelineEnHoraLocal(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	at := time.Date(2026, 11, 18, 4, 13, 9, 7e6, time.UTC)
	got := TimelineReport{Dir: "d", Events: []Event{{At: at, Source: "log", Text: "x"}}}.TextIn("en")
	if !strings.Contains(got, "2026-11-17 22:13:09.007 CST") {
		t.Errorf("sin hora local con zona: %q", got)
	}
}

func TestJSONRFC3339ConZona(t *testing.T) {
	r := TimelineReport{Dir: "d", Events: []Event{{At: time.Date(2026, 11, 18, 4, 13, 9, 0, time.UTC), Source: "log"}}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back struct{ Events []struct{ At string } }
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, back.Events[0].At); err != nil || !strings.HasSuffix(back.Events[0].At, "Z") {
		t.Errorf("at sin zona RFC 3339: %q (%v)", back.Events[0].At, err)
	}
}
