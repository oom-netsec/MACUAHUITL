package field

import (
	"bytes"
	"regexp"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestFieldHoraConFechaYZona(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	var out bytes.Buffer
	printTransfer(&cli.Env{Out: &out}, `{"Client":"c","File":"f","Result":"ok"}`)
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d CST  c`).MatchString(out.String()) {
		t.Errorf("%q", out.String())
	}
}
