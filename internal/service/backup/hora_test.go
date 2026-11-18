package backup

import (
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/backup"
)

func TestListaDeRespaldosEnHoraLocal(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("CST", -6*3600)
	defer func() { time.Local = old }()
	e := backup.Entry{ID: "a", Kind: "running", Bytes: 5, At: time.Date(2026, 11, 18, 4, 13, 9, 0, time.UTC)}
	if got, want := listLine(e, ""), "a  2026-11-17 22:13:09 CST  running  5 bytes\n"; got != want {
		t.Errorf("%q, quería %q", got, want)
	}
}
