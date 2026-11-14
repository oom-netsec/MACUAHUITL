package field

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// El error de una transferencia sale en el idioma de la llamada; la auditoría siempre en inglés y con %q.
func TestServeSinkErrorEnElIdiomaDeLaLlamada(t *testing.T) {
	for loc, want := range map[string]string{i18n.En: "file not published", i18n.Es: "archivo no publicado"} {
		var ev *v1.ServeFilesResponse
		var audit string
		k := newServeSink(loc, func(_, _, d string) { audit = d }, func(e *v1.ServeFilesResponse) error { ev = e; return nil })
		k.onTransfer(fileserve.Transfer{Proto: "tftp", File: "x", Result: "error", Error: "archivo no publicado", ReasonT: i18n.Tx("fileserve.reason.not_published")})
		k.stop()
		var m map[string]any
		if ev == nil || json.Unmarshal([]byte(ev.TransferJson), &m) != nil || m["Error"] != want {
			t.Errorf("%s: cliente %v", loc, m)
		}
		if !strings.Contains(audit, `result=error error="file not published"`) {
			t.Errorf("%s: auditoría %q", loc, audit)
		}
	}
}
