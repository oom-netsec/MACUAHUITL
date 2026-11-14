package field

import (
	"encoding/json"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
)

// Contrato para front: las transferencias de Campo también llevan dirCode (read|write) junto a Dir.
func TestServeFilesTransferenciaLlevaDirCode(t *testing.T) {
	for dir, want := range map[string]string{"lectura": "read", "escritura": "write"} {
		var ev *v1.ServeFilesResponse
		k := newServeSink("es", func(a, _, d string) {}, func(e *v1.ServeFilesResponse) error { ev = e; return nil })
		k.onTransfer(fileserve.Transfer{Proto: "tftp", Dir: dir, Result: "ok"})
		k.stop()
		var m map[string]any
		if ev == nil || json.Unmarshal([]byte(ev.TransferJson), &m) != nil || m["dirCode"] != want || m["Dir"] != dir {
			t.Errorf("%s: %v", dir, m)
		}
	}
}
