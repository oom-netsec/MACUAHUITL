package core

import (
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// Un equipo partial no cuenta como correcto ni como fallido.
func TestTallyContarParcial(t *testing.T) {
	j := &job{}
	for _, s := range []string{"completed", "partial", "partial", "failed", "skipped"} {
		j.tally(s)
	}
	if j.OK != 1 || j.Partial != 2 || j.Failed != 2 {
		t.Fatalf("ok=%d partial=%d failed=%d", j.OK, j.Partial, j.Failed)
	}
	j.enterRound(2)
	if j.OK+j.Partial+j.Failed != 0 {
		t.Fatal("la ronda nueva no reinicia los conteos")
	}
	if deviceStates["partial"] != v1.DeviceState_DEVICE_STATE_PARTIAL {
		t.Fatal("falta partial en deviceStates")
	}
}

// El fin de ronda dice los parciales solo cuando los hay; sin ellos el texto de siempre.
func TestRoundPhaseTextoConParciales(t *testing.T) {
	for _, c := range []struct {
		partial int
		key     string
		es, en  string
	}{
		{0, "phase.ok_failed", "2 correctos, 1 con fallas", "2 successful, 1 failed"},
		{3, "phase.ok_partial_failed", "2 correctos, 3 parciales, 1 con fallas", "2 successful, 3 partial, 1 failed"},
	} {
		key, args := roundPhase(2, c.partial, 1)
		if key != c.key {
			t.Fatalf("clave %q, quería %q", key, c.key)
		}
		if es, en := i18n.Tx(key, argsKV(args)...).In(i18n.Es), i18n.Tx(key, argsKV(args)...).In(i18n.En); es != c.es || en != c.en {
			t.Errorf("es=%q en=%q", es, en)
		}
	}
}

func argsKV(a i18n.Args) []any {
	var kv []any
	for k, v := range a {
		kv = append(kv, k, v)
	}
	return kv
}

// En el proto, los cortes solo viajan con partial; un equipo failed tras un corte va con 0.
func TestCutOfSoloConParcial(t *testing.T) {
	d := patrol.DeviceResult{State: "partial", CutCommands: []string{"a", "b"}, Reconnects: 2}
	if c := cutOf(d); c.cut != 2 || c.reconnects != 2 {
		t.Fatalf("partial: %+v", c)
	}
	d.State = "failed"
	if c := cutOf(d); c.cut != 0 || c.reconnects != 0 {
		t.Fatalf("failed: %+v", c)
	}
}
