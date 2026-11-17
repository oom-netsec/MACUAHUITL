package diag

import (
	"reflect"
	"testing"
)

func TestSweepArgv(t *testing.T) {
	for _, c := range []struct {
		win  bool
		in   []string
		want []string
	}{
		{false, []string{"-n", "-c", "1", "192.0.2.1"}, []string{"-n", "-c", "1", "-s", "9", "192.0.2.1"}},
		{true, []string{"-n", "1", "-w", "4000", "192.0.2.1"}, []string{"-n", "1", "-w", "4000", "-l", "9", "192.0.2.1"}},
	} {
		got, err := sweepArgv(c.in, 9, c.win)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v %v", got, err)
		}
	}
	if _, err := sweepArgv([]string{"-n", "-x"}, 9, false); err == nil { // vuelve a pasar por checkFlagLike
		t.Error("un valor con forma de bandera debe rechazarse")
	}
}
