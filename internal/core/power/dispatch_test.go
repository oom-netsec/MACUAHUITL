package power

import "testing"

func TestDispatch(t *testing.T) {
	cases := []struct {
		name         string
		msg          uint32
		wp           uintptr
		sleeps, lock int
	}{
		{"suspensión", wmPowerBroadcast, pbtAPMSuspend, 1, 0},
		{"bloqueo", wmWTSSessionChg, wtsSessionLock, 0, 1},
		{"reanudar no es suspender", wmPowerBroadcast, 0x0007, 0, 0},
		{"desbloqueo no es bloqueo", wmWTSSessionChg, 0x8, 0, 0},
		{"wparam de suspensión en otro mensaje", wmWTSSessionChg, pbtAPMSuspend, 0, 0},
		{"wparam de bloqueo en otro mensaje", wmPowerBroadcast, wtsSessionLock, 0, 0},
		{"mensaje ajeno", 0x0001, pbtAPMSuspend, 0, 0},
	}
	for _, c := range cases {
		var s, l int
		dispatch(c.msg, c.wp, func() { s++ }, func() { l++ })
		if s != c.sleeps || l != c.lock {
			t.Errorf("%s: sleep=%d lock=%d, quería %d/%d", c.name, s, l, c.sleeps, c.lock)
		}
	}
}
