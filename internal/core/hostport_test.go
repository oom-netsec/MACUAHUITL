package core

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// Excluir al armar usa el mismo formato que muestra el Login Test, también con IPv6.
func TestPatrolHostportEsElDelLoginTest(t *testing.T) {
	for want, tg := range map[string]patrol.Target{
		"192.0.2.1:22":       {Address: "192.0.2.1"},
		"[2001:db8::1]:22":   {Address: "2001:db8::1"},
		"[2001:db8::1]:2222": {Address: "2001:db8::1", Port: 2222},
		"sw.example.net:22":  {Address: "sw.example.net"},
	} {
		if got := patrolHostport(tg); got != want {
			t.Errorf("patrolHostport(%+v) = %q, quiero %q", tg, got, want)
		}
	}
}
