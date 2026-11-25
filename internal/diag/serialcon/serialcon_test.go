package serialcon

import "testing"

// AuditString va junto a String: mismo formato de línea pero con la clave en inglés para la bitácora.
func TestConfigAuditString(t *testing.T) {
	c := Config{Baud: 9600, DataBits: 8, Parity: "n", StopBits: 1, Flow: "none"}
	if got, want := c.AuditString(), "9600 8N1 flow=none"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
