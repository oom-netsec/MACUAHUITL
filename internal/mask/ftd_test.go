package mask

import "testing"

// El lina de FTD usa las reglas de ASA (también con plataforma "ftd"): trozo de show running-config, sin validar en laboratorio.
func TestFTDRunningConfigTapaPSK(t *testing.T) {
	in := "tunnel-group 203.0.113.5 ipsec-attributes\n ikev2 remote-authentication pre-shared-key ClaveFTD\n ikev1 pre-shared-key OtraFTD\n"
	want := "tunnel-group 203.0.113.5 ipsec-attributes\n ikev2 remote-authentication pre-shared-key <MASKED:psk>\n ikev1 pre-shared-key <MASKED:psk>\n"
	got, _ := Apply("ftd", in)
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
	if again, n := Apply("ftd", got); again != got || len(n) != 0 {
		t.Fatalf("no idempotente: %q %v", again, n)
	}
}
