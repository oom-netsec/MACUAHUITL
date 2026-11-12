package archcheck

import "testing"

func TestImportKinds(t *testing.T) {
	for path, want := range map[string]bool{"net": true, "net/http": true, "golang.org/x/net/icmp": true, "net/netip": false, "net/url": false, "fmt": false, "golang.org/x/netx": false} {
		if got := isNetwork(path); got != want {
			t.Errorf("isNetwork(%q) = %v, want %v", path, got, want)
		}
	}
	for path, want := range map[string]bool{"google.golang.org/grpc": true, "google.golang.org/grpc/credentials": true, "google.golang.org/grpc/status": false, "google.golang.org/grpc/codes": false, "google.golang.org/protobuf/proto": false} {
		if got := isGRPC(path); got != want {
			t.Errorf("isGRPC(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDomainOf(t *testing.T) {
	for rel, want := range map[string]string{"internal/diag": "internal/diag", "internal/diag/dnsq": "internal/diag", "internal/diagx": "", "internal/vault": "", "internal/core": "", "internal/iosconf": "internal/iosconf", "internal/pcapan": "internal/pcapan", "internal/audit": ""} {
		if got := domainOf(rel); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", rel, got, want)
		}
	}
}
