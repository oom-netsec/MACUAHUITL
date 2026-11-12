package noegress

import "testing"

func TestIsForbidden(t *testing.T) {
	cases := map[string]bool{
		"net": true, "net/http": true, "net/textproto": true, "net/rpc/jsonrpc": true,
		"net/http/httptest": true, "crypto/tls": true, "log/syslog": true, "syscall": true,
		"os/exec": true, "C": true, "golang.org/x/sys/unix": true, "golang.org/x/net/icmp": true,
		"golang.org/x/crypto/ssh": true, "google.golang.org/grpc": true,
		"net/netip": false, "net/url": false, "net/mail": false, "fmt": false,
		"google.golang.org/grpc/status": false, "golang.org/x/crypto/argon2": false,
		"golang.org/x/netx": false,
	}
	for path, want := range cases {
		if got := isForbidden(path); got != want {
			t.Errorf("isForbidden(%q) = %v, want %v", path, got, want)
		}
	}
}
