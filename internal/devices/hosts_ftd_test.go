package devices

import (
	"slices"
	"testing"
)

// ftd es una plataforma de host (el firewall de Cisco que Patrol ya detecta).
func TestHostPlatformsIncluyeFTD(t *testing.T) {
	if !slices.Contains(HostPlatforms, "ftd") {
		t.Fatalf("HostPlatforms = %v", HostPlatforms)
	}
	if _, err := Clean(Host{Name: "fw", Address: "192.0.2.1", Platform: "ftd"}); err != nil {
		t.Fatal(err)
	}
}
