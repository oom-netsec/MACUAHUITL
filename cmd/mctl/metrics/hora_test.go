package metrics

import (
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestPortsStatusSinFechaCero(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("CST", -6*3600)
	defer func() { time.Local = old }()
	r := &v1.GetPortStatusResponse{Hostname: "sw1", Address: "192.0.2.1", Source: "dir"}
	if got := portsHead(r); strings.Contains(got, "1970") || strings.Contains(got, "·  ·") || got != "sw1 (192.0.2.1) · dir" {
		t.Errorf("sin hora: %q", got)
	}
	r.AtMs = time.Date(2026, 11, 18, 4, 13, 0, 0, time.UTC).UnixMilli()
	if got := portsHead(r); got != "sw1 (192.0.2.1) · dir · 2026-11-17 22:13 CST" {
		t.Errorf("con hora: %q", got)
	}
}
