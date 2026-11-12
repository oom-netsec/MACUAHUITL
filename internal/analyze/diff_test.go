package analyze

import (
	"fmt"
	"strings"
	"testing"
)

func devDiff(t *testing.T, r DiffReport, dev string) DeviceDiff {
	t.Helper()
	for _, d := range r.Devices {
		if strings.HasPrefix(d.Device, dev) {
			return d
		}
	}
	t.Fatalf("no diff for %s in %+v", dev, r.Devices)
	return DeviceDiff{}
}

func TestDiffCountersAndText(t *testing.T) {
	r, err := Diff(load(t), 1, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	sw := devDiff(t, r, "SW1")
	got := map[string]int64{}
	for _, c := range sw.Counters {
		got[c.Interface+" "+c.Counter] = c.Delta
	}
	want := map[string]int64{"GigabitEthernet1/0/1 crc": 1500, "GigabitEthernet1/0/1 input_errors": 1500, "GigabitEthernet1/0/7 output_drops": 4000}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("counters = %v", got)
	}
	if sw.Uptime == nil || sw.Uptime.Reset {
		t.Fatalf("uptime = %+v", sw.Uptime)
	}
	var ver *TextDiff
	for i := range sw.Text {
		if sw.Text[i].Command == "show version" {
			ver = &sw.Text[i]
		}
	}
	if ver == nil || !contains(ver.Lines, "- SW1 uptime is 2 weeks, 3 days, 4 hours, 12 minutes") || !contains(ver.Lines, "+ SW1 uptime is 2 weeks, 3 days, 4 hours, 22 minutes") {
		t.Fatalf("show version diff = %+v", ver)
	}
	for _, td := range sw.Text {
		if td.Command == "dir crashinfo:" {
			t.Fatal("unchanged output listed in the text diff")
		}
	}
}

func TestDiffUptimeReset(t *testing.T) {
	r, _ := Diff(load(t), 2, 3, "SW1")
	if len(r.Devices) != 1 {
		t.Fatalf("device filter: %d devices", len(r.Devices))
	}
	if u := devDiff(t, r, "SW1").Uptime; u == nil || !u.Reset {
		t.Fatalf("uptime = %+v", u)
	}
	// Contadores que bajan (recarga o clear) no se reportan como crecimiento.
	for _, c := range devDiff(t, r, "SW1").Counters {
		if c.Delta > 0 {
			t.Errorf("growth after reload: %+v", c)
		}
	}
}

func TestDiffNeighborsAndPrefixes(t *testing.T) {
	r, _ := Diff(load(t), 1, 3, "RTR2")
	d := devDiff(t, r, "RTR2")
	var ch []string
	for _, n := range d.Neighbors {
		ch = append(ch, fmt.Sprintf("%s %s %s %s→%s", n.Protocol, n.ID, n.Change, n.From, n.To))
	}
	for _, w := range []string{"ospf 10.255.0.4 por GigabitEthernet0/0/2 desapareció FULL→", "hsrp Vl30 grupo 30 apareció →Init"} {
		if !contains(ch, w) {
			t.Errorf("missing %q in %q", w, ch)
		}
	}
	if fmt.Sprint(d.Prefixes) != "[{10.0.12.1 10 12}]" {
		t.Errorf("prefixes = %+v", d.Prefixes)
	}
	r, _ = Diff(load(t), 1, 2, "RTR2")
	d = devDiff(t, r, "RTR2")
	ch = nil
	for _, n := range d.Neighbors {
		ch = append(ch, fmt.Sprintf("%s %s %s %s→%s", n.Protocol, n.ID, n.Change, n.From, n.To))
	}
	for _, w := range []string{"bgp 10.0.13.1 cambió Established→Idle", "ospf 10.255.0.3 por GigabitEthernet0/0/1 cambió FULL→EXSTART", "hsrp Vl10 grupo 10 cambió Active→Standby"} {
		if !contains(ch, w) {
			t.Errorf("missing %q in %q", w, ch)
		}
	}
}

func TestDiffRejectsMissingRound(t *testing.T) {
	if _, err := Diff(load(t), 1, 9, ""); err == nil {
		t.Fatal("round 9 accepted")
	}
}

func TestLineDiff(t *testing.T) {
	got, _ := lineDiff([]string{"a", "b", "c", "d"}, []string{"a", "x", "c", "d", "e"})
	if strings.Join(got, "|") != "- b|+ x|+ e" {
		t.Fatalf("diff = %q", got)
	}
	big := make([]string, 5000)
	other := make([]string, 5000)
	for i := range big {
		big[i], other[i] = fmt.Sprint(i), fmt.Sprint(-i-1)
	}
	if _, note := lineDiff(big, other); note == "" {
		t.Fatal("huge diff not capped")
	}
}

func TestDiffSameUptimeIsNotReset(t *testing.T) {
	v := "R uptime is 3 hours, 2 minutes\n"
	r, _ := Diff(bundleOf("show version", v, v), 1, 2, "")
	if u := r.Devices[0].Uptime; u == nil || u.Reset {
		t.Fatalf("uptime = %+v", u)
	}
}

func TestDiffOSPFSameRouterIDTwoLinks(t *testing.T) {
	r, _ := Diff(ospfTwoLinks(), 1, 2, "")
	n := r.Devices[0].Neighbors
	if len(n) != 1 || n[0].Change != "desapareció" || !strings.Contains(n[0].ID, "GigabitEthernet0/0/2") {
		t.Fatalf("neighbors = %+v", n)
	}
}
