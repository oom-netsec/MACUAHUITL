package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestIngestFlagsParseAndRangeCheck(t *testing.T) {
	var f IngestFlags
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	f.Register(fs, "traps_{fecha}_{hora}")
	if err := fs.Parse([]string{"--rate", "5", "--burst", "6", "--rate-global", "7", "--burst-global", "8", "--queue", "64", "--rotate-mb", "3", "--rotate-min", "2", "--max-files", "4", "--name", "t_{fecha}", "--format", "jsonl"}); err != nil {
		t.Fatal(err)
	}
	v, err := f.Values()
	if err != nil {
		t.Fatal(err)
	}
	if v != (IngestValues{Rate: 5, Burst: 6, RateG: 7, BurstG: 8, Queue: 64, RotMB: 3, RotMin: 2, MaxFiles: 4}) || f.Name != "t_{fecha}" || f.Format != "jsonl" {
		t.Fatalf("%+v %+v", v, f)
	}
	for flagName, set := range map[string]func(*IngestFlags){
		"rate": func(f *IngestFlags) { f.Rate = 1 << 31 }, "burst": func(f *IngestFlags) { f.Burst = -1 << 32 }, "rate-global": func(f *IngestFlags) { f.RateG = 1 << 40 },
		"burst-global": func(f *IngestFlags) { f.BurstG = 1 << 31 }, "queue": func(f *IngestFlags) { f.Queue = 1 << 31 }, "rotate-mb": func(f *IngestFlags) { f.RotMB = 1 << 31 },
		"rotate-min": func(f *IngestFlags) { f.RotMin = 1 << 31 }, "max-files": func(f *IngestFlags) { f.MaxFiles = 1 << 31 },
	} {
		var g IngestFlags
		set(&g)
		if _, err := g.Values(); err == nil || !strings.HasPrefix(err.Error(), "--"+flagName+" fuera de rango") {
			t.Errorf("%s: err = %v", flagName, err)
		}
	}
	if _, err := Int32("for", 1<<31-1); err != nil {
		t.Fatal(err)
	}
}

func TestPrintDrops(t *testing.T) {
	var b bytes.Buffer
	PrintDrops(&b, &v1.SyslogDrops{Total: 9, PorOrigen: 5, Global: 3, ColaLlena: 1, Top: []*v1.SyslogSourceDrops{{Source: "10.0.0.1", Count: 7}, {Source: "otros", Count: 2}}})
	if got := b.String(); got != "descartes: 9 (por origen 5, global 3, cola llena 1) 10.0.0.1=7 otros=2\n" {
		t.Fatalf("%q", got)
	}
}
