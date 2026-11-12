package calc

import (
	"math"
	"strings"
	"testing"
)

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol*math.Max(1, math.Abs(b)) }

func TestTCP(t *testing.T) {
	// 1 Gb/s a 50 ms: BDP 6.25 MB, escala 7 (65535<<7 = 8 388 480).
	r, err := TCP("1g", 50, "64k", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.BDPBytes != 6_250_000 || r.WindowScale != 7 || r.MSS != 1460 || !near(r.WindowLimitBps, 65536*8/0.05, 1e-9) || r.Limit != "ventana" || !near(r.MaxBps, r.WindowLimitBps, 1e-9) {
		t.Fatalf("%+v", r)
	}
	// Mathis: (1460·8/0,05)·√1,5/√0,0001 ≈ 28,61 Mb/s.
	r, err = TCP("10G", 50, "", 0.01, 1460)
	if err != nil || !near(r.MathisBps, 28_610_040, 1e-4) || r.Limit != "pérdida" || r.WindowLimitBps != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "-P") {
		t.Fatalf("falta la explicación de iperf3: %v", r.Notes)
	}
	r, err = TCP("100m", 1, "4m", 0, 0)
	if err != nil || r.Limit != "enlace" || r.MaxBps != 100e6 || r.WindowScale != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	// BDP enorme: la escala se topa en 14.
	if r, _ = TCP("400g", 300, "", 0, 0); r.WindowScale != 14 {
		t.Fatalf("escala %d", r.WindowScale)
	}
	for _, c := range [][2]string{{"", "50"}, {"1x", "50"}, {"1g", "0"}, {"-1g", "5"}} {
		rtt := map[string]float64{"50": 50, "0": 0, "5": 5}[c[1]]
		if _, err := TCP(c[0], rtt, "", 0, 0); err == nil {
			t.Errorf("%v aceptado", c)
		}
	}
	if _, err := TCP("1g", 10, "", 100, 0); err == nil {
		t.Error("100 % de pérdida aceptado")
	}
	if _, err := TCP("1g", 10, "zz", 0, 0); err == nil {
		t.Error("ventana inválida aceptada")
	}
}

func TestDSCP(t *testing.T) {
	r, err := DSCP("ef", "")
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if e := r.Entries[0]; e.DSCP != 46 || e.Binary != "101110" || e.ToS != 184 || e.ToSHex != "0xB8" || e.Precedence != 5 || e.CoS != 5 || e.EXP != 5 || e.Class != "telefonía (voz)" {
		t.Fatalf("%+v", e)
	}
	if r, _ = DSCP("AF41", ""); r.Entries[0].DSCP != 34 || r.Entries[0].ToS != 136 || r.Entries[0].Drop != "baja" {
		t.Fatalf("%+v", r.Entries)
	}
	if r, _ = DSCP("0xb8", "tos"); r.Entries[0].Name != "EF" {
		t.Fatalf("%+v", r.Entries)
	}
	if r, _ = DSCP("101110", "binary"); r.Entries[0].Name != "EF" {
		t.Fatalf("%+v", r.Entries)
	}
	if r, _ = DSCP("3", "cos"); len(r.Entries) != 4 || r.Entries[0].Name != "CS3" {
		t.Fatalf("%+v", r.Entries)
	}
	if r, _ = DSCP("default", ""); r.Entries[0].DSCP != 0 {
		t.Fatalf("%+v", r.Entries)
	}
	if r, _ = DSCP("", ""); len(r.Entries) != 23 {
		t.Fatalf("tabla completa: %d", len(r.Entries))
	}
	// Un valor sin nombre se calcula igual.
	if r, _ = DSCP("5", ""); len(r.Entries) != 1 || r.Entries[0].Name != "" || r.Entries[0].ToS != 20 || r.Entries[0].Binary != "000101" {
		t.Fatalf("%+v", r.Entries)
	}
	for _, q := range [][2]string{{"64", ""}, {"xx", ""}, {"8", "cos"}, {"1", "frob"}, {"1012", "binary"}} {
		if _, err := DSCP(q[0], q[1]); err == nil {
			t.Errorf("%v aceptado", q)
		}
	}
}

func TestOptics(t *testing.T) {
	in := OpticsInput{TxDbm: -8.2, RxSensDbm: -14.4, Km: 10, Fiber: "smf-1310", Connectors: 2, ConnectorLoss: 0.5, Splices: 2, SpliceLoss: 0.1, MarginDb: 3}
	r, err := Optics(in)
	if err != nil {
		t.Fatal(err)
	}
	if !near(r.BudgetDb, 6.2, 1e-9) || !near(r.TotalLossDb, 4.7, 1e-9) || !near(r.RemainingDb, -1.5, 1e-9) || r.Closes {
		t.Fatalf("%+v", r)
	}
	in.Km = 5
	if r, _ = Optics(in); !r.Closes || !near(r.RemainingDb, 0.25, 1e-9) || !near(r.ExpectedRxDbm, -11.15, 1e-9) {
		t.Fatalf("%+v", r)
	}
	// Óptica ER en un enlace corto: satura el receptor.
	ov := -1.0
	r, err = Optics(OpticsInput{TxDbm: 4, RxSensDbm: -15, RxOverloadDbm: &ov, Km: 2, Fiber: "smf-1310", Connectors: 2, ConnectorLoss: 0.5, MarginDb: 3})
	if err != nil || !r.Overload || !near(r.AttenuatorDb, 3.3, 1e-9) {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = Optics(OpticsInput{TxDbm: -2, RxSensDbm: -10, Km: 0.3, LossPerKm: 3.5, MarginDb: 0})
	if err != nil || !near(r.FiberLossDb, 1.05, 1e-9) {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []OpticsInput{{TxDbm: 0, RxSensDbm: -10, Km: 1}, {TxDbm: 0, RxSensDbm: -10, Km: -1, Fiber: "mmf-850"}, {TxDbm: 0, RxSensDbm: -10, Km: 1, Fiber: "frob"}} {
		if _, err := Optics(bad); err == nil {
			t.Errorf("%+v aceptado", bad)
		}
	}
}

func TestPower(t *testing.T) {
	for in, want := range map[string][2]float64{"-3dBm": {-3, 0.501187}, "0 dbm": {0, 1}, "0.5mW": {-3.0103, 0.5}, "1mw": {0, 1}, "10 mW": {10, 10}} {
		p, err := Power(in)
		if err != nil || !near(p.Dbm, want[0], 1e-4) || !near(p.Mw, want[1], 1e-4) {
			t.Errorf("%s: %+v %v", in, p, err)
		}
	}
	for _, bad := range []string{"", "3", "0mW", "-1mW", "xdBm"} {
		if _, err := Power(bad); err == nil {
			t.Errorf("%q aceptado", bad)
		}
	}
}
