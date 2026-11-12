package calc

import "testing"

// Recorre el Report() de cada calculadora: kv hace panic si una etiqueta no es string ni lbl, y toda tabla debe
// traer sus claves completas.
func TestTodosLosReportsArman(t *testing.T) {
	lp := uint32(200)
	ov := -1.0
	var reps []Report
	add := func(r Reporter, err error) {
		if err != nil {
			t.Fatal(err)
		}
		reps = append(reps, r.Report())
	}
	for _, p := range []string{"10.0.0.5/24", "10.0.0.1/32", "10.0.0.1/31", "2001:db8::5/64", "2001:db8::/127"} {
		add(Subnet(p))
	}
	add(VLSM("10.0.0.0/24", []Need{{Name: "a", Hosts: 100}, {Name: "b", Hosts: 500}}))
	add(Summarize([]string{"10.0.0.0/24", "10.0.2.0/24"}))
	add(Wildcard("", "/24"))
	add(Wildcard("10.1.2.3", "0.0.255.254"))
	add(IPv6("fe80::/64", "00:50:56:ab:cd:ef"))
	add(MTU(1500, []string{"gre", "esp-tunnel:aes-cbc:sha256"}, false))
	add(TCP("1g", 50, "64k", 1, 0))
	add(DSCP("ef", ""))
	add(DSCP("", ""))
	add(Optics(OpticsInput{TxDbm: 4, RxSensDbm: -15, RxOverloadDbm: &ov, Km: 2, Fiber: "smf-1310", Connectors: 2, ConnectorLoss: 0.5, MarginDb: 3}))
	add(Power("-3dBm"))
	add(BGPBestPath([]Route{{Name: "A", ASPath: "65001", EBGP: true, RouterID: "1.1.1.1"}, {Name: "B", ASPath: "65001", LocalPref: &lp, RouterID: "1.1.1.2"}}, BGPOptions{MaximumPaths: 2}))
	for i, r := range reps {
		if len(r.Notes) != len(r.NoteItems) && len(r.NoteItems) != 0 {
			t.Errorf("reporte %d: %d notas y %d claves", i, len(r.Notes), len(r.NoteItems))
		}
		for _, tb := range r.Tables {
			if tb.TitleKey == "" || len(tb.HeadKeys) != len(tb.Head) || len(tb.RowKeys) != len(tb.Rows) {
				t.Errorf("reporte %d: tabla %q incompleta", i, tb.Title)
			}
		}
	}
}
