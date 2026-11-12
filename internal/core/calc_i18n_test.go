package core

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// calcCases cubre todas las calculadoras y cada una de sus notas.
func calcCases(t *testing.T) map[string]func(c v1.CalcServiceClient, ctx func() ctxT) (*v1.CalcResult, error) {
	t.Helper()
	ov, ov2 := -1.0, 0.0
	lp := uint32(200)
	routes := []*v1.BgpRoute{
		{Name: "A", AsPath: "65001", Ebgp: true, RouterId: "10.0.0.1", Neighbor: "1.1.1.1"},
		{Name: "B", AsPath: "65001", LocalPref: &lp, RouterId: "10.0.0.2", Neighbor: "1.1.1.2"},
		{Name: "C", LocallyOriginated: true, RouterId: "10.0.0.3", NextHopUnreachable: true, OriginatorId: "9.9.9.9"},
	}
	type fn = func(c v1.CalcServiceClient, ctx func() ctxT) (*v1.CalcResult, error)
	sub := func(p string) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Subnet(cx(), &v1.SubnetRequest{Prefix: p})
			return r.GetResult(), err
		}
	}
	wc := func(a, v string) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Wildcard(cx(), &v1.WildcardRequest{Address: a, Value: v})
			return r.GetResult(), err
		}
	}
	v6 := func(a, m string) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Ipv6(cx(), &v1.Ipv6Request{Address: a, Mac: m})
			return r.GetResult(), err
		}
	}
	mtu := func(phys uint32, v6 bool, l ...string) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Mtu(cx(), &v1.MtuRequest{Physical: phys, Layers: l, InnerIpv6: v6})
			return r.GetResult(), err
		}
	}
	tcp := func(q *v1.TcpRequest) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Tcp(cx(), q)
			return r.GetResult(), err
		}
	}
	dscp := func(q string) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Dscp(cx(), &v1.DscpRequest{Query: q})
			return r.GetResult(), err
		}
	}
	opt := func(q *v1.OpticsRequest) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Optics(cx(), q)
			return r.GetResult(), err
		}
	}
	bgp := func(q *v1.BgpRequest) fn {
		return func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Bgp(cx(), q)
			return r.GetResult(), err
		}
	}
	return map[string]fn{
		"subnet-host":   sub("10.0.0.5/24"),
		"subnet-32":     sub("10.0.0.1/32"),
		"subnet-31":     sub("10.0.0.1/31"),
		"subnet-v6":     sub("2001:db8::5/64"),
		"subnet-v6-127": sub("2001:db8::/127"),
		"vlsm": func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Vlsm(cx(), &v1.VlsmRequest{Network: "10.0.0.0/24", Needs: []*v1.VlsmNeed{{Name: "lan", Hosts: 100}, {Name: "voz", Hosts: 20}, {Name: "grande", Hosts: 500}}})
			return r.GetResult(), err
		},
		"summarize": func(c v1.CalcServiceClient, cx func() ctxT) (*v1.CalcResult, error) {
			r, err := c.Summarize(cx(), &v1.SummarizeRequest{Prefixes: []string{"10.0.0.0/24", "10.0.2.0/24"}})
			return r.GetResult(), err
		},
		"wildcard-conv":      wc("", "/24"),
		"wildcard-acl":       wc("10.1.2.3", "0.0.0.255"),
		"wildcard-noncontig": wc("10.1.2.3", "0.0.255.254"),
		"wildcard-many":      wc("10.0.0.0", "0.255.255.255"),
		"ipv6-mac":           v6("fe80::/64", "00:50:56:ab:cd:ef"),
		"ipv6-eui":           v6("fe80::250:56ff:feab:cdef", ""),
		"mtu-gre":            mtu(1500, false, "gre"),
		"mtu-esp":            mtu(1500, false, "esp-tunnel:aes-cbc:sha256"),
		"mtu-vxlan-dot1q":    mtu(1500, false, "vxlan", "dot1q"),
		"mtu-v6-small":       mtu(1400, true, "gre", "nat-t", "esp-tunnel:aes-cbc:sha256"),
		"mtu-v6-tiny":        mtu(1300, true, "gre"),
		"mtu-dot1q-out":      mtu(1500, false, "dot1q"),
		"tcp-none":           tcp(&v1.TcpRequest{Bandwidth: "1g", RttMs: 50}),
		"tcp-window":         tcp(&v1.TcpRequest{Bandwidth: "1g", RttMs: 50, Window: "64k"}),
		"tcp-loss":           tcp(&v1.TcpRequest{Bandwidth: "1g", RttMs: 50, LossPercent: 1}),
		"dscp-ef":            dscp("ef"),
		"dscp-all":           dscp(""),
		"optics-overload":    opt(&v1.OpticsRequest{TxDbm: 4, RxSensitivityDbm: -15, RxOverloadDbm: &ov, Km: 2, Fiber: "smf-1310", Connectors: 2, ConnectorLossDb: 0.5, MarginDb: 3}),
		"optics-short":       opt(&v1.OpticsRequest{TxDbm: 0, RxSensitivityDbm: -10, RxOverloadDbm: &ov2, Km: 40, Fiber: "smf-1310", Connectors: 2, ConnectorLossDb: 0.5, Splices: 2, SpliceLossDb: 0.1, MarginDb: 3}),
		"power":              opt(&v1.OpticsRequest{Convert: "-3dBm"}),
		"bgp-basic":          bgp(&v1.BgpRequest{Routes: routes}),
		"bgp-det":            bgp(&v1.BgpRequest{Routes: routes, DeterministicMed: true, AlwaysCompareMed: true, MaximumPaths: 2}),
		"bgp-relax":          bgp(&v1.BgpRequest{Routes: routes[:2], MultipathRelax: true, MaximumPaths: 4}),
	}
}

type ctxT = context.Context

// calcView es la parte de la respuesta que la regresión fija byte por byte.
type calcView struct {
	Json   string
	Text   string
	Tables [][][]string // por tabla: título, encabezado y luego las filas
	Notes  []string
}

func viewOf(r *v1.CalcResult) calcView {
	v := calcView{Json: r.Json, Text: r.Text, Notes: r.Notes}
	for _, tb := range r.Tables {
		rows := [][]string{{tb.Title}, tb.Head}
		for _, row := range tb.Rows {
			rows = append(rows, row.Cells)
		}
		v.Tables = append(v.Tables, rows)
	}
	return v
}

// Regresión: sin accept-language, o con es, la respuesta de cada calculadora es la de antes de la fase.
func TestCalcRegresionEs(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewCalcServiceClient(h.conn)
	cases := calcCases(t)
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	slices.Sort(names)
	got := map[string]calcView{}
	for _, lang := range []string{"", "es", "es-MX", "fr"} {
		for _, n := range names {
			r, err := cases[n](c, func() ctxT { return con(t, lang) })
			if err != nil {
				t.Fatalf("%s: %v", n, err)
			}
			if lang == "" {
				got[n] = viewOf(r)
				continue
			}
			a, _ := json.Marshal(viewOf(r))
			b, _ := json.Marshal(got[n])
			if string(a) != string(b) {
				t.Errorf("%s con %q difiere de sin idioma", n, lang)
			}
		}
	}
	const file = "testdata/calc_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]calcView
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		a, _ := json.Marshal(got[n])
		b, _ := json.Marshal(want[n])
		if string(a) != string(b) {
			t.Errorf("%s: el texto en español cambió\n got: %s\nwant: %s", n, a, b)
		}
	}
}

// Lo estructurado dice lo mismo que el texto: cada título, columna, etiqueta y nota trae su clave, y el
// español del catálogo para esa clave es la celda que ve el ingeniero.
func TestCalcEstructuradoCoincideConElTexto(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewCalcServiceClient(h.conn)
	for n, f := range calcCases(t) {
		r, err := f(c, func() ctxT { return con(t, "") })
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if len(r.NotesStructured) != len(r.Notes) {
			t.Fatalf("%s: %d notas y %d estructuradas", n, len(r.Notes), len(r.NotesStructured))
		}
		for i, ns := range r.NotesStructured {
			if got := i18n.Msg(i18n.Es, ns.Key, ns.Args); got != r.Notes[i] || !strings.HasPrefix(ns.Key, "calc.note.") {
				t.Errorf("%s: nota %d: %q (%s) no es %q", n, i, got, ns.Key, r.Notes[i])
			}
		}
		for _, tb := range r.Tables {
			if got := i18n.Msg(i18n.Es, tb.TitleKey, tb.TitleArgs); tb.TitleKey == "" || got != tb.Title {
				t.Errorf("%s: título %q vs %q (%s)", n, tb.Title, got, tb.TitleKey)
			}
			if len(tb.Columns) != len(tb.Head) {
				t.Fatalf("%s: %d columnas y %d encabezados", n, len(tb.Columns), len(tb.Head))
			}
			for i, col := range tb.Columns {
				if !strings.HasPrefix(col.Key, "calc.col.") || i18n.Msg(i18n.Es, col.Key, nil) != tb.Head[i] {
					t.Errorf("%s: columna %d %q no es %q", n, i, col.Key, tb.Head[i])
				}
			}
			for _, row := range tb.Rows {
				if row.LabelKey != "" && (!strings.HasPrefix(row.LabelKey, "calc.row.") || i18n.Msg(i18n.Es, row.LabelKey, row.LabelArgs) != row.Cells[0]) {
					t.Errorf("%s: fila %q con clave %s", n, row.Cells[0], row.LabelKey)
				}
			}
		}
	}
}

// valueOf busca el valor de una fila campo/valor por la clave de su etiqueta.
func valueOf(r *v1.CalcResult, key string) string {
	for _, tb := range r.Tables {
		for _, row := range tb.Rows {
			if row.LabelKey == key {
				return row.Cells[len(row.Cells)-1]
			}
		}
	}
	return "<sin fila " + key + ">"
}

// Los valores de las filas por clave son los del JSON del resultado (lo que hoy el front saca del texto).
func TestCalcEstructuradoValores(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewCalcServiceClient(h.conn)
	cs := calcCases(t)
	r, _ := cs["subnet-host"](c, func() ctxT { return con(t, "") })
	var s struct{ Network, Broadcast, FirstUsable, LastUsable, Total, Usable string }
	if err := json.Unmarshal([]byte(r.Json), &s); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"calc.row.network": s.Network, "calc.row.broadcast": s.Broadcast, "calc.row.first_usable": s.FirstUsable,
		"calc.row.last_usable": s.LastUsable, "calc.row.addresses": s.Total, "calc.row.usable_hosts": s.Usable} {
		if got := valueOf(r, key); got != want || want == "" {
			t.Errorf("%s: %q, el json dice %q", key, got, want)
		}
	}
	if r.Tables[0].TitleKey != "calc.title.subnet" || r.Tables[0].TitleArgs["prefix"] != "10.0.0.0/24" {
		t.Errorf("título: %+v", r.Tables[0])
	}
	r, _ = cs["vlsm"](c, func() ctxT { return con(t, "") })
	tb := r.Tables[0]
	if tb.TitleKey != "calc.title.vlsm" || tb.TitleArgs["parent"] != "10.0.0.0/24" || tb.Columns[0].Key != "calc.col.name" || tb.Columns[2].Key != "calc.col.prefix" {
		t.Errorf("vlsm: %+v", tb)
	}
	var free, unplaced string
	for _, n := range r.NotesStructured {
		switch n.Key {
		case "calc.note.vlsm_free":
			free = n.Args["free"]
		case "calc.note.vlsm_unplaced":
			unplaced = n.Args["names"]
		}
	}
	var v struct {
		Free     []string
		Unplaced []string
	}
	json.Unmarshal([]byte(r.Json), &v)
	if free != strings.Join(v.Free, " ") || free == "" || unplaced != strings.Join(v.Unplaced, ", ") || unplaced == "" {
		t.Errorf("libre %q (json %v), no caben %q", free, v.Free, unplaced)
	}
}

// Con en, títulos, encabezados, etiquetas y notas salen en inglés y los valores no cambian.
func TestCalcEnTraduce(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewCalcServiceClient(h.conn)
	for n, f := range calcCases(t) {
		es, _ := f(c, func() ctxT { return con(t, "") })
		en, err := f(c, func() ctxT { return con(t, "en-US") })
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if en.Json != es.Json || en.Text == es.Text {
			t.Errorf("%s: el json debe ser igual y el texto distinto", n)
		}
		for ti, tb := range en.Tables {
			if tb.Title != i18n.Msg(i18n.En, tb.TitleKey, tb.TitleArgs) || tb.TitleKey != es.Tables[ti].TitleKey {
				t.Errorf("%s: título %q", n, tb.Title)
			}
			for ri, row := range tb.Rows {
				if row.LabelKey != "" && row.Cells[0] != i18n.Msg(i18n.En, row.LabelKey, row.LabelArgs) {
					t.Errorf("%s: etiqueta %q", n, row.Cells[0])
				}
				if len(row.Cells) > 1 && row.Cells[len(row.Cells)-1] != es.Tables[ti].Rows[ri].Cells[len(row.Cells)-1] {
					t.Errorf("%s: el valor cambió: %q", n, row.Cells)
				}
			}
		}
		for i, ns := range en.NotesStructured {
			if en.Notes[i] != i18n.Msg(i18n.En, ns.Key, ns.Args) || en.Notes[i] == es.Notes[i] && !strings.HasPrefix(ns.Key, "calc.note.bgp_unvalidated") {
				t.Errorf("%s: nota %d sin traducir: %q", n, i, en.Notes[i])
			}
			if !strings.Contains(en.Text, en.Notes[i]) {
				t.Errorf("%s: el texto no trae la nota en inglés", n)
			}
		}
	}
	r, _ := calcCases(t)["subnet-host"](c, func() ctxT { return con(t, "en") })
	if !strings.Contains(r.Text, "Subnet 10.0.0.0/24") || !strings.Contains(r.Text, "First usable") || !strings.Contains(r.Text, "10.0.0.5 is a host inside 10.0.0.0/24") {
		t.Errorf("%s", r.Text)
	}
}
