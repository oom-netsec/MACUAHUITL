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
		// Fase 30c-A: valores con palabras (Tipo de dirección, clases DSCP, pasos BGP, capas MTU, veredicto).
		"subnet-any":      sub("0.0.0.0/0"),
		"subnet-public":   sub("8.8.8.0/24"),
		"subnet-private":  sub("10.0.0.0/8"),
		"subnet-mixed":    sub("192.0.0.0/8"),
		"subnet-mcast":    sub("224.0.0.5/32"),
		"subnet-this":     sub("0.0.0.0/8"),
		"subnet-v6-mcast": sub("ff05::1/128"),
		"subnet-v6-mc-x":  sub("ff07::1/128"),
		"subnet-v6-un":    sub("4000::/16"),
		"subnet-v6-ula":   sub("fc00::1/64"),
		"ipv6-global":     v6("2001:4860::1", ""),
		"ipv6-loop":       v6("::1", ""),
		"dscp-af11":       dscp("af11"),
		"dscp-45":         dscp("45"),
		"dscp-cs3":        dscp("cs3"),
		"mtu-getvpn":      mtu(1500, false, "getvpn:aes-cbc:sha1:tbar"),
		"mtu-transport":   mtu(1500, false, "gre-key", "esp-transport:aes-gcm"),
		"mtu-tr-alone":    mtu(1500, false, "esp-transport:aes-cbc:sha256"),
		"mtu-mpls-qinq":   mtu(1500, false, "mpls:3", "vxlan", "qinq", "pppoe", "lisp"),
		"optics-ok":       opt(&v1.OpticsRequest{TxDbm: 4, RxSensitivityDbm: -15, Km: 2, Fiber: "smf-1310", Connectors: 2, ConnectorLossDb: 0.5, MarginDb: 3}),
		"bgp-steps": bgp(&v1.BgpRequest{Routes: []*v1.BgpRoute{
			{Name: "w", Weight: 10, AsPath: "1 2", RouterId: "1.0.0.1", Neighbor: "9.0.0.1"},
			{Name: "o", AsPath: "1 2", Origin: "e", RouterId: "1.0.0.2", Neighbor: "9.0.0.2"},
			{Name: "m", AsPath: "1 2", Med: &lp, RouterId: "1.0.0.3", Neighbor: "9.0.0.3"},
			{Name: "e", AsPath: "1 2", Ebgp: true, RouterId: "1.0.0.4", Neighbor: "9.0.0.4"},
			{Name: "i", AsPath: "1 2", IgpMetric: 5, RouterId: "1.0.0.5", Neighbor: "9.0.0.5"},
			{Name: "l", AsPath: "1 2 3 4", RouterId: "1.0.0.6", Neighbor: "9.0.0.6"},
			{Name: "r", AsPath: "1 2", RouterId: "1.0.0.7", Neighbor: "9.0.0.7", ClusterListLength: 2},
		}}),
		"bgp-age": bgp(&v1.BgpRequest{Routes: []*v1.BgpRoute{
			{Name: "x", AsPath: "1", Ebgp: true, RouterId: "1.0.0.1", Neighbor: "9.0.0.1", AgeSeconds: 100},
			{Name: "y", AsPath: "1", Ebgp: true, RouterId: "1.0.0.2", Neighbor: "9.0.0.2", AgeSeconds: 5},
		}}),
		"bgp-tie": bgp(&v1.BgpRequest{Routes: []*v1.BgpRoute{
			{Name: "x", AsPath: "1", RouterId: "1.0.0.1", Neighbor: "9.0.0.1"},
			{Name: "y", AsPath: "1", RouterId: "1.0.0.1", Neighbor: "9.0.0.1"},
		}}),
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
				if len(row.Cells) > 1 && !codedCol(row, len(row.Cells)-1) && row.Cells[len(row.Cells)-1] != es.Tables[ti].Rows[ri].Cells[len(row.Cells)-1] {
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

func codedCol(row *v1.CalcRow, col int) bool {
	for _, c := range row.Coded {
		if int(c.Col) == col {
			return true
		}
	}
	return false
}

// Fase 30c-A: las celdas con palabras viajan como código (calc.val.*), el español del catálogo es la celda de
// siempre y con en la celda sale en inglés (sin tocar los datos del resto de la fila).
func TestCalcValoresConPalabrasEnCodigo(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewCalcServiceClient(h.conn)
	total := 0
	for n, f := range calcCases(t) {
		es, err := f(c, func() ctxT { return con(t, "") })
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		en, _ := f(c, func() ctxT { return con(t, "en") })
		for ti, tb := range es.Tables {
			for ri, row := range tb.Rows {
				for _, cd := range row.Coded {
					total++
					if !strings.HasPrefix(cd.Key, "calc.val.") || i18n.Msg(i18n.Es, cd.Key, cd.Args) != row.Cells[cd.Col] {
						t.Errorf("%s: celda %q con clave %s", n, row.Cells[cd.Col], cd.Key)
					}
					if got := en.Tables[ti].Rows[ri].Cells[cd.Col]; got != i18n.Msg(i18n.En, cd.Key, cd.Args) {
						t.Errorf("%s: celda %q en inglés es %q", n, row.Cells[cd.Col], got)
					}
				}
			}
		}
	}
	if total < 100 {
		t.Errorf("solo %d celdas con código", total)
	}
	one := func(name, lang, key string) string {
		r, _ := calcCases(t)[name](c, func() ctxT { return con(t, lang) })
		return valueOf(r, key)
	}
	for _, x := range []struct{ name, lang, key, want string }{
		{"tcp-window", "", "calc.row.limited_by", "ventana"}, {"tcp-window", "en", "calc.row.limited_by", "window"},
		{"tcp-loss", "en", "calc.row.limited_by", "loss"}, {"tcp-none", "en", "calc.row.limited_by", "link"},
		{"optics-overload", "", "calc.row.verdict", "sí cierra, pero satura el receptor"}, {"optics-overload", "en", "calc.row.verdict", "it closes, but it overloads the receiver"},
		{"optics-short", "en", "calc.row.verdict", "it does NOT close"},
		{"subnet-private", "en", "calc.row.kind", "private (RFC 1918)"}, {"subnet-v6-mcast", "en", "calc.row.kind", "multicast, site scope"},
		{"subnet-v6-mcast", "", "calc.row.kind", "multicast, alcance sitio"}, {"ipv6-global", "en", "calc.row.kind", "global unicast (RFC 4291)"},
	} {
		if got := one(x.name, x.lang, x.key); got != x.want {
			t.Errorf("%s/%s %s: %q, esperaba %q", x.name, x.lang, x.key, got, x.want)
		}
	}
	// el paso que decide viaja como código también dentro de la nota
	r, _ := calcCases(t)["bgp-basic"](c, func() ctxT { return con(t, "en") })
	if r.NotesStructured[0].Args["step"] != "calc.val.step.local_pref" || !strings.Contains(r.Notes[0], `step "local-preference"`) {
		t.Errorf("%v / %s", r.NotesStructured[0], r.Notes[0])
	}
	r, _ = calcCases(t)["bgp-tie"](c, func() ctxT { return con(t, "en") })
	if !strings.Contains(r.Text, "total tie") || strings.Contains(r.Text, "empate") {
		t.Errorf("%s", r.Text)
	}
	r, _ = calcCases(t)["mtu-mpls-qinq"](c, func() ctxT { return con(t, "en") })
	if !strings.Contains(r.Text, "3 label(s) × 4") || !strings.Contains(r.Text, "tag in the inner frame 8") || strings.Contains(r.Text, "etiqueta") {
		t.Errorf("%s", r.Text)
	}
}
