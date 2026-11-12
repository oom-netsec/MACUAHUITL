package calc

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Route es una ruta candidata con los atributos que usa el algoritmo de Cisco.
// LocalPref nil = 100 (bgp default local-preference); MED nil = 0 (sin
// bgp bestpath med missing-as-worst).
type Route struct {
	Name               string  `json:"name"`
	Weight             uint32  `json:"weight,omitempty"` // 0 = por defecto (32768 si Local)
	LocalPref          *uint32 `json:"localPref,omitempty"`
	Local              bool    `json:"local,omitempty"`
	ASPath             string  `json:"asPath,omitempty"`
	Origin             string  `json:"origin,omitempty"` // i, e, ? (vacío = i)
	MED                *uint32 `json:"med,omitempty"`
	EBGP               bool    `json:"ebgp,omitempty"`
	IGPMetric          uint32  `json:"igpMetric,omitempty"`
	RouterID           string  `json:"routerId,omitempty"`
	OriginatorID       string  `json:"originatorId,omitempty"`
	ClusterListLen     int     `json:"clusterListLen,omitempty"`
	Neighbor           string  `json:"neighbor,omitempty"`
	AgeSeconds         int64   `json:"ageSeconds,omitempty"`
	NextHopUnreachable bool    `json:"nextHopUnreachable,omitempty"`
}

type BGPOptions struct {
	AlwaysCompareMED bool `json:"alwaysCompareMed"` // bgp always-compare-med
	DeterministicMED bool `json:"deterministicMed"` // bgp deterministic-med
	MultipathRelax   bool `json:"multipathRelax"`   // bgp bestpath as-path multipath-relax
	MaximumPaths     int  `json:"maximumPaths"`     // maximum-paths (0 o 1 = sin multipath)
}

type BGPComparison struct {
	A, B   string `json:"-"`
	Pair   string `json:"pair"`
	Step   string `json:"step"`
	ValueA string `json:"valueA"`
	ValueB string `json:"valueB"`
	Winner string `json:"winner"`
}

type BGPResult struct {
	Best        string          `json:"best"`
	DecidedBy   string          `json:"decidedBy"`
	Comparisons []BGPComparison `json:"comparisons"`
	Multipath   []string        `json:"multipath,omitempty"`
	Excluded    []string        `json:"excluded,omitempty"`
	LocalWeight []string        `json:"localWeight,omitempty"` // locales con weight 0 → 32768
	Routes      []Route         `json:"routes"`
	Options     BGPOptions      `json:"options"`
	Notes       []string        `json:"notes"`
	notes       []Note
}

type path struct {
	Route
	lp, med       uint32
	asLen, origin int
	neighborAS    string
	rid, nbr      netip.Addr
}

// parseASPath cuenta la longitud como IOS: cada AS de una secuencia suma 1, un
// AS_SET {..} suma 1 y los segmentos de confederación (..) no suman.
func parseASPath(s string) (n int, first string, err error) {
	s = strings.NewReplacer("{", " { ", "}", " } ", "(", " ( ", ")", " ) ", ",", " ").Replace(s)
	var in string
	for _, tok := range strings.Fields(s) {
		switch tok {
		case "{", "(":
			if in != "" {
				return 0, "", errors.New("segmentos anidados")
			}
			in = tok
			if tok == "{" {
				n++
			}
		case "}", ")":
			if (in == "{") != (tok == "}") || in == "" {
				return 0, "", errors.New("segmento mal cerrado")
			}
			in = ""
		default:
			for _, part := range strings.Split(tok, ".") { // asdot: 1.10
				if _, err := strconv.ParseUint(part, 10, 32); err != nil {
					return 0, "", fmt.Errorf("AS %q inválido", tok)
				}
			}
			if in == "" {
				n++
				if first == "" {
					first = tok
				}
			}
		}
	}
	if in != "" {
		return 0, "", errors.New("segmento sin cerrar")
	}
	return n, first, nil
}

var origins = map[string]int{"": 0, "i": 0, "igp": 0, "e": 1, "egp": 1, "?": 2, "incomplete": 2}
var originNames = []string{"IGP (i)", "EGP (e)", "incomplete (?)"}

func prep(r Route) (path, error) {
	p := path{Route: r, lp: 100}
	if r.LocalPref != nil {
		p.lp = *r.LocalPref
	}
	if r.MED != nil {
		p.med = *r.MED
	}
	var ok bool
	if p.origin, ok = origins[strings.ToLower(r.Origin)]; !ok {
		return p, fmt.Errorf("%s: origin %q inválido (i, e, ?)", r.Name, r.Origin)
	}
	var err error
	if p.asLen, p.neighborAS, err = parseASPath(r.ASPath); err != nil {
		return p, fmt.Errorf("%s: AS_PATH %q: %w", r.Name, r.ASPath, err)
	}
	id := r.RouterID
	if r.OriginatorID != "" { // en rutas reflejadas el ORIGINATOR_ID ocupa el lugar del router-ID
		id = r.OriginatorID
	}
	for _, a := range []struct {
		s   string
		dst *netip.Addr
	}{{id, &p.rid}, {r.Neighbor, &p.nbr}} {
		if a.s == "" {
			*a.dst = netip.IPv4Unspecified()
			continue
		}
		if *a.dst, err = netip.ParseAddr(a.s); err != nil {
			return p, fmt.Errorf("%s: dirección %q inválida", r.Name, a.s)
		}
	}
	return p, nil
}

type step struct {
	name string
	// cmp < 0: gana a; > 0: gana b; 0: empate. skip: el paso no aplica a este par.
	f func(a, b *path, o BGPOptions) (cmp int, va, vb string, skip bool)
}

func higher(x, y uint32) int { return cmpU(uint64(y), uint64(x)) }
func lower(x, y uint32) int  { return cmpU(uint64(x), uint64(y)) }
func itoa[T ~int | ~uint32 | ~int64](v T) string {
	return strconv.FormatInt(int64(v), 10)
}
func yes(b bool) string {
	if b {
		return "sí"
	}
	return "no"
}
func kindOf(p *path) string {
	if p.EBGP {
		return "eBGP"
	}
	return "iBGP"
}

// El orden de IOS/IOS-XE (Cisco: "BGP Best Path Selection Algorithm").
var bgpSteps = []step{
	{"weight", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return higher(a.Weight, b.Weight), itoa(a.Weight), itoa(b.Weight), false
	}},
	{"local-preference", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return higher(a.lp, b.lp), itoa(a.lp), itoa(b.lp), false
	}},
	{"originada localmente", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		c := 0
		if a.Local != b.Local {
			c = map[bool]int{true: -1, false: 1}[a.Local]
		}
		return c, yes(a.Local), yes(b.Local), false
	}},
	{"longitud de AS_PATH", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return lower(uint32(a.asLen), uint32(b.asLen)), itoa(a.asLen), itoa(b.asLen), false
	}},
	{"origin", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return lower(uint32(a.origin), uint32(b.origin)), originNames[a.origin], originNames[b.origin], false
	}},
	{"MED", func(a, b *path, o BGPOptions) (int, string, string, bool) {
		// Solo entre rutas del mismo AS vecino, salvo always-compare-med.
		return lower(a.med, b.med), itoa(a.med), itoa(b.med), !o.AlwaysCompareMED && a.neighborAS != b.neighborAS
	}},
	{"eBGP sobre iBGP", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		c := 0
		if a.EBGP != b.EBGP {
			c = map[bool]int{true: -1, false: 1}[a.EBGP]
		}
		return c, kindOf(a), kindOf(b), false
	}},
	{"métrica IGP al next-hop", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return lower(a.IGPMetric, b.IGPMetric), itoa(a.IGPMetric), itoa(b.IGPMetric), false
	}},
	{"ruta eBGP más antigua", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		c := 0
		if a.AgeSeconds != b.AgeSeconds {
			c = map[bool]int{true: -1, false: 1}[a.AgeSeconds > b.AgeSeconds]
		}
		return c, itoa(a.AgeSeconds) + " s", itoa(b.AgeSeconds) + " s", !a.EBGP || !b.EBGP
	}},
	{"router-ID", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return a.rid.Compare(b.rid), a.rid.String(), b.rid.String(), false
	}},
	{"longitud de CLUSTER_LIST", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return lower(uint32(a.ClusterListLen), uint32(b.ClusterListLen)), itoa(a.ClusterListLen), itoa(b.ClusterListLen), false
	}},
	{"dirección del vecino", func(a, b *path, _ BGPOptions) (int, string, string, bool) {
		return a.nbr.Compare(b.nbr), a.nbr.String(), b.nbr.String(), false
	}},
}

// multipathSteps: hasta la métrica IGP inclusive (y por tanto el tipo eBGP/iBGP), las
// rutas deben empatar para ser multipath.
const multipathSteps = 8

func compare(a, b *path, o BGPOptions, upto int) (winner *path, c BGPComparison) {
	c = BGPComparison{A: a.Name, B: b.Name, Pair: a.Name + " vs " + b.Name}
	for _, s := range bgpSteps[:upto] {
		r, va, vb, skip := s.f(a, b, o)
		if skip || r == 0 {
			continue
		}
		c.Step, c.ValueA, c.ValueB = s.name, va, vb
		if r < 0 {
			c.Winner = a.Name
			return a, c
		}
		c.Winner = b.Name
		return b, c
	}
	c.Step, c.Winner = "empate total", a.Name
	return a, c
}

// BGPBestPath aplica el algoritmo de Cisco por pares, en el orden en que llegan las
// rutas (como las lista show ip bgp: la más nueva primero). Con deterministic-med
// primero se elige el mejor de cada AS vecino y luego se comparan esos ganadores.
func BGPBestPath(routes []Route, o BGPOptions) (BGPResult, error) {
	if len(routes) < 2 {
		return BGPResult{}, errors.New("indica al menos dos rutas candidatas")
	}
	res := BGPResult{Routes: slices.Clone(routes), Options: o}
	var ps []*path
	for i := range res.Routes {
		r := &res.Routes[i]
		if r.Name == "" {
			r.Name = fmt.Sprintf("ruta %d", i+1)
		}
		// IOS asigna weight 32768 a lo originado localmente; 0 aquí significa "por defecto".
		if r.Local && r.Weight == 0 {
			r.Weight = 32768
			res.LocalWeight = append(res.LocalWeight, r.Name)
		}
		p, err := prep(*r)
		if err != nil {
			return BGPResult{}, err
		}
		if r.NextHopUnreachable {
			res.Excluded = append(res.Excluded, r.Name)
			continue
		}
		ps = append(ps, &p)
	}
	if len(ps) == 0 {
		return BGPResult{}, errors.New("ninguna ruta tiene el next-hop accesible: no hay mejor ruta")
	}
	run := func(list []*path) *path {
		b := list[0]
		for _, p := range list[1:] {
			var c BGPComparison
			b, c = compare(b, p, o, len(bgpSteps))
			res.Comparisons = append(res.Comparisons, c)
		}
		return b
	}
	var winner *path
	if o.DeterministicMED {
		var order []string
		groups := map[string][]*path{}
		for _, p := range ps {
			if _, ok := groups[p.neighborAS]; !ok {
				order = append(order, p.neighborAS)
			}
			groups[p.neighborAS] = append(groups[p.neighborAS], p)
		}
		var finals []*path
		for _, as := range order {
			finals = append(finals, run(groups[as]))
		}
		winner = run(finals)
	} else {
		winner = run(ps)
	}
	res.Best, res.DecidedBy = winner.Name, "next-hop accesible"
	for i := len(res.Comparisons) - 1; i >= 0; i-- {
		if c := res.Comparisons[i]; c.A == winner.Name || c.B == winner.Name {
			res.DecidedBy = c.Step
			break
		}
	}
	if o.MaximumPaths > 1 {
		res.Multipath = []string{winner.Name}
		for _, p := range ps {
			if p == winner || len(res.Multipath) >= o.MaximumPaths {
				continue
			}
			if _, c := compare(winner, p, o, multipathSteps); c.Step != "empate total" {
				continue
			}
			if o.MultipathRelax || (p.ASPath == winner.ASPath && p.neighborAS == winner.neighborAS) {
				res.Multipath = append(res.Multipath, p.Name)
			}
		}
	}
	res.Notes, res.notes = bgpNotes(res)
	return res, nil
}

func bgpNotes(r BGPResult) ([]string, []Note) {
	var n []string
	var items []Note
	add := func(key string, kv ...any) { addNote(&n, &items, key, kv...) }
	add("calc.note.bgp_winner", "best", r.Best, "step", r.DecidedBy)
	if len(r.LocalWeight) > 0 {
		add("calc.note.bgp_local_weight", "routes", strings.Join(r.LocalWeight, ", "))
	}
	if len(r.Excluded) > 0 {
		add("calc.note.bgp_excluded", "routes", strings.Join(r.Excluded, ", "))
	}
	if r.Options.DeterministicMED {
		add("calc.note.bgp_det_med")
	} else {
		add("calc.note.bgp_no_det_med")
	}
	if r.Options.AlwaysCompareMED {
		add("calc.note.bgp_always_med")
	} else {
		add("calc.note.bgp_med_same_as")
	}
	if r.Options.MaximumPaths > 1 {
		key := "calc.note.bgp_multipath"
		if r.Options.MultipathRelax {
			key = "calc.note.bgp_multipath_relax"
		}
		add(key, "max", r.Options.MaximumPaths, "routes", strings.Join(r.Multipath, ", "))
	}
	add("calc.note.bgp_unvalidated")
	return n, items
}

func (r BGPResult) Report() Report {
	rt := titled("calc.title.bgp_routes", nil, "calc.col.route", "calc.col.weight", "calc.col.local_pref", "calc.col.local", "calc.col.as_path", "calc.col.origin", "calc.col.med", "calc.col.type", "calc.col.igp", "calc.col.router_id", "calc.col.cluster", "calc.col.neighbor", "calc.col.age", "calc.col.next_hop")
	for _, x := range r.Routes {
		lp, med := "100", "0"
		if x.LocalPref != nil {
			lp = itoa(*x.LocalPref)
		}
		if x.MED != nil {
			med = itoa(*x.MED)
		}
		id, nh := x.RouterID, "accesible"
		if x.OriginatorID != "" {
			id += " (originator " + x.OriginatorID + ")"
		}
		if x.NextHopUnreachable {
			nh = "inaccesible"
		}
		origin := x.Origin
		if origin == "" {
			origin = "i"
		}
		t := "iBGP"
		if x.EBGP {
			t = "eBGP"
		}
		rt.add("", nil, x.Name, itoa(x.Weight), lp, yes(x.Local), x.ASPath, origin, med, t, itoa(x.IGPMetric), id, itoa(x.ClusterListLen), x.Neighbor, itoa(x.AgeSeconds), nh)
	}
	ct := titled("calc.title.bgp_comparisons", nil, "calc.col.comparison", "calc.col.step", "calc.col.value_a", "calc.col.value_b", "calc.col.winner")
	for _, c := range r.Comparisons {
		ct.add("", nil, c.Pair, c.Step, c.ValueA, c.ValueB, c.Winner)
	}
	return Report{Tables: []Table{rt, ct}, Notes: r.Notes, NoteItems: r.notes}
}
