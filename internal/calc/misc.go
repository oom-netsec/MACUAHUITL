package calc

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ---- rendimiento TCP ----

type TCPResult struct {
	BandwidthBps   float64 `json:"bandwidthBps"`
	RTTms          float64 `json:"rttMs"`
	MSS            int     `json:"mss"`
	WindowBytes    float64 `json:"windowBytes,omitempty"`
	LossPct        float64 `json:"lossPct,omitempty"`
	BDPBytes       float64 `json:"bdpBytes"`
	WindowScale    int     `json:"windowScale"`
	WindowLimitBps float64 `json:"windowLimitBps,omitempty"`
	MathisBps      float64 `json:"mathisBps,omitempty"`
	MaxBps         float64 `json:"maxBps"`
	Limit          string  `json:"limit"`
	limitKey       string
	Notes          []string `json:"notes"`
	notes          []Note
}

// parseQty lee "1g", "100M", "1.5gbps", "64k"; base 1000 para bits/s y 1024 para bytes.
func parseQty(s string, base float64, unit string) (float64, error) {
	t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), unit)
	mult := 1.0
	if i := strings.IndexAny(t, "kmgt"); i >= 0 && i == len(t)-1 {
		mult = math.Pow(base, float64(strings.IndexByte("kmgt", t[i])+1))
		t = t[:i]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil || v <= 0 || math.IsInf(v, 0) || math.IsNaN(v) {
		return 0, fmt.Errorf("cantidad %q inválida", s)
	}
	return v * mult, nil
}

func human(v float64, unit string, base float64) string {
	prefixes := []string{"", "k", "M", "G", "T"}
	if base == 1024 {
		prefixes = []string{"", "Ki", "Mi", "Gi", "Ti"}
	}
	for _, p := range prefixes {
		if math.Abs(v) < base || p == prefixes[4] {
			return strconv.FormatFloat(v, 'f', 2, 64) + " " + p + unit
		}
		v /= base
	}
	return ""
}

func bps(v float64) string   { return human(v, "b/s", 1000) }
func bytes(v float64) string { return human(v, "B", 1024) }

// mathisC es √(3/2), la constante de Mathis et al. (1997) con ACK por segmento.
var mathisC = math.Sqrt(1.5)

// TCP calcula lo que puede dar un solo flujo: el mínimo entre el enlace, ventana/RTT
// y el techo de Mathis por pérdida.
func TCP(bandwidth string, rttMs float64, window string, lossPct float64, mss int) (TCPResult, error) {
	bw, err := parseQty(bandwidth, 1000, "bps")
	if err != nil {
		return TCPResult{}, fmt.Errorf("ancho de banda: %w", err)
	}
	if rttMs <= 0 || math.IsNaN(rttMs) || math.IsInf(rttMs, 0) {
		return TCPResult{}, errors.New("el RTT debe ser mayor que 0 ms")
	}
	if lossPct < 0 || lossPct >= 100 || math.IsNaN(lossPct) {
		return TCPResult{}, errors.New("la pérdida va de 0 a menos de 100 %")
	}
	if mss <= 0 {
		mss = 1460
	}
	rtt := rttMs / 1000
	r := TCPResult{BandwidthBps: bw, RTTms: rttMs, MSS: mss, LossPct: lossPct, BDPBytes: bw * rtt / 8, MaxBps: bw, Limit: "enlace", limitKey: "calc.val.limit.link"}
	for r.WindowScale < 14 && float64(int64(65535)<<r.WindowScale) < r.BDPBytes {
		r.WindowScale++
	}
	if strings.TrimSpace(window) != "" {
		if r.WindowBytes, err = parseQty(window, 1024, "b"); err != nil {
			return TCPResult{}, fmt.Errorf("ventana: %w", err)
		}
		if r.WindowLimitBps = r.WindowBytes * 8 / rtt; r.WindowLimitBps < r.MaxBps {
			r.MaxBps, r.Limit, r.limitKey = r.WindowLimitBps, "ventana", "calc.val.limit.window"
		}
	}
	if lossPct > 0 {
		if r.MathisBps = float64(mss) * 8 / rtt * mathisC / math.Sqrt(lossPct/100); r.MathisBps < r.MaxBps {
			r.MaxBps, r.Limit, r.limitKey = r.MathisBps, "pérdida", "calc.val.limit.loss"
		}
	}
	addNote(&r.Notes, &r.notes, "calc.note.tcp_bdp", "bandwidth", bps(bw), "rtt", fmt.Sprintf("%g", rttMs), "bdp", bytes(r.BDPBytes), "scale", r.WindowScale)
	switch r.Limit {
	case "ventana":
		addNote(&r.Notes, &r.notes, "calc.note.tcp_window_limit", "window", bytes(r.WindowBytes), "limit", bps(r.WindowLimitBps), "buffer", fmt.Sprintf("%.0f", math.Ceil(r.BDPBytes/1024)))
	case "pérdida":
		addNote(&r.Notes, &r.notes, "calc.note.tcp_loss_limit", "loss", fmt.Sprintf("%g", lossPct), "limit", bps(r.MathisBps), "flows", fmt.Sprintf("%.0f", math.Ceil(bw/r.MathisBps)))
	}
	addNote(&r.Notes, &r.notes, "calc.note.tcp_single_flow")
	return r, nil
}

func (r TCPResult) Report() Report {
	opt := func(v float64) string {
		if v == 0 {
			return ""
		}
		return bps(v)
	}
	return Report{Tables: []Table{kv("calc.title.tcp", nil,
		"calc.row.link", bps(r.BandwidthBps), "calc.row.rtt", strconv.FormatFloat(r.RTTms, 'f', -1, 64)+" ms",
		"calc.row.bdp", fmt.Sprintf("%s (%.0f bytes)", bytes(r.BDPBytes), r.BDPBytes), "calc.row.window_scale", strconv.Itoa(r.WindowScale),
		"calc.row.window_limit", opt(r.WindowLimitBps), "calc.row.loss_limit", opt(r.MathisBps),
		"calc.row.max_flow", bps(r.MaxBps), "calc.row.limited_by", val{key: r.limitKey})}, Notes: r.Notes, NoteItems: r.notes}
}

// ---- QoS: DSCP, ToS, CoS, EXP ----

type DSCPEntry struct {
	Name       string `json:"name"`
	DSCP       int    `json:"dscp"`
	Binary     string `json:"binary"`
	ToS        int    `json:"tos"`
	ToSHex     string `json:"tosHex"`
	Precedence int    `json:"precedence"`
	CoS        int    `json:"cos"`
	EXP        int    `json:"exp"`
	Class      string `json:"class"`
	Drop       string `json:"drop,omitempty"`
	classKey   string
	dropKey    string
}

type DSCPResult struct {
	Entries []DSCPEntry `json:"entries"`
	Notes   []string    `json:"notes"`
	notes   []Note
}

var dscpNames = []struct {
	name  string
	dscp  int
	class string
}{
	{"CS0", 0, "calc.val.dscp.default"}, {"LE", 1, "calc.val.dscp.le"}, {"CS1", 8, "calc.val.dscp.scavenger"},
	{"AF11", 10, "calc.val.dscp.high_volume"}, {"AF12", 12, "calc.val.dscp.high_volume"}, {"AF13", 14, "calc.val.dscp.high_volume"},
	{"CS2", 16, "calc.val.dscp.oam"}, {"AF21", 18, "calc.val.dscp.low_latency"}, {"AF22", 20, "calc.val.dscp.low_latency"}, {"AF23", 22, "calc.val.dscp.low_latency"},
	{"CS3", 24, "calc.val.dscp.cs3"}, {"AF31", 26, "calc.val.dscp.streaming"}, {"AF32", 28, "calc.val.dscp.streaming"}, {"AF33", 30, "calc.val.dscp.streaming"},
	{"CS4", 32, "calc.val.dscp.realtime"}, {"AF41", 34, "calc.val.dscp.video_conf"}, {"AF42", 36, "calc.val.dscp.video_conf"}, {"AF43", 38, "calc.val.dscp.video_conf"},
	{"CS5", 40, "calc.val.dscp.cs5"}, {"VOICE-ADMIT", 44, "calc.val.dscp.voice_admit"}, {"EF", 46, "calc.val.dscp.voice"},
	{"CS6", 48, "calc.val.dscp.network"}, {"CS7", 56, "calc.val.dscp.cs7"},
}

var dscpAliases = map[string]string{"DEFAULT": "CS0", "DF": "CS0", "BE": "CS0", "VA": "VOICE-ADMIT"}

func dscpEntry(d int) DSCPEntry {
	e := DSCPEntry{DSCP: d, Binary: fmt.Sprintf("%06b", d), ToS: d << 2, ToSHex: fmt.Sprintf("0x%02X", d<<2), Precedence: d >> 3, CoS: d >> 3, EXP: d >> 3, Class: kindText("calc.val.dscp.none"), classKey: "calc.val.dscp.none"}
	for _, n := range dscpNames {
		if n.dscp == d {
			e.Name, e.classKey = n.name, n.class
			e.Class = kindText(n.class)
		}
	}
	if strings.HasPrefix(e.Name, "AF") {
		e.dropKey = []string{"calc.val.drop.low", "calc.val.drop.medium", "calc.val.drop.high"}[e.Name[3]-'1']
		e.Drop = kindText(e.dropKey)
	}
	return e
}

// DSCP busca por cualquier campo; sin campo, un número es DSCP y un texto es nombre.
// CoS y EXP siguen el mapeo Cisco por defecto: los 3 bits altos (la precedencia).
func DSCP(query, by string) (DSCPResult, error) {
	q, by := strings.ToUpper(strings.TrimSpace(query)), strings.ToLower(strings.TrimSpace(by))
	r := DSCPResult{}
	addNote(&r.Notes, &r.notes, "calc.note.dscp_cos_map")
	addNote(&r.Notes, &r.notes, "calc.note.dscp_rfc4594")
	num := func(base int, max int) (int, error) {
		s := q
		if base == 16 {
			s = strings.TrimPrefix(s, "0X")
		}
		v, err := strconv.ParseInt(s, base, 32)
		if err != nil || v < 0 || int(v) > max {
			return 0, fmt.Errorf("%q no es un valor válido para %s", query, by)
		}
		return int(v), nil
	}
	if q == "" {
		for _, n := range dscpNames {
			r.Entries = append(r.Entries, dscpEntry(n.dscp))
		}
		return r, nil
	}
	if by == "" {
		if _, err := strconv.Atoi(q); err == nil {
			by = "dscp"
		} else {
			by = "name"
		}
	}
	match := func(f func(DSCPEntry) bool) DSCPResult {
		for d := 0; d < 64; d++ {
			if e := dscpEntry(d); (e.Name != "" || by == "dscp") && f(e) {
				r.Entries = append(r.Entries, e)
			}
		}
		return r
	}
	switch by {
	case "name":
		if a, ok := dscpAliases[q]; ok {
			q = a
		}
		r = match(func(e DSCPEntry) bool { return e.Name == q })
	case "dscp", "binary":
		base := map[string]int{"dscp": 10, "binary": 2}[by]
		v, err := num(base, 63)
		if err != nil {
			return DSCPResult{}, err
		}
		by = "dscp"
		r = match(func(e DSCPEntry) bool { return e.DSCP == v })
	case "tos":
		base := 10
		if strings.HasPrefix(q, "0X") {
			base = 16
		}
		v, err := num(base, 255)
		if err != nil {
			return DSCPResult{}, err
		}
		by = "dscp" // los 2 bits bajos son ECN
		r = match(func(e DSCPEntry) bool { return e.DSCP == v>>2 })
	case "precedence", "cos", "exp":
		v, err := num(10, 7)
		if err != nil {
			return DSCPResult{}, err
		}
		r = match(func(e DSCPEntry) bool { return e.Precedence == v })
	default:
		return DSCPResult{}, fmt.Errorf("campo %q desconocido (name, dscp, binary, tos, precedence, cos, exp)", by)
	}
	if len(r.Entries) == 0 {
		return DSCPResult{}, fmt.Errorf("nada coincide con %q", query)
	}
	return r, nil
}

func (r DSCPResult) Report() Report {
	t := titled("calc.title.dscp", nil, "calc.col.name", "calc.col.dscp", "calc.col.binary", "calc.col.tos", "calc.col.tos_hex", "calc.col.precedence", "calc.col.cos", "calc.col.exp", "calc.col.af_drop", "calc.col.class")
	for _, e := range r.Entries {
		var drop any = e.Drop
		if e.dropKey != "" {
			drop = val{key: e.dropKey}
		}
		t.add("", nil, e.Name, strconv.Itoa(e.DSCP), e.Binary, strconv.Itoa(e.ToS), e.ToSHex, strconv.Itoa(e.Precedence),
			strconv.Itoa(e.CoS), strconv.Itoa(e.EXP), drop, val{key: e.classKey})
	}
	return Report{Tables: []Table{t}, Notes: r.Notes, NoteItems: r.notes}
}

// ---- óptica ----

// Pérdidas típicas de diseño por km; la hoja del fabricante o la medición mandan.
var fiberLoss = map[string]float64{"smf-1310": 0.35, "smf-1550": 0.25, "mmf-850": 3.0, "mmf-1300": 1.0}

type OpticsInput struct {
	TxDbm         float64  `json:"txDbm"`
	RxSensDbm     float64  `json:"rxSensDbm"`
	RxOverloadDbm *float64 `json:"rxOverloadDbm,omitempty"`
	Km            float64  `json:"km"`
	Fiber         string   `json:"fiber,omitempty"`
	LossPerKm     float64  `json:"lossPerKm,omitempty"`
	Connectors    int      `json:"connectors"`
	ConnectorLoss float64  `json:"connectorLoss"`
	Splices       int      `json:"splices"`
	SpliceLoss    float64  `json:"spliceLoss"`
	MarginDb      float64  `json:"marginDb"`
}

type OpticsResult struct {
	OpticsInput
	BudgetDb      float64  `json:"budgetDb"`
	FiberLossDb   float64  `json:"fiberLossDb"`
	TotalLossDb   float64  `json:"totalLossDb"`
	ExpectedRxDbm float64  `json:"expectedRxDbm"`
	RemainingDb   float64  `json:"remainingDb"`
	Closes        bool     `json:"closes"`
	Overload      bool     `json:"overload"`
	AttenuatorDb  float64  `json:"attenuatorDb,omitempty"`
	Notes         []string `json:"notes,omitempty"`
	notes         []Note
}

func Optics(in OpticsInput) (OpticsResult, error) {
	lpk := in.LossPerKm
	if lpk <= 0 {
		var ok bool
		if lpk, ok = fiberLoss[strings.ToLower(in.Fiber)]; !ok {
			return OpticsResult{}, fmt.Errorf("fibra %q desconocida (smf-1310, smf-1550, mmf-850, mmf-1300) o indica la pérdida por km", in.Fiber)
		}
	}
	if in.Km < 0 || in.Connectors < 0 || in.Splices < 0 || in.ConnectorLoss < 0 || in.SpliceLoss < 0 || in.MarginDb < 0 {
		return OpticsResult{}, errors.New("distancia, conectores, empalmes, pérdidas y margen no pueden ser negativos")
	}
	r := OpticsResult{OpticsInput: in, BudgetDb: in.TxDbm - in.RxSensDbm, FiberLossDb: in.Km * lpk}
	r.LossPerKm = lpk
	r.TotalLossDb = r.FiberLossDb + float64(in.Connectors)*in.ConnectorLoss + float64(in.Splices)*in.SpliceLoss
	r.ExpectedRxDbm = in.TxDbm - r.TotalLossDb
	r.RemainingDb = r.BudgetDb - r.TotalLossDb - in.MarginDb
	r.Closes = r.RemainingDb >= 0
	if in.RxOverloadDbm != nil && r.ExpectedRxDbm > *in.RxOverloadDbm {
		r.Overload, r.AttenuatorDb = true, r.ExpectedRxDbm-*in.RxOverloadDbm
		addNote(&r.Notes, &r.notes, "calc.note.optics_overload", "rx", fmt.Sprintf("%.2f", r.ExpectedRxDbm), "overload", fmt.Sprintf("%.2f", *in.RxOverloadDbm), "attenuator", fmt.Sprintf("%.1f", r.AttenuatorDb))
	}
	if !r.Closes {
		addNote(&r.Notes, &r.notes, "calc.note.optics_short", "missing", fmt.Sprintf("%.2f", -r.RemainingDb))
	}
	addNote(&r.Notes, &r.notes, "calc.note.optics_typical")
	return r, nil
}

func (r OpticsResult) Report() Report {
	f := func(v float64, u string) string { return strconv.FormatFloat(v, 'f', 2, 64) + " " + u }
	verdict := "calc.val.verdict.closes"
	if !r.Closes {
		verdict = "calc.val.verdict.not_closes"
	}
	if r.Overload {
		verdict += "_overload"
	}
	loss := titled("calc.title.losses", nil, "calc.col.item", "calc.col.quantity", "calc.col.loss")
	loss.add("calc.row.fiber", i18n.A("loss", fmt.Sprintf("%.2f", r.LossPerKm)), "", f(r.Km, "km"), f(r.FiberLossDb, "dB"))
	loss.add("calc.row.connectors", i18n.A("loss", fmt.Sprintf("%.2f", r.ConnectorLoss)), "", strconv.Itoa(r.Connectors), f(float64(r.Connectors)*r.ConnectorLoss, "dB"))
	loss.add("calc.row.splices", i18n.A("loss", fmt.Sprintf("%.2f", r.SpliceLoss)), "", strconv.Itoa(r.Splices), f(float64(r.Splices)*r.SpliceLoss, "dB"))
	loss.add("calc.row.total", nil, "", "", f(r.TotalLossDb, "dB"))
	return Report{Tables: []Table{loss,
		kv("calc.title.budget", nil, "calc.row.tx", f(r.TxDbm, "dBm"), "calc.row.rx_sensitivity", f(r.RxSensDbm, "dBm"), "calc.row.budget", f(r.BudgetDb, "dB"),
			"calc.row.rx_expected", f(r.ExpectedRxDbm, "dBm"), "calc.row.margin", f(r.MarginDb, "dB"), "calc.row.spare", f(r.RemainingDb, "dB"), "calc.row.verdict", val{key: verdict}),
	}, Notes: r.Notes, NoteItems: r.notes}
}

type PowerResult struct {
	Dbm float64 `json:"dbm"`
	Mw  float64 `json:"mw"`
}

// Power convierte "-3dBm" ↔ "0.5mW".
func Power(s string) (PowerResult, error) {
	t := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	switch {
	case strings.HasSuffix(t, "dbm"):
		v, err := strconv.ParseFloat(strings.TrimSuffix(t, "dbm"), 64)
		if err != nil || math.IsInf(v, 0) || math.IsNaN(v) {
			return PowerResult{}, fmt.Errorf("potencia %q inválida", s)
		}
		return PowerResult{Dbm: v, Mw: math.Pow(10, v/10)}, nil
	case strings.HasSuffix(t, "mw"):
		v, err := strconv.ParseFloat(strings.TrimSuffix(t, "mw"), 64)
		if err != nil || v <= 0 || math.IsInf(v, 0) {
			return PowerResult{}, fmt.Errorf("potencia %q inválida (mW mayor que 0)", s)
		}
		return PowerResult{Dbm: 10 * math.Log10(v), Mw: v}, nil
	}
	return PowerResult{}, fmt.Errorf("indica la unidad: %q → -3dBm o 0.5mW", s)
}

func (p PowerResult) Report() Report {
	return Report{Tables: []Table{kv("calc.title.power", nil, "calc.row.dbm", strconv.FormatFloat(p.Dbm, 'f', 3, 64), "calc.row.mw", strconv.FormatFloat(p.Mw, 'g', 6, 64))}}
}
