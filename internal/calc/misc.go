package calc

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ---- rendimiento TCP ----

type TCPResult struct {
	BandwidthBps   float64  `json:"bandwidthBps"`
	RTTms          float64  `json:"rttMs"`
	MSS            int      `json:"mss"`
	WindowBytes    float64  `json:"windowBytes,omitempty"`
	LossPct        float64  `json:"lossPct,omitempty"`
	BDPBytes       float64  `json:"bdpBytes"`
	WindowScale    int      `json:"windowScale"`
	WindowLimitBps float64  `json:"windowLimitBps,omitempty"`
	MathisBps      float64  `json:"mathisBps,omitempty"`
	MaxBps         float64  `json:"maxBps"`
	Limit          string   `json:"limit"`
	Notes          []string `json:"notes"`
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
	r := TCPResult{BandwidthBps: bw, RTTms: rttMs, MSS: mss, LossPct: lossPct, BDPBytes: bw * rtt / 8, MaxBps: bw, Limit: "enlace"}
	for r.WindowScale < 14 && float64(int64(65535)<<r.WindowScale) < r.BDPBytes {
		r.WindowScale++
	}
	if strings.TrimSpace(window) != "" {
		if r.WindowBytes, err = parseQty(window, 1024, "b"); err != nil {
			return TCPResult{}, fmt.Errorf("ventana: %w", err)
		}
		if r.WindowLimitBps = r.WindowBytes * 8 / rtt; r.WindowLimitBps < r.MaxBps {
			r.MaxBps, r.Limit = r.WindowLimitBps, "ventana"
		}
	}
	if lossPct > 0 {
		if r.MathisBps = float64(mss) * 8 / rtt * mathisC / math.Sqrt(lossPct/100); r.MathisBps < r.MaxBps {
			r.MaxBps, r.Limit = r.MathisBps, "pérdida"
		}
	}
	r.Notes = []string{
		fmt.Sprintf("Un flujo TCP no pasa de ventana/RTT: para llenar %s a %g ms hacen falta %s en vuelo (escala de ventana %d o más).", bps(bw), rttMs, bytes(r.BDPBytes), r.WindowScale),
	}
	switch r.Limit {
	case "ventana":
		r.Notes = append(r.Notes, fmt.Sprintf("La ventana de %s limita a %s: sube el búfer (iperf3 -w %.0fK; en Linux net.core.rmem_max/wmem_max y net.ipv4.tcp_rmem).", bytes(r.WindowBytes), bps(r.WindowLimitBps), math.Ceil(r.BDPBytes/1024)))
	case "pérdida":
		r.Notes = append(r.Notes, fmt.Sprintf("Con %g %% de pérdida, Mathis limita cada flujo a %s; harían falta unos %.0f flujos en paralelo (iperf3 -P) o quitar la pérdida.", lossPct, bps(r.MathisBps), math.Ceil(bw/r.MathisBps)))
	}
	r.Notes = append(r.Notes, "Además, un solo flujo cae en un único miembro de port-channel o ruta ECMP (hash por flujo) y en un solo núcleo de CPU: mide con iperf3 -P 4 a 8 antes de culpar al enlace.")
	return r, nil
}

func (r TCPResult) Report() Report {
	opt := func(v float64) string {
		if v == 0 {
			return ""
		}
		return bps(v)
	}
	return Report{Tables: []Table{kv("Rendimiento TCP de un flujo",
		"Enlace", bps(r.BandwidthBps), "RTT", strconv.FormatFloat(r.RTTms, 'f', -1, 64)+" ms",
		"BDP (ventana necesaria)", fmt.Sprintf("%s (%.0f bytes)", bytes(r.BDPBytes), r.BDPBytes), "Escala de ventana mínima", strconv.Itoa(r.WindowScale),
		"Límite por ventana", opt(r.WindowLimitBps), "Límite por pérdida (Mathis)", opt(r.MathisBps),
		"Máximo de un flujo", bps(r.MaxBps), "Lo limita", r.Limit)}, Notes: r.Notes}
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
}

type DSCPResult struct {
	Entries []DSCPEntry `json:"entries"`
	Notes   []string    `json:"notes"`
}

var dscpNames = []struct {
	name  string
	dscp  int
	class string
}{
	{"CS0", 0, "estándar (default, DF)"}, {"LE", 1, "menor esfuerzo (RFC 8622)"}, {"CS1", 8, "datos de baja prioridad (scavenger)"},
	{"AF11", 10, "datos de alto volumen"}, {"AF12", 12, "datos de alto volumen"}, {"AF13", 14, "datos de alto volumen"},
	{"CS2", 16, "OAM (gestión)"}, {"AF21", 18, "datos de baja latencia"}, {"AF22", 20, "datos de baja latencia"}, {"AF23", 22, "datos de baja latencia"},
	{"CS3", 24, "video broadcast (Cisco: señalización)"}, {"AF31", 26, "streaming multimedia"}, {"AF32", 28, "streaming multimedia"}, {"AF33", 30, "streaming multimedia"},
	{"CS4", 32, "interactivo en tiempo real"}, {"AF41", 34, "videoconferencia"}, {"AF42", 36, "videoconferencia"}, {"AF43", 38, "videoconferencia"},
	{"CS5", 40, "señalización (Cisco: video broadcast)"}, {"VOICE-ADMIT", 44, "voz con control de admisión (RFC 5865)"}, {"EF", 46, "telefonía (voz)"},
	{"CS6", 48, "control de red (enrutamiento)"}, {"CS7", 56, "reservado (control de red)"},
}

var dscpAliases = map[string]string{"DEFAULT": "CS0", "DF": "CS0", "BE": "CS0", "VA": "VOICE-ADMIT"}

func dscpEntry(d int) DSCPEntry {
	e := DSCPEntry{DSCP: d, Binary: fmt.Sprintf("%06b", d), ToS: d << 2, ToSHex: fmt.Sprintf("0x%02X", d<<2), Precedence: d >> 3, CoS: d >> 3, EXP: d >> 3, Class: "sin clase estándar"}
	for _, n := range dscpNames {
		if n.dscp == d {
			e.Name, e.Class = n.name, n.class
		}
	}
	if strings.HasPrefix(e.Name, "AF") {
		e.Drop = []string{"baja", "media", "alta"}[e.Name[3]-'1']
	}
	return e
}

// DSCP busca por cualquier campo; sin campo, un número es DSCP y un texto es nombre.
// CoS y EXP siguen el mapeo Cisco por defecto: los 3 bits altos (la precedencia).
func DSCP(query, by string) (DSCPResult, error) {
	q, by := strings.ToUpper(strings.TrimSpace(query)), strings.ToLower(strings.TrimSpace(by))
	r := DSCPResult{Notes: []string{
		"CoS y MPLS EXP por defecto en Cisco = precedencia IP (3 bits altos del DSCP). El mapa cos-dscp por defecto es 0 8 16 24 32 40 48 56; para voz se suele cambiar CoS 5 → 46 (mls qos map cos-dscp 0 8 16 24 32 46 48 56).",
		"Clases según RFC 4594; Cisco intercambia CS3 y CS5 (señalización en CS3, video broadcast en CS5).",
	}}
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
	t := Table{Title: "DSCP", Head: []string{"Nombre", "DSCP", "Binario", "ToS", "ToS hex", "Precedencia", "CoS", "EXP", "Descarte AF", "Clase (RFC 4594)"}}
	for _, e := range r.Entries {
		t.Rows = append(t.Rows, []string{e.Name, strconv.Itoa(e.DSCP), e.Binary, strconv.Itoa(e.ToS), e.ToSHex, strconv.Itoa(e.Precedence),
			strconv.Itoa(e.CoS), strconv.Itoa(e.EXP), e.Drop, e.Class})
	}
	return Report{Tables: []Table{t}, Notes: r.Notes}
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
		r.Notes = append(r.Notes, fmt.Sprintf("La potencia recibida (%.2f dBm) supera la saturación del receptor (%.2f dBm): pon un atenuador de al menos %.1f dB.", r.ExpectedRxDbm, *in.RxOverloadDbm, r.AttenuatorDb))
	}
	if !r.Closes {
		r.Notes = append(r.Notes, fmt.Sprintf("Faltan %.2f dB: el enlace no cierra con el margen pedido. Revisa conectores sucios, la óptica (LR→ER) o la distancia.", -r.RemainingDb))
	}
	r.Notes = append(r.Notes, "Pérdidas por km y por conector son valores típicos de diseño: usa la hoja de la óptica y la medición OTDR cuando las tengas.")
	return r, nil
}

func (r OpticsResult) Report() Report {
	f := func(v float64, u string) string { return strconv.FormatFloat(v, 'f', 2, 64) + " " + u }
	verdict := "sí cierra"
	if !r.Closes {
		verdict = "NO cierra"
	}
	if r.Overload {
		verdict += ", pero satura el receptor"
	}
	return Report{Tables: []Table{
		Table{Title: "Pérdidas", Head: []string{"Elemento", "Cantidad", "Pérdida"}, Rows: [][]string{
			{fmt.Sprintf("Fibra (%.2f dB/km)", r.LossPerKm), f(r.Km, "km"), f(r.FiberLossDb, "dB")},
			{fmt.Sprintf("Conectores (%.2f dB c/u)", r.ConnectorLoss), strconv.Itoa(r.Connectors), f(float64(r.Connectors)*r.ConnectorLoss, "dB")},
			{fmt.Sprintf("Empalmes (%.2f dB c/u)", r.SpliceLoss), strconv.Itoa(r.Splices), f(float64(r.Splices)*r.SpliceLoss, "dB")},
			{"Total", "", f(r.TotalLossDb, "dB")},
		}},
		kv("Presupuesto", "Tx", f(r.TxDbm, "dBm"), "Sensibilidad Rx", f(r.RxSensDbm, "dBm"), "Presupuesto", f(r.BudgetDb, "dB"),
			"Rx esperada", f(r.ExpectedRxDbm, "dBm"), "Margen pedido", f(r.MarginDb, "dB"), "Sobrante", f(r.RemainingDb, "dB"), "Veredicto", verdict),
	}, Notes: r.Notes}
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
	return Report{Tables: []Table{kv("Potencia", "dBm", strconv.FormatFloat(p.Dbm, 'f', 3, 64), "mW", strconv.FormatFloat(p.Mw, 'g', 6, 64))}}
}
