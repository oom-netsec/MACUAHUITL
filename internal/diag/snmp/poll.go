package snmp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Perfiles de sondeo: OIDs útiles en un caso TAC.
var Profiles = []string{"sistema", "interfaces", "cpu", "memoria"}

var sysOIDs = map[string]string{
	".1.3.6.1.2.1.1.1.0": "sysDescr", ".1.3.6.1.2.1.1.2.0": "sysObjectID", ".1.3.6.1.2.1.1.3.0": "sysUpTime",
	".1.3.6.1.2.1.1.4.0": "sysContact", ".1.3.6.1.2.1.1.5.0": "sysName", ".1.3.6.1.2.1.1.6.0": "sysLocation",
}

// Columnas de IF-MIB (ifTable/ifXTable), CISCO-PROCESS-MIB y CISCO-MEMORY-POOL-MIB.
const (
	ifDescr       = ".1.3.6.1.2.1.2.2.1.2"
	ifOperStatus  = ".1.3.6.1.2.1.2.2.1.8"
	ifInOctets    = ".1.3.6.1.2.1.2.2.1.10"
	ifInDiscards  = ".1.3.6.1.2.1.2.2.1.13"
	ifInErrors    = ".1.3.6.1.2.1.2.2.1.14"
	ifOutOctets   = ".1.3.6.1.2.1.2.2.1.16"
	ifOutDiscards = ".1.3.6.1.2.1.2.2.1.19"
	ifOutErrors   = ".1.3.6.1.2.1.2.2.1.20"
	ifName        = ".1.3.6.1.2.1.31.1.1.1.1"
	ifHCInOctets  = ".1.3.6.1.2.1.31.1.1.1.6"
	ifHCOutOctets = ".1.3.6.1.2.1.31.1.1.1.10"
	ifHighSpeed   = ".1.3.6.1.2.1.31.1.1.1.15"
	cpm5sec       = ".1.3.6.1.4.1.9.9.109.1.1.1.1.6"
	cpm1min       = ".1.3.6.1.4.1.9.9.109.1.1.1.1.7"
	cpm5min       = ".1.3.6.1.4.1.9.9.109.1.1.1.1.8"
	memPoolName   = ".1.3.6.1.4.1.9.9.48.1.1.1.2"
	memPoolUsed   = ".1.3.6.1.4.1.9.9.48.1.1.1.5"
	memPoolFree   = ".1.3.6.1.4.1.9.9.48.1.1.1.6"
)

type IfStat struct {
	Index, Name, Oper                    string
	SpeedMbps                            uint64
	InOctets, OutOctets                  uint64
	InErrors, OutErrors                  uint64
	InDiscards, OutDiscards              uint64
	InBps, OutBps, InUtilPct, OutUtilPct *float64 // nil en la primera muestra, tras un reinicio del contador o sin velocidad
	counterBits                          int
}

type CPUStat struct {
	Index                    string
	FiveSec, OneMin, FiveMin uint64
}

type MemStat struct {
	Name       string
	Used, Free uint64
	UsedPct    float64
}

type Sample struct {
	Time       time.Time
	Uptime     uint32            `json:",omitempty"` // sysUpTime en centésimas; detecta reinicios entre muestras
	System     map[string]string `json:",omitempty"`
	Interfaces []IfStat          `json:",omitempty"`
	CPU        []CPUStat         `json:",omitempty"`
	Memory     []MemStat         `json:",omitempty"`
	Errors     []string          `json:",omitempty"` // un perfil que falla no detiene a los demás
	ErrorTexts []i18n.Text       `json:"-"`          // Errors como textos, para darlos en otro idioma
}

// rate calcula bits/s entre dos lecturas de un contador de octetos. No adivina:
// sin tasa si un contador de 64 bits baja (reinicio), si uno de 32 bits pudo dar
// más de una vuelta en dt a la velocidad del puerto (o no se conoce la velocidad
// y bajó), o si el resultado supera la velocidad del puerto.
func rate(prev, cur uint64, bits int, dt float64, mbps uint64) (float64, bool) {
	if dt <= 0 {
		return 0, false
	}
	speed := float64(mbps) * 1e6
	var d uint64
	switch {
	case bits == 32 && mbps > 0 && dt >= float64(uint64(1)<<32)*8/speed:
		return 0, false
	case cur >= prev:
		d = cur - prev
	case bits == 32 && mbps > 0 && prev < 1<<32:
		d = 1<<32 - prev + cur
	default:
		return 0, false
	}
	r := float64(d) * 8 / dt
	if mbps > 0 && r > speed*1.05 { // 5 % de holgura por el reloj entre muestras
		return 0, false
	}
	return r, true
}

func num(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case uint:
		return uint64(n)
	case uint32:
		return uint64(n)
	case int:
		if n > 0 {
			return uint64(n)
		}
	case int64:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

// column recorre una columna y devuelve índice → valor.
func column(x *gosnmp.GoSNMP, oid string) (map[string]any, error) {
	out := map[string]any{}
	err := x.BulkWalk(oid, func(p gosnmp.SnmpPDU) error {
		if len(out) >= MaxWalk {
			return errLimit
		}
		v := toVar(p)
		out[strings.TrimPrefix(p.Name, oid+".")] = v.Value
		return nil
	})
	if errors.Is(err, errLimit) {
		err = nil
	}
	return out, err
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		a, ea := strconv.Atoi(ks[i])
		b, eb := strconv.Atoi(ks[j])
		if ea == nil && eb == nil {
			return a < b
		}
		return ks[i] < ks[j]
	})
	return ks
}

var operNames = map[uint64]string{1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

func pollInterfaces(x *gosnmp.GoSNMP) ([]IfStat, error) {
	cols := map[string]map[string]any{}
	for _, c := range []string{ifName, ifDescr, ifOperStatus, ifHighSpeed, ifHCInOctets, ifHCOutOctets, ifInErrors, ifOutErrors, ifInDiscards, ifOutDiscards} {
		m, err := column(x, c)
		if err != nil {
			return nil, err
		}
		cols[c] = m
	}
	in, out, bits := cols[ifHCInOctets], cols[ifHCOutOctets], 64
	if len(in) == 0 { // agente sin ifXTable: contadores de 32 bits
		var err error
		if in, err = column(x, ifInOctets); err != nil {
			return nil, err
		}
		if out, err = column(x, ifOutOctets); err != nil {
			return nil, err
		}
		bits = 32
	}
	idx := cols[ifDescr]
	if len(cols[ifName]) > 0 {
		idx = cols[ifName]
	}
	var res []IfStat
	for _, i := range sortedKeys(idx) {
		name, _ := idx[i].(string)
		res = append(res, IfStat{Index: i, Name: name, Oper: operNames[num(cols[ifOperStatus][i])], SpeedMbps: num(cols[ifHighSpeed][i]),
			InOctets: num(in[i]), OutOctets: num(out[i]), InErrors: num(cols[ifInErrors][i]), OutErrors: num(cols[ifOutErrors][i]),
			InDiscards: num(cols[ifInDiscards][i]), OutDiscards: num(cols[ifOutDiscards][i]), counterBits: bits})
	}
	return res, nil
}

func pollCPU(x *gosnmp.GoSNMP) ([]CPUStat, error) {
	var cols [3]map[string]any
	for i, c := range []string{cpm5sec, cpm1min, cpm5min} {
		m, err := column(x, c)
		if err != nil {
			return nil, err
		}
		cols[i] = m
	}
	var res []CPUStat
	for _, i := range sortedKeys(cols[0]) {
		res = append(res, CPUStat{Index: i, FiveSec: num(cols[0][i]), OneMin: num(cols[1][i]), FiveMin: num(cols[2][i])})
	}
	return res, nil
}

func pollMemory(x *gosnmp.GoSNMP) ([]MemStat, error) {
	var cols [3]map[string]any
	for i, c := range []string{memPoolName, memPoolUsed, memPoolFree} {
		m, err := column(x, c)
		if err != nil {
			return nil, err
		}
		cols[i] = m
	}
	var res []MemStat
	for _, i := range sortedKeys(cols[0]) {
		name, _ := cols[0][i].(string)
		m := MemStat{Name: name, Used: num(cols[1][i]), Free: num(cols[2][i])}
		if t := m.Used + m.Free; t > 0 {
			m.UsedPct = float64(m.Used) * 100 / float64(t)
		}
		res = append(res, m)
	}
	return res, nil
}

func pollSystem(x *gosnmp.GoSNMP) (map[string]string, error) {
	oids := make([]string, 0, len(sysOIDs))
	for o := range sysOIDs {
		oids = append(oids, o)
	}
	r, err := x.Get(oids)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range r.Variables {
		if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance {
			continue
		}
		out[sysOIDs[p.Name]] = fmt.Sprint(toVar(p).Value)
	}
	return out, nil
}

// Poll toma count muestras (0 = hasta que ctx termine) cada interval y calcula tasas entre muestras.
func Poll(ctx context.Context, t Target, profiles []string, interval time.Duration, count int, onSample func(Sample)) error {
	want := map[string]bool{}
	for _, p := range profiles {
		if !contains(Profiles, p) {
			return i18n.Wrap("snmp.err.profile", ErrInvalid, i18n.A("profile", p, "profiles", strings.Join(Profiles, ", ")))
		}
		want[p] = true
	}
	if len(want) == 0 {
		want["sistema"], want["interfaces"] = true, true
	}
	if interval < time.Second/10 {
		interval = time.Second / 10
	}
	x, err := t.client(ctx)
	if err != nil {
		return err
	}
	defer x.Conn.Close()
	var prev *Sample
	for n := 0; count == 0 || n < count; n++ {
		if n > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(interval):
			}
		}
		s := Sample{Time: time.Now()}
		note := func(p string, err error) {
			if err != nil {
				t := i18n.Join(": ", i18n.Lit(p, p), i18n.FromErr(err))
				s.Errors, s.ErrorTexts = append(s.Errors, t.In(i18n.Es)), append(s.ErrorTexts, t)
			}
		}
		if want["sistema"] {
			s.System, err = pollSystem(x)
			note("sistema", err)
		}
		if want["interfaces"] {
			if r, err := x.Get([]string{".1.3.6.1.2.1.1.3.0"}); err == nil && len(r.Variables) == 1 {
				s.Uptime = uint32(num(r.Variables[0].Value))
			}
			s.Interfaces, err = pollInterfaces(x)
			note("interfaces", err)
		}
		if want["cpu"] {
			s.CPU, err = pollCPU(x)
			note("cpu", err)
		}
		if want["memoria"] {
			s.Memory, err = pollMemory(x)
			note("memoria", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		if prev != nil {
			rates(prev, &s)
		}
		onSample(s)
		prev = &s
	}
	return nil
}

// Localize da los errores de la muestra en el idioma pedido.
func (s Sample) Localize(loc string) Sample {
	s.Errors = i18n.Notes(loc, s.Errors, s.ErrorTexts)
	return s
}

func rates(prev, cur *Sample) {
	dt := cur.Time.Sub(prev.Time).Seconds()
	if prev.Uptime > 0 && cur.Uptime > 0 && (cur.Uptime < prev.Uptime || float64(cur.Uptime)/100 < dt) {
		i18n.Note(&cur.Errors, &cur.ErrorTexts, "snmp.poll.rates_skipped")
		return
	}
	old := map[string]IfStat{}
	for _, i := range prev.Interfaces {
		old[i.Index] = i
	}
	for k := range cur.Interfaces {
		c := &cur.Interfaces[k]
		p, ok := old[c.Index]
		if !ok {
			continue
		}
		if r, ok := rate(p.InOctets, c.InOctets, c.counterBits, dt, c.SpeedMbps); ok {
			c.InBps = &r
			c.InUtilPct = util(r, c.SpeedMbps)
		}
		if r, ok := rate(p.OutOctets, c.OutOctets, c.counterBits, dt, c.SpeedMbps); ok {
			c.OutBps = &r
			c.OutUtilPct = util(r, c.SpeedMbps)
		}
	}
}

func util(bps float64, mbps uint64) *float64 {
	if mbps == 0 {
		return nil
	}
	u := bps * 100 / (float64(mbps) * 1e6)
	return &u
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
