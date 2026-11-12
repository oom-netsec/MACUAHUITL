package fleet

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

// golden: el JSON y el texto en español de cada informe de la flota, tal como salían antes de la fase 30c.
type golden struct{ JSON, Text string }

func gold(v any, text string) golden {
	b, _ := json.Marshal(v)
	return golden{string(b), text}
}

// regCases arma informes que recorren todos los avisos, motivos y evidencias; no usa nada de 30c.
func regCases(t *testing.T) (map[string]golden, map[string]any) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]any{}
	add := func(name string, v any, text string) {
		out[name] = gold(v, text)
		cp := reflect.New(reflect.TypeOf(v).Elem()) // copia: varios casos reusan la misma variable
		cp.Elem().Set(reflect.ValueOf(v).Elem())
		ptrs[name] = cp.Interface()
	}
	f := load(t)
	for _, q := range []string{"10.1.10.20", "aabb.cc00.0a01", "dist1", "10.9.9.9", "10.255.0.2"} {
		r := f.Find(q)
		add("find-"+q, &r, f.FindText(r))
	}
	for _, q := range []string{"10.1.10.20", "aabb.cc00.0a01", "aabb.cc00.9999", "10.7.7.7", "nada", "10.1.20.50"} {
		r := f.Trace(q)
		add("trace-"+q, &r, f.TraceText(r))
	}
	for _, p := range [][2]string{{"10.1.10.20", "10.1.20.50"}, {"10.1.10.20", "172.31.0.1"}, {"10.1.20.50", "192.0.2.1"},
		{"10.1.10.20", "10.9.1.1"}, {"203.0.113.5", "10.1.20.50"}, {"10.1.10.20", "10.255.0.2"}, {"x", "y"}} {
		r := f.Path(p[0], p[1])
		add("path-"+p[0]+"-"+p[1], &r, f.PathText(r))
		out["svg-"+p[0]+"-"+p[1]] = golden{Text: r.SVG()}
	}
	h := f.Health()
	add("health", &h, f.HealthText(h))
	s := f.Summary()
	add("summary", &s, f.SummaryText(s))
	for _, n := range []int64{0, 1 << 30, 1 << 40} {
		c := f.Capacity(n)
		add("capacity-"+string(rune('a'+n%7)), &c, f.CapacityText(c))
	}
	i := f.Inventory()
	add("inventory", &i, f.InventoryText(i))

	// bucle, vecino sin evidencia, trunk sin vecino, MAC propia
	a := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": cdp("B", "10.0.0.2", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")})
	b := devFrom("B_10.0.0.2", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": cdp("A", "10.0.0.1", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1")})
	fl := New([]*Dev{a, b}, now)
	r := fl.Trace("aabb.cc00.0a01")
	add("trace-bucle", &r, fl.TraceText(r))
	x := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl, "show cdp neighbors detail": cdp("X", "10.0.0.9", "GigabitEthernet1/0/1", "GigabitEthernet1/0/2")})
	fx := New([]*Dev{x}, now)
	r = fx.Trace("aabb.cc00.0a01")
	add("trace-sin-evidencia", &r, fx.TraceText(r))
	r = fx.Trace("10.0.0.77")
	add("trace-ip-sin-arp", &r, fx.TraceText(r))
	y := devFrom("A_10.0.0.1", map[string]string{"show mac address-table": macTbl})
	fy := New([]*Dev{y}, now)
	r = fy.Trace("aabb.cc00.0a01")
	add("trace-sin-cdp", &r, fy.TraceText(r))

	// formato inesperado y evidencias rechazadas
	bad := devFrom("A_10.0.0.1", map[string]string{
		"show ip arp": "Protocol Address\nbasura inesperada\n", "show mac address-table": "% Invalid input detected at '^' marker.\n",
		"show ntp status": "NTP is not enabled.\n", "show processes cpu": "formato nuevo\n",
		"show interfaces status": "xx\n", "show interfaces": "yy\n", "show version": "zz\n", "dir flash:": "qq\n",
	})
	fb := New([]*Dev{bad}, now)
	fr := fb.Find("10.0.0.5")
	add("bad-find", &fr, fb.FindText(fr))
	sr := fb.Summary()
	add("bad-summary", &sr, fb.SummaryText(sr))
	hr := fb.Health()
	add("bad-health", &hr, fb.HealthText(hr))
	cr := fb.Capacity(5)
	add("bad-capacity", &cr, fb.CapacityText(cr))
	pr := fb.Path("10.0.0.1", "10.0.0.2")
	add("bad-path", &pr, fb.PathText(pr))

	// avisos de carga: zip roto, archivo sin salidas, carpeta ilegible
	d := t.TempDir()
	put(t, d, "trabajo_1/SW1_10.0.0.1/r001.txt", errDis)
	put(t, d, "trabajo_1/ronda.zip", "esto no es un zip")
	put(t, d, "trabajo_1/SW2_10.0.0.2/r001.txt", "sin encabezados\n")
	fd, err := Load(d, now)
	if err != nil {
		t.Fatal(err)
	}
	hd := fd.Health()
	add("load-health", &hd, fd.HealthText(hd))
	// el aviso de path: solo tabla global, rutas con forma no leída, sin show ip route
	pd := devFrom("R1_10.0.0.1", map[string]string{"show ip route": "Gateway of last resort is not set\nL 10.0.0.1/32 is directly connected, Vlan1\nO 1.1.1.1 weird\n", "show ip arp": "x\n"})
	fp := New([]*Dev{pd}, now)
	pp := fp.Path("10.0.0.1", "8.8.8.8")
	add("path-weird", &pp, fp.PathText(pp))
	return out, ptrs
}

func TestRegresionEs(t *testing.T) {
	got, _ := regCases(t)
	const file = "testdata/regresion_es.golden.json"
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
	var want map[string]golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, got[n], want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("casos: %d vs %d", len(got), len(want))
	}
}
