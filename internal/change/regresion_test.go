package change

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
)

type golden struct{ JSON, Text string }

func gold(v any, text string) golden {
	b, _ := json.Marshal(v)
	return golden{string(b), text}
}

func file(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// devOf arma un equipo de la captura con el texto de salidas dado.
func devOf(addr, host, state, text string) capture.Device {
	return capture.Device{Address: addr, Hostname: host, State: state, Outputs: capture.Split(text)}
}

// cut quita de text la sección de un comando.
func cut(text, cmd string) string {
	parts := strings.Split(text, "===== ")
	var keep []string
	for _, p := range parts {
		if p != "" && !strings.Contains(strings.SplitN(p, "\n", 2)[0], "· "+cmd+" =====") {
			keep = append(keep, p)
		}
	}
	return "===== " + strings.Join(keep, "===== ")
}

// regCases arma informes que recorren cada hallazgo del cambio; solo usa lo que ya existía antes de la fase 30c.
func regCases(t *testing.T) (map[string]golden, map[string]any) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]any{}
	add := func(name string, r Report) {
		out[name] = gold(r, r.Text())
		ptrs[name] = &r
	}
	pre, post := file(t, "pre.txt"), file(t, "post.txt")
	a, b := "192.0.2.1", "192.0.2.2"
	one := func(name, x, y string) {
		add(name, Compare([]capture.Device{devOf(a, "DIST-01", "completed", x)}, []capture.Device{devOf(a, "DIST-01", "completed", y)}))
	}
	one("pre-post", pre, post)
	one("post-pre", post, pre)
	one("igual", pre, pre)
	// facetas que faltan en POST, una a una
	for _, cmd := range []string{"show version", "show ip interface brief", "show cdp neighbors detail", "show ip bgp summary", "show standby brief", "show spanning-tree root"} {
		one("sin-"+cmd, pre, cut(pre, cmd))
	}
	// protocolos: se pierde un vecino o un grupo, bajan prefijos, rutas a cero, grupo anómalo, raíz nueva
	one("ospf-perdido", pre, strings.Replace(pre, "192.0.2.3         0   FULL/  -        00:00:33    203.0.113.2     GigabitEthernet1/0/24\n", "", 1))
	one("bgp-perdido", pre, strings.Replace(pre, "203.0.113.9     4        65003    5021    5003      120    0    0 3d04h          20\n", "", 1))
	one("bgp-prefijos", pre, strings.Replace(pre, "192.0.2.9       4        65002   12034   12001      120    0    0 1w2d          118", "192.0.2.9       4        65002   12034   12001      120    0    0 1w2d          10", 1))
	one("rutas-cero", pre, strings.Replace(pre, "ospf 1          3           12", "ospf 1          0           0", 1))
	one("hsrp-perdido", pre, strings.Replace(pre, "Vl20        20   100   Standby 198.51.100.131  local           198.51.100.129\n", "", 1))
	one("hsrp-init", pre, strings.Replace(pre, "Vl20        20   100   Standby", "Vl20        20   100   Init   ", 1))
	one("hsrp-cambio", pre, strings.Replace(pre, "Vl10        10   110 P Active  local", "Vl10        10   110 P Standby local", 1))
	one("stp-perdida", pre, strings.Replace(pre, "VLAN0020         24596 00a3.d14f.0001         0    2   20  15               \n", "", 1))
	one("stp-puerto", pre, strings.Replace(pre, "VLAN0020         24596 00a3.d14f.0001         0    2   20  15               ", "VLAN0020         24596 00a3.d14f.0001         0    2   20  15  Gi1/0/9      ", 1))
	// lo contrario: aparece un vecino, una adyacencia, un grupo, una raíz o una interfaz; desaparece una interfaz
	ospfL := "192.0.2.3         0   FULL/  -        00:00:33    203.0.113.2     GigabitEthernet1/0/24\n"
	bgpL := "203.0.113.9     4        65003    5021    5003      120    0    0 3d04h          20\n"
	hsrpL := "Vl20        20   100   Standby 198.51.100.131  local           198.51.100.129\n"
	stpL := "VLAN0020         24596 00a3.d14f.0001         0    2   20  15               \n"
	v20 := "Vlan20                 198.51.100.130  YES NVRAM  up                    up      \n"
	one("ospf-nuevo", strings.Replace(pre, ospfL, "", 1), pre)
	one("bgp-nuevo", strings.Replace(pre, bgpL, "", 1), pre)
	one("hsrp-nuevo", strings.Replace(pre, hsrpL, "", 1), pre)
	one("stp-nueva", strings.Replace(pre, stpL, "", 1), pre)
	one("iface-desaparece", pre, strings.Replace(pre, v20, "", 1))
	one("iface-nueva", strings.Replace(pre, v20, "", 1), pre)
	one("cdp-puerto", pre, strings.Replace(pre, "Port ID (outgoing port): GigabitEthernet1/1/1", "Port ID (outgoing port): GigabitEthernet1/1/9", 1))
	// configuración con más de 500 líneas de diferencia
	var big strings.Builder
	for i := 0; i < 600; i++ {
		big.WriteString(" description extra" + strings.Repeat("x", i%7) + "\n")
	}
	one("config-grande", pre, strings.Replace(post, "ntp clock-period 36028797018963999\n", "ntp clock-period 36028797018963999\ninterface Vlan999\n"+strings.ReplaceAll(big.String(), "description extra", "description e"), 1))
	// equipos de más y de menos, capturas fallidas y sin salidas
	add("sin-post", Compare([]capture.Device{devOf(a, "DIST-01", "completed", pre)}, nil))
	add("solo-post", Compare(nil, []capture.Device{devOf(a, "DIST-01", "completed", post)}))
	add("post-fallida", Compare([]capture.Device{devOf(a, "DIST-01", "completed", pre)}, []capture.Device{{Address: a, Hostname: "DIST-01", State: "failed", Detail: "timeout"}}))
	add("pre-fallida", Compare([]capture.Device{{Address: a, State: "failed", Detail: "sin ruta"}}, []capture.Device{devOf(a, "DIST-01", "completed", post)}))
	add("vacias", Compare([]capture.Device{devOf(b, "", "completed", "nada")}, []capture.Device{devOf(b, "", "completed", "nada")}))
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
