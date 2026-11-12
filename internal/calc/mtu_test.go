package calc

import (
	"strings"
	"testing"
)

func TestMTU(t *testing.T) {
	cases := []struct {
		phys     int
		stack    string
		inner6   bool
		eff, mss int
	}{
		{1500, "gre", false, 1476, 1436},
		{1500, "gre-key", false, 1472, 1432},
		{1500, "gre", true, 1476, 1416},
		{1500, "pppoe", false, 1492, 1452},
		{1500, "mpls:3", false, 1488, 1448},
		{1500, "mpls", false, 1496, 1456},
		{1500, "vxlan", false, 1450, 1410},
		{1500, "vxlan dot1q", false, 1446, 1406},
		{1500, "vxlan qinq", false, 1442, 1402},
		{1500, "dot1q", false, 1500, 1460}, // la etiqueta exterior no entra en la MTU IP
		{1500, "lisp", false, 1464, 1424},
		// ESP túnel AES-GCM: 20 + 8 SPI/sec + 8 IV + 16 ICV + 2 cola, alineado a 4.
		{1500, "esp-tunnel:aes-gcm", false, 1446, 1406},
		// NAT-T + túnel AES-CBC/SHA-256: 1472-40=1432 → 1424 cifrables (8 de alineación) → 1422.
		{1500, "nat-t esp-tunnel:aes-cbc:sha256", false, 1422, 1382},
		// GRE sobre IPsec transporte: la IP de GRE queda fuera del cifrado.
		// 1500-20=1480; 1480-36=1444 → 1440 cifrables → 1438 de carga → GRE 4 → 1434.
		{1500, "esp-transport:aes-cbc:sha1 gre", false, 1434, 1394},
		// Transporte sin nada dentro: el paquete conserva su propia cabecera IP.
		{1500, "esp-transport:aes-cbc:sha1", false, 1458, 1418},
		{1500, "esp-tunnel:3des:md5", false, 1446, 1406},
		{1500, "getvpn:aes-cbc:sha1", false, 1438, 1398},
		{1500, "getvpn:aes-cbc:sha1:tbar", false, 1422, 1382},
		{1500, "getvpn:aes-gcm:tbar", false, 1434, 1394}, // 1500-64=1436 cifrables → 1434
		{9000, "vxlan", false, 8950, 8910},
		{1500, "pppoe esp-tunnel:aes-cbc:sha512 gre-key", false, 1378, 1338},
	}
	for _, c := range cases {
		r, err := MTU(c.phys, strings.Fields(c.stack), c.inner6)
		if err != nil {
			t.Fatalf("%s: %v", c.stack, err)
		}
		if r.Effective != c.eff || r.MSS != c.mss || r.IPMTU != c.eff {
			t.Errorf("%d %s: eff=%d mss=%d, quiero %d %d", c.phys, c.stack, r.Effective, r.MSS, c.eff, c.mss)
		}
		sum := 0
		for _, l := range r.Layers {
			sum += l.Bytes
		}
		if sum != c.phys-r.Effective {
			t.Errorf("%s: el desglose suma %d, no %d", c.stack, sum, c.phys-r.Effective)
		}
	}
}

func TestMTUBreakdownAndNeeded(t *testing.T) {
	r, err := MTU(1500, []string{"nat-t", "esp-tunnel:aes-cbc:sha256"}, false)
	if err != nil {
		t.Fatal(err)
	}
	esp := r.Layers[1]
	if esp.Bytes != 70 || !strings.Contains(esp.Detail, "IV 16") || !strings.Contains(esp.Detail, "ICV 16") || !strings.Contains(esp.Detail, "alineación 8") {
		t.Fatalf("%+v", esp)
	}
	// Carga ≥ 1500 exige 1504 cifrables (múltiplo de 16): 1504 + 40 + 20 + 8 = 1572.
	if r.PhysicalFor1500 != 1572 {
		t.Fatalf("física para 1500: %d", r.PhysicalFor1500)
	}
	tr, _ := MTU(1500, []string{"esp-transport:aes-cbc:sha1", "gre"}, false)
	if tr.Layers[0].Bytes != 62 || tr.Layers[1].Bytes != 4 {
		t.Fatalf("GRE en transporte: %+v", tr.Layers)
	}
	g, _ := MTU(1500, []string{"gre"}, false)
	if g.PhysicalFor1500 != 1524 {
		t.Fatalf("gre necesita %d", g.PhysicalFor1500)
	}
	d, _ := MTU(1500, []string{"dot1q"}, false)
	if d.PhysicalFor1500 != 0 || len(d.Notes) == 0 {
		t.Fatalf("%+v", d)
	}
}

func TestMTURejects(t *testing.T) {
	for _, c := range []struct {
		phys  int
		stack string
	}{
		{1500, "frob"}, {1500, "esp-tunnel:aes-cbc"}, {1500, "esp-tunnel:aes-gcm:sha1"}, {1500, "esp-tunnel:rc4:sha1"},
		// NAT-T solo va inmediatamente por fuera de un ESP; nada que no lleve IP va dentro de ESP de transporte.
		{1500, "esp-tunnel:aes-cbc:sha1 nat-t"}, {1500, "esp-transport:aes-cbc:sha1 nat-t"}, {1500, "nat-t gre"}, {1500, "nat-t"},
		{1500, "esp-transport:aes-cbc:sha1 pppoe"},
		{1500, "mpls:0"}, {1500, "mpls:x"}, {67, "gre"}, {70000, "gre"}, {100, "gre gre"}, {1500, ""},
	} {
		if _, err := MTU(c.phys, strings.Fields(c.stack), false); err == nil {
			t.Errorf("%d %q aceptado", c.phys, c.stack)
		}
	}
}
