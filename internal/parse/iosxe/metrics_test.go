package iosxe

import (
	"testing"
	"time"
)

func TestParseMemPools(t *testing.T) {
	// IOS 15.2: show memory statistics
	p, ok := ParseMemPools(fx(t, "ios152_show-memory-statistics"))
	if !ok || len(p) != 2 || p[0] != (MemPool{"Processor", 183869200, 21386712, 162482488}) || p[1].Name != "I/O" || p[1].Used != 5237548 || p[1].Total != 16777216 {
		t.Fatalf("stats = %+v %v", p, ok)
	}
	// IOS-XE: encabezado de show processes memory (pool "lsmpi_io")
	p, ok = ParseMemPools(fx(t, "iosxe_show-processes-memory"))
	if !ok || len(p) != 2 || p[0] != (MemPool{"Processor", 1463259136, 483214336, 980044800}) || p[1].Name != "lsmpi_io" || p[1].Free != 824 {
		t.Fatalf("pools = %+v %v", p, ok)
	}
	// IOS 15.2: show processes memory con I/O Pool
	p, ok = ParseMemPools(fx(t, "core1_show-processes-memory"))
	if !ok || len(p) != 2 || p[1].Name != "I/O" || p[1].Total != 200000000 {
		t.Fatalf("core1 = %+v", p)
	}
	for _, junk := range []string{"", "% Invalid input detected at '^' marker.\n", "Processor Pool Total: 0 Used: 0 Free: 0\n", "Processor Pool Total: 10 Used: 5 Free: 50\n"} {
		if _, ok := ParseMemPools(junk); ok {
			t.Errorf("%q no debe leerse", junk)
		}
	}
}

func TestParseCPUIOS152(t *testing.T) {
	c, ok := ParseCPU(fx(t, "ios152_show-processes-cpu"))
	if !ok || c.FiveSec != 7 || c.OneMin != 6 || c.FiveMin != 5 {
		t.Fatalf("cpu = %+v", c)
	}
}

func TestParseIfStatusTipo(t *testing.T) {
	st, ok := ParseIfStatus(fx(t, "ios152_show-interfaces-status"))
	if !ok || len(st) != 10 {
		t.Fatalf("filas = %d %v", len(st), ok)
	}
	if st[0].Type != "10/100/1000BaseTX" || st[2].Name != "sala de juntas" || st[5].Status != "err-disabled" || st[7].Type != "1000BaseSX SFP" || st[9].Type != "" {
		t.Fatalf("filas = %+v", st)
	}
}

func TestParseTrunks(t *testing.T) {
	tr, ok := ParseTrunks(fx(t, "ios152_show-interfaces-trunk"))
	if !ok || len(tr) != 3 || tr[0] != (Trunk{"Gi1/0/1", "on", "802.1q", "trunking", "1"}) || tr[2].Port != "Po1" {
		t.Fatalf("trunks = %+v %v", tr, ok)
	}
	if _, ok := ParseTrunks("Port\nPort Mode\n"); ok {
		t.Error("cabecera incompleta no es trunk")
	}
	if _, ok := ParseTrunks("% Invalid input\n"); ok {
		t.Error("basura no es trunk")
	}
	if tr, ok := ParseTrunks("Port        Mode             Encapsulation  Status        Native vlan\n"); !ok || len(tr) != 0 {
		t.Errorf("sin trunks: %+v %v", tr, ok)
	}
}

func TestParseEtherChannels(t *testing.T) {
	ec, ok := ParseEtherChannels(fx(t, "iosxe_show-etherchannel-summary"))
	if !ok || len(ec) != 2 {
		t.Fatalf("canales = %+v %v", ec, ok)
	}
	if ec[0].Name != "Po1" || ec[0].State != "SU" || ec[0].Protocol != "LACP" || len(ec[0].Members) != 2 || ec[0].Members[1] != (ChannelMember{"Gi1/0/2", "P"}) {
		t.Fatalf("Po1 = %+v", ec[0])
	}
	if len(ec[1].Members) != 1 {
		t.Fatalf("Po2 = %+v", ec[1])
	}
	if ec[1].State != "SD" || ec[1].Members[0].Flags != "D" {
		t.Fatalf("Po2 = %+v", ec[1])
	}
}

func TestParsePortPos(t *testing.T) {
	cases := []struct {
		in   string
		want PortPos
		ok   bool
	}{
		{"Gi1/0/12", PortPos{"Gi", 1, 0, 12}, true},
		{"GigabitEthernet2/1/48", PortPos{"Gi", 2, 1, 48}, true},
		{"Fa0/24", PortPos{"Fa", 0, 0, 24}, true},
		{"Te1/1/2", PortPos{"Te", 1, 1, 2}, true},
		{"Eth1/5", PortPos{"Eth", 1, 0, 5}, true},
		{"Po1", PortPos{}, false},
		{"Vlan10", PortPos{}, false},
		{"Gi1/0/1.100", PortPos{}, false},
		{"Gi1/0/x", PortPos{}, false},
		{"", PortPos{}, false},
	}
	for _, c := range cases {
		if got, ok := ParsePortPos(c.in); ok != c.ok || got != c.want {
			t.Errorf("%q → %+v %v", c.in, got, ok)
		}
	}
}

func TestParseInterfacesContadores(t *testing.T) {
	ifs, ok := ParseInterfaces(fx(t, "lab1_show-interfaces"))
	if !ok {
		t.Fatal("no leyó")
	}
	i := ifs[0]
	if i.BWKbit != 1000000 || i.InBytes != 98765432 || i.OutBytes != 123456789 || i.InRateBps != 2000 || i.OutRateBps != 5000 || i.Description != "Uplink-Core" || !i.HasBytes {
		t.Fatalf("Gi1/0/1 = %+v", i)
	}
	// una interfaz sin contadores de bytes no los inventa
	ifs, _ = ParseInterfaces("GigabitEthernet1/0/7 is up, line protocol is up\n  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec,\n")
	if ifs[0].HasBytes || ifs[0].BWKbit != 100000 {
		t.Fatalf("sin bytes = %+v", ifs[0])
	}
}

func TestParseEtherChannelsIgnoraTextoSuelto(t *testing.T) {
	ec, _ := ParseEtherChannels("1      Po1(SU)         LACP      Gi1/0/1(P)\nGi1/0/9(P) fuera de la tabla\n")
	if len(ec) != 1 || len(ec[0].Members) != 1 {
		t.Fatalf("= %+v", ec)
	}
}

func TestParseInterfacesUltimaLimpieza(t *testing.T) {
	ifs, ok := ParseInterfaces(fx(t, "ios152_show-interfaces-clear"))
	if !ok || len(ifs) != 4 {
		t.Fatalf("= %+v", ifs)
	}
	if !ifs[0].HasClear || ifs[0].ClearAgo != 5*time.Minute+12*time.Second {
		t.Errorf("hh:mm:ss = %+v %v", ifs[0].HasClear, ifs[0].ClearAgo)
	}
	// «never», una forma que no es hh:mm:ss y la línea ausente: no se sabe cuándo (y no se inventa)
	for _, i := range ifs[1:] {
		if i.HasClear || i.ClearAgo != 0 {
			t.Errorf("%s: %+v %v", i.Name, i.HasClear, i.ClearAgo)
		}
	}
}

// Fixture con columnas de datos desplazadas respecto a la cabecera (como en un 3560CX),
// descripciones con espacios y puertos SFP «Not Present»; sin validar en laboratorio.
func TestParseIfStatusDesplazado(t *testing.T) {
	st, ok := ParseIfStatus(fx(t, "ios152_show-interfaces-status-desplazado"))
	if !ok || len(st) != 11 {
		t.Fatalf("filas = %d %v", len(st), ok)
	}
	want := []struct{ port, name, status, vlan, duplex, speed, typ string }{
		{"Gi0/1", "uplink-a-core-1", "connected", "trunk", "a-full", "a-1000", "10/100/1000BaseTX"},
		{"Gi0/2", "", "notconnect", "1", "auto", "auto", "10/100/1000BaseTX"},
		{"Gi0/3", "descripcion-larga-", "connected", "1", "a-full", "a-1000", "10/100/1000BaseTX"},
		{"Gi0/4", "PC sala de juntas", "connected", "10", "a-half", "a-100", "10/100/1000BaseTX"},
		{"Gi0/5", "AP piso 2 oeste", "connected", "30", "a-full", "a-1000", "10/100/1000BaseTX"},
		{"Gi0/6", "impresora", "err-disabled", "20", "auto", "auto", "10/100/1000BaseTX"},
		{"Gi0/7", "enlace 10G", "connected", "routed", "full", "10G", "10GBase-SR"},
		{"Gi0/49", "", "notconnect", "1", "auto", "auto", "Not Present"},
		{"Gi0/50", "SFP sin modulo", "notconnect", "1", "auto", "auto", "Not Present"},
		{"Gi0/51", "", "notconnect", "1", "full", "1000", "1000BaseSX SFP"},
		{"Gi0/52", "apagado", "disabled", "1", "auto", "auto", "10/100/1000BaseTX"},
	}
	for i, w := range want {
		g := st[i]
		if g.Port != w.port || g.Name != w.name || g.Status != w.status || g.VLAN != w.vlan || g.Duplex != w.duplex || g.Speed != w.speed || g.Type != w.typ {
			t.Errorf("fila %d = %+v, quiero %+v", i, g, w)
		}
	}
}

// Una descripción con un par que parece dúplex y velocidad no esconde el estado real (hallazgo de la
// revisión: el modo asistido revisa err-disabled/inactive en el POST). Velocidad con decimales también.
func TestParseIfStatusNombreEngañoso(t *testing.T) {
	text := "Port      Name               Status       Vlan       Duplex  Speed Type\n" +
		"Gi0/11    PC sala 3 half 10  err-disabled 11           auto   auto 10/100/1000BaseTX\n" +
		"Gi0/12    AP P2 x full 1000  inactive     12         a-full a-1000 10/100/1000BaseTX\n" +
		"Te1/1/1   uplink             connected    trunk      a-full a-2.5G 100/1000/2.5G/5G/10GBaseT\n"
	rows, ok := ParseIfStatus(text)
	if !ok || len(rows) != 3 {
		t.Fatalf("%v %+v", ok, rows)
	}
	for i, want := range []IfStatus{
		{Port: "Gi0/11", Name: "PC sala 3 half 10", Status: "err-disabled", VLAN: "11", Duplex: "auto", Speed: "auto", Type: "10/100/1000BaseTX"},
		{Port: "Gi0/12", Name: "AP P2 x full 1000", Status: "inactive", VLAN: "12", Duplex: "a-full", Speed: "a-1000", Type: "10/100/1000BaseTX"},
		{Port: "Te1/1/1", Name: "uplink", Status: "connected", VLAN: "trunk", Duplex: "a-full", Speed: "a-2.5G", Type: "100/1000/2.5G/5G/10GBaseT"},
	} {
		if rows[i] != want {
			t.Errorf("fila %d = %+v, quiero %+v", i, rows[i], want)
		}
	}
}
