package snmp

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp/snmptest"
)

func v2(a *snmptest.Agent) Target {
	return Target{Host: "127.0.0.1", Port: a.Port(), Version: "2c", Community: "lab-ro", Timeout: 500 * time.Millisecond}
}

func TestGetV2c(t *testing.T) {
	a := snmptest.New(t, "lab-ro", nil)
	vs, err := Get(context.Background(), v2(a), []string{"1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.99.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 3 || vs[0].Value != "SW1" || vs[0].Type != "OctetString" || vs[1].Value != uint32(123456) || vs[2].Type != "NoSuchObject" {
		t.Fatalf("vars = %+v", vs)
	}
}

func TestComunidadEquivocadaExpira(t *testing.T) {
	a := snmptest.New(t, "lab-ro", nil)
	tg := v2(a)
	tg.Community, tg.Timeout = "otra", 200*time.Millisecond
	if _, err := Get(context.Background(), tg, []string{"1.3.6.1.2.1.1.5.0"}); err == nil {
		t.Fatal("respuesta con comunidad equivocada")
	}
}

func TestWalkYBulkWalk(t *testing.T) {
	a := snmptest.New(t, "lab-ro", nil)
	for _, bulk := range []bool{false, true} {
		vs, err := Walk(context.Background(), v2(a), "1.3.6.1.2.1.31.1.1.1.1", bulk, 0)
		if err != nil || len(vs) != 2 || vs[1].Value != "Gi1/0/2" {
			t.Fatalf("bulk=%t: %+v %v", bulk, vs, err)
		}
	}
	vs, err := Walk(context.Background(), v2(a), "1.3.6.1", true, 3)
	if err != nil || len(vs) != 3 {
		t.Fatalf("límite: %d %v", len(vs), err)
	}
}

func TestV3AuthPriv(t *testing.T) {
	a := snmptest.New(t, "", &gosnmp.UsmSecurityParameters{UserName: "noc", AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "authpass123",
		PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privpass123"})
	tg := Target{Host: "127.0.0.1", Port: a.Port(), Version: "3", User: "noc", AuthProto: "SHA", AuthPass: "authpass123", PrivProto: "AES", PrivPass: "privpass123", Timeout: time.Second}
	vs, err := Get(context.Background(), tg, []string{"1.3.6.1.2.1.1.5.0"})
	if err != nil || len(vs) != 1 || vs[0].Value != "SW1" {
		t.Fatalf("v3: %+v %v", vs, err)
	}
	tg.PrivPass, tg.Timeout = "equivocada", 300*time.Millisecond
	if _, err := Get(context.Background(), tg, []string{"1.3.6.1.2.1.1.5.0"}); err == nil {
		t.Fatal("v3 con privacidad equivocada respondió")
	}
}

func TestTargetInvalido(t *testing.T) {
	for _, tg := range []Target{
		{Host: "127.0.0.1", Version: "1"},
		{Host: "127.0.0.1", Version: "3", User: "u", AuthProto: "MD5", AuthPass: "12345678", PrivProto: "AES", PrivPass: "12345678"},
		{Host: "127.0.0.1", Version: "3", User: "u", AuthProto: "SHA", AuthPass: "12345678"}, // solo authPriv
		{Host: "", Version: "2c", Community: "x"},
	} {
		if _, err := Get(context.Background(), tg, []string{"1.3.6.1.2.1.1.5.0"}); err == nil {
			t.Errorf("aceptado: %+v", tg)
		}
	}
}

func TestControlCortaLaSalida(t *testing.T) {
	a := snmptest.New(t, "lab-ro", nil)
	tg := v2(a)
	deny := errors.New("negado")
	tg.Control = func(string, string, syscall.RawConn) error { return deny }
	if _, err := Get(context.Background(), tg, []string{"1.3.6.1.2.1.1.5.0"}); !errors.Is(err, deny) {
		t.Fatalf("err = %v", err)
	}
	if a.Requests() != 0 {
		t.Fatal("el agente recibió la consulta")
	}
}

func TestPollPerfiles(t *testing.T) {
	a := snmptest.New(t, "lab-ro", nil)
	var got []Sample
	err := Poll(context.Background(), v2(a), []string{"sistema", "interfaces", "cpu", "memoria"}, 100*time.Millisecond, 2, func(s Sample) { got = append(got, s) })
	if err != nil || len(got) != 2 {
		t.Fatalf("%d muestras: %v", len(got), err)
	}
	s := got[1]
	if s.System["sysName"] != "SW1" || len(s.Interfaces) != 2 || s.Interfaces[0].Name != "Gi1/0/1" || s.Interfaces[0].Oper != "up" {
		t.Fatalf("muestra = %+v", s)
	}
	if got[0].Interfaces[0].InBps != nil || s.Interfaces[0].InBps == nil || *s.Interfaces[0].InBps <= 0 {
		t.Fatalf("tasas: primera=%v segunda=%v", got[0].Interfaces[0].InBps, s.Interfaces[0].InBps)
	}
	if len(s.CPU) != 1 || s.CPU[0].FiveSec != 7 || len(s.Memory) != 1 || s.Memory[0].Name != "Processor" || s.Memory[0].UsedPct != 30 {
		t.Fatalf("cpu/mem = %+v %+v", s.CPU, s.Memory)
	}
	if err := Poll(context.Background(), v2(a), []string{"nada"}, time.Second, 1, func(Sample) {}); err == nil {
		t.Fatal("perfil desconocido aceptado")
	}
}

func TestRate(t *testing.T) {
	cases := []struct {
		prev, cur uint64
		bits      int
		dt        float64
		mbps      uint64
		want      float64
		ok        bool
	}{
		{1000, 2000, 64, 1, 1000, 8000, true},
		{4294967000, 704, 32, 1, 1000, 8000, true}, // vuelta del contador de 32 bits
		{5000, 1000, 64, 1, 1000, 0, false},        // reinicio del equipo o del contador
		{1000, 2000, 64, 0, 1000, 0, false},
		{4e9, 1000, 32, 10, 100, 0, false},   // 236 Mb/s en un puerto de 100: imposible
		{1000, 2000, 32, 60, 1000, 0, false}, // a 1 Gb/s el contador de 32 bits da la vuelta en 34 s
		{4e9, 1000, 32, 1, 0, 0, false},      // sin velocidad no se puede saber si fue vuelta
		{1000, 1e12, 64, 1, 1000, 0, false},  // más que la velocidad del puerto
	}
	for _, c := range cases {
		got, ok := rate(c.prev, c.cur, c.bits, c.dt, c.mbps)
		if ok != c.ok || got != c.want {
			t.Errorf("rate(%v,%v,%d,%v,%d) = %v %v, quiero %v %v", c.prev, c.cur, c.bits, c.dt, c.mbps, got, ok, c.want, c.ok)
		}
	}
}

// Revisión: si sysUpTime bajó entre muestras, el equipo se reinició y no hay tasa.
func TestRatesTrasReinicio(t *testing.T) {
	now := time.Now()
	prev := &Sample{Time: now, Uptime: 100000, Interfaces: []IfStat{{Index: "1", SpeedMbps: 1000, InOctets: 4e9, OutOctets: 4e9, counterBits: 32}}}
	cur := &Sample{Time: now.Add(10 * time.Second), Uptime: 500, Interfaces: []IfStat{{Index: "1", SpeedMbps: 1000, InOctets: 1000, OutOctets: 1000, counterBits: 32}}}
	rates(prev, cur)
	if cur.Interfaces[0].InBps != nil || len(cur.Errors) != 1 || !strings.Contains(cur.Errors[0], "reinici") {
		t.Fatalf("muestra = %+v", cur)
	}
	cur.Uptime, cur.Errors = 100000+1000, nil // 10 s más tarde según el equipo
	rates(prev, cur)
	if cur.Interfaces[0].InBps == nil {
		t.Fatal("vuelta legítima sin tasa")
	}
}

func TestPollInterfacesLeeUptime(t *testing.T) {
	a := snmptest.New(t, "lab-ro", nil)
	var got Sample
	if err := Poll(context.Background(), v2(a), []string{"interfaces"}, time.Second, 1, func(s Sample) { got = s }); err != nil {
		t.Fatal(err)
	}
	if got.Uptime != 123456 {
		t.Fatalf("uptime = %d", got.Uptime)
	}
}
